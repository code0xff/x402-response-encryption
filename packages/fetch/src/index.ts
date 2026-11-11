// Client side of x402 response encryption: a fetch wrapper that pays with an
// EIP-3009 authorization whose nonce commits a fresh ephemeral key (proposal 3.1),
// then decrypts the seller's envelope. Plaintext success responses are refused.
import {
  ENVELOPE_CONTENT_TYPE,
  EXTENSION_KEY,
  ResponseEncryptionError,
  authorizationDigest,
  canonicalUrl,
  createBinding,
  openResponse,
  payloadInfoFor,
  transferAuthorizationTypedData,
  verifySellerKey,
  type ClientBinding,
  type ContractSignatureVerifier,
  type Envelope,
  type PaymentRequiredInfo,
  type TokenDomain,
  type TransferAuthorization,
  type VerifiedSellerKey,
} from '@x402-response-encryption/core';
import { decodePaymentRequiredHeader, decodePaymentResponseHeader, encodePaymentSignatureHeader } from '@x402/core/http';
import type { PaymentPayload, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { getAddress, type Address, type Hex } from 'viem';

/** Minimal signer: a viem LocalAccount or WalletClient account satisfies it. */
export interface PaymentSigner {
  address: Address;
  signTypedData(args: ReturnType<typeof transferAuthorizationTypedData>): Promise<Hex>;
}

export interface EncryptedFetchOptions {
  signer: PaymentSigner;
  /** Seller payTo known out of band (proposal 4.3). */
  pinnedPayTo?: Address;
  contractVerifier?: ContractSignatureVerifier;
  /** Resends of the identical paid request after a transport failure (proposal 8.1). Default 2. */
  transportRetries?: number;
  /** Unix seconds; injectable for tests. */
  now?: () => number;
}

/** Raised when the paid exchange fails; carries the response-encryption reason when there is one. */
export class EncryptedFetchError extends Error {
  constructor(
    message: string,
    readonly reason?: string,
  ) {
    super(message);
    this.name = 'EncryptedFetchError';
  }
}

interface PaidAttempt {
  key: VerifiedSellerKey;
  binding: ClientBinding;
  network: string;
  digest: Uint8Array;
  header: string;
}

// requestHash covers the body after removing Content-Encoding (proposal 3.2).
async function committedBody(request: Request): Promise<Uint8Array> {
  const raw = new Uint8Array(await request.clone().arrayBuffer());
  const codings = (request.headers.get('content-encoding') ?? '')
    .split(',')
    .map((c) => c.trim().toLowerCase())
    .filter((c) => c && c !== 'identity');
  let body: Uint8Array = raw;
  for (const coding of codings.reverse()) {
    const format = coding === 'gzip' || coding === 'x-gzip' ? 'gzip' : coding === 'deflate' ? 'deflate' : undefined;
    if (!format) throw new EncryptedFetchError(`unsupported request content-encoding: ${coding}`);
    const stream = new Blob([body]).stream().pipeThrough(new DecompressionStream(format));
    body = new Uint8Array(await new Response(stream).arrayBuffer());
  }
  return body;
}

const isEip155Exact = (r: PaymentRequirements) => r.scheme === 'exact' && r.network.startsWith('eip155:');

function readPaymentRequired(res: Response, body: string): PaymentRequired {
  const header = res.headers.get('PAYMENT-REQUIRED');
  if (header) return decodePaymentRequiredHeader(header);
  return JSON.parse(body) as PaymentRequired;
}

function extensionInfo(pr: PaymentRequired): PaymentRequiredInfo | undefined {
  const ext = pr.extensions?.[EXTENSION_KEY] as { info?: PaymentRequiredInfo } | undefined;
  return ext?.info;
}

function errorReason(pr: PaymentRequired): string | undefined {
  const info = extensionInfo(pr) as (PaymentRequiredInfo & { errorReason?: string }) | undefined;
  return info?.errorReason;
}

export function wrapFetchWithEncryptedPayment(fetchImpl: typeof fetch, opts: EncryptedFetchOptions): typeof fetch {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const retries = opts.transportRetries ?? 2;

  async function preparePayment(pr: PaymentRequired, bodyBytes: Uint8Array, method: string, requestedUrl: string): Promise<PaidAttempt> {
    const info = extensionInfo(pr);
    if (!info) throw new EncryptedFetchError('resource does not offer response encryption');
    // The client signs over resource.url, so it must be the resource the client asked for (proposal 3.3).
    const sameUrl = (() => {
      try {
        return canonicalUrl(pr.resource.url) === canonicalUrl(requestedUrl);
      } catch {
        return false;
      }
    })();
    if (!sameUrl) throw new EncryptedFetchError('402 resource.url differs from the requested URL', 'response_encryption_resource_url_mismatch');
    const requirements = pr.accepts.find(
      (r) => isEip155Exact(r) && (r.extra?.assetTransferMethod ?? 'eip3009') === 'eip3009' && getAddress(r.payTo) === getAddress(info.attestation.payTo),
    );
    if (!requirements) throw new EncryptedFetchError('no EIP-3009 exact requirement matches the attested payTo', 'response_encryption_pay_to_mismatch');

    const chainId = Number(requirements.network.split(':')[1]);
    const key = await verifySellerKey(info, {
      chainId,
      payTo: requirements.payTo as Address,
      now: now(),
      pinnedPayTo: opts.pinnedPayTo,
      contractVerifier: opts.contractVerifier,
    });

    // requestHash covers resource.url from the 402, the seller's public namespace (proposal 3.3).
    const binding = createBinding(key, { method, url: pr.resource.url, body: bodyBytes });
    const authorization: TransferAuthorization = {
      from: opts.signer.address,
      to: getAddress(requirements.payTo),
      value: requirements.amount,
      validAfter: '0',
      validBefore: String(now() + requirements.maxTimeoutSeconds),
      nonce: binding.nonce,
    };
    const extra = requirements.extra as { name?: string; version?: string };
    if (!extra.name || !extra.version) throw new EncryptedFetchError('requirements lack the token EIP-712 domain');
    const domain: TokenDomain = { name: extra.name, version: extra.version, chainId, verifyingContract: getAddress(requirements.asset) };
    const signature = await opts.signer.signTypedData(transferAuthorizationTypedData(domain, authorization));

    const payload: PaymentPayload = {
      x402Version: 2,
      resource: pr.resource,
      accepted: requirements,
      payload: { authorization, signature },
      // x402 extensions echo the advertised info and add the client's fields.
      extensions: {
        [EXTENSION_KEY]: { info: payloadInfoFor(info, binding.payloadInfo) },
      },
    };
    return {
      key,
      binding,
      network: requirements.network,
      digest: authorizationDigest(domain, authorization),
      header: encodePaymentSignatureHeader(payload),
    };
  }

  async function sendPaid(request: Request, attempt: PaidAttempt): Promise<Response> {
    let lastError: unknown;
    for (let i = 0; i <= retries; i++) {
      const paid = request.clone();
      paid.headers.set('PAYMENT-SIGNATURE', attempt.header);
      try {
        return await fetchImpl(paid);
      } catch (err) {
        // Same payload again: the seller returns its stored envelope, no second payment.
        lastError = err;
      }
    }
    throw lastError;
  }

  async function open(res: Response, attempt: PaidAttempt): Promise<Response> {
    const type = res.headers.get('content-type') ?? '';
    if (!type.startsWith(ENVELOPE_CONTENT_TYPE)) {
      throw new EncryptedFetchError('paid response was not encrypted', 'response_encryption_decrypt_failed');
    }
    const envelope = (await res.json()) as Envelope;
    const plain = openResponse(attempt.key, attempt.binding, attempt.network, attempt.digest, envelope);
    const headers = new Headers(res.headers);
    headers.set('content-type', plain.contentType);
    headers.delete('content-length');
    const bodyless = plain.status === 204 || plain.status === 205 || plain.status === 304;
    return new Response(bodyless ? null : plain.body, { status: plain.status, headers });
  }

  return async (input, init) => {
    const request = new Request(input, init);
    const bodyBytes = await committedBody(request);
    const first = await fetchImpl(request.clone());
    if (first.status !== 402) return first;

    let pr = readPaymentRequired(first, await first.text());
    // One retry when the key was rotated between the 402 and the paid request (proposal 4.4).
    for (let round = 0; round < 2; round++) {
      let attempt: PaidAttempt;
      try {
        attempt = await preparePayment(pr, bodyBytes, request.method, request.url);
      } catch (err) {
        if (err instanceof ResponseEncryptionError) throw new EncryptedFetchError(err.message, err.reason);
        throw err;
      }
      const res = await sendPaid(request, attempt);
      if (res.status >= 200 && res.status < 300) {
        try {
          return await open(res, attempt);
        } catch (err) {
          if (err instanceof ResponseEncryptionError) throw new EncryptedFetchError(err.message, err.reason);
          throw err;
        }
      }
      if (res.status !== 402) return res;
      const body = await res.text();
      // A 402 carrying only PAYMENT-RESPONSE is a settlement failure, not new requirements.
      const settlement = res.headers.get('PAYMENT-RESPONSE');
      if (settlement && !res.headers.get('PAYMENT-REQUIRED')) {
        const s = decodePaymentResponseHeader(settlement);
        throw new EncryptedFetchError(`settlement failed: ${s.errorReason ?? 'unknown'}`, s.errorReason);
      }
      pr = readPaymentRequired(res, body);
      const reason = errorReason(pr);
      if (reason !== 'response_encryption_unknown_key_id' || round === 1) {
        throw new EncryptedFetchError(`payment rejected: ${reason ?? pr.error ?? 'unknown'}`, reason ?? pr.error);
      }
    }
    throw new EncryptedFetchError('unreachable');
  };
}
