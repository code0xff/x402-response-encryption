// Runs the shared test vectors in test-vectors/ against this implementation.
import { readFileSync } from 'node:fs';
import { getAddress, recoverTypedDataAddress } from 'viem';
import { describe, expect, it } from 'vitest';
import {
  ResponseEncryptionError,
  authorizationDigest,
  canonicalUrl,
  checkBinding,
  createBinding,
  fromBase64Url,
  fromHex,
  sellerKeyFromPrivate,
  openResponse,
  sealResponse,
  toHex,
  transferAuthorizationTypedData,
  utf8Bytes,
  verifySellerKey,
  type Envelope,
  type PaymentPayloadInfo,
  type PaymentRequiredInfo,
  type TokenDomain,
  type TransferAuthorization,
} from '../src/index.js';

const dir = new URL('../../../test-vectors/', import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), 'utf8'));

const vector = load('vector-1.json');
const negative = load('negative-cases.json');
const urlCases = load('url-cases.json');

const chainIdOf = (caip2: string) => Number(caip2.split(':')[1]);

describe('vector-1', () => {
  const { inputs, intermediate, output } = vector;
  const chainId = chainIdOf(inputs.network);
  const seller = sellerKeyFromPrivate(fromHex(inputs.sellerEncryptionPrivateKey));
  const info: PaymentRequiredInfo = {
    version: 1,
    required: true,
    suite: 'secp256k1-hkdf-sha256-aes256gcm',
    keyId: intermediate.keyId,
    publicKey: intermediate.sellerEncryptionPublicKey,
    attestation: { payTo: intermediate.payToAddress, ...inputs.attestation, signature: intermediate.attestationSignature },
  };

  it('reproduces every intermediate value and the envelope', async () => {
    expect(toHex(seller.publicKey)).toBe(intermediate.sellerEncryptionPublicKey);
    expect(toHex(seller.keyId)).toBe(intermediate.keyId);

    const key = await verifySellerKey(info, { chainId, payTo: intermediate.payToAddress, now: 1800000000 });
    const binding = createBinding(key, inputs.request, {
      ephemeralPrivateKey: fromHex(inputs.clientEphemeralPrivateKey),
      nonceSalt: fromHex(inputs.nonceSalt),
    });
    expect(toHex(binding.ephemeralPublicKey)).toBe(intermediate.clientEphemeralPublicKey);
    expect(toHex(binding.requestHash)).toBe(intermediate.requestHash);
    expect(binding.nonce).toBe(intermediate.nonce);

    const authorization: TransferAuthorization = { ...inputs.authorization, nonce: binding.nonce };
    const digest = authorizationDigest(inputs.tokenDomain, authorization);
    expect(toHex(digest)).toBe(intermediate.authorizationDigest);

    const bound = checkBinding(binding.payloadInfo, { authorizationNonce: binding.nonce, request: inputs.request, keys: [seller] });
    const envelope = sealResponse(
      bound,
      inputs.network,
      digest,
      { status: inputs.response.status, contentType: inputs.response.contentType, body: utf8Bytes(inputs.response.body) },
      fromHex(inputs.iv),
    );
    expect(envelope).toEqual(output.envelope);

    const opened = openResponse(key, binding, inputs.network, digest, envelope);
    expect(new TextDecoder().decode(opened.body)).toBe(inputs.response.body);
  });
});

// Negative cases: run the same stages as verify_cases.py, through the public API.
type Stage = { stage: string; reason: string | null } | null;

async function runCase(c: any): Promise<Stage> {
  const w = c.wire;
  const network: string = negative.network;
  const tokenDomain: TokenDomain = negative.tokenDomain;
  const mer = c.seller ?? negative.seller;
  const reject = (stage: string, err: unknown): Stage => {
    if (err instanceof ResponseEncryptionError) return { stage, reason: err.reason };
    throw err;
  };

  const { resource: _resource, ...info } = w.paymentRequired;
  let key;
  try {
    key = await verifySellerKey(info as PaymentRequiredInfo, {
      chainId: chainIdOf(network),
      payTo: w.paymentRequirements.payTo,
      now: c.client.now,
    });
  } catch (err) {
    return reject('client-402', err);
  }
  if (c.expect && c.expect.stage === 'client-402' && c.expect.reason === null) return c.expect;

  const auth: TransferAuthorization = w.paymentPayload.authorization;
  // The vectors give only the default key's private part; other accepted keyIds are matched by id alone.
  const own = sellerKeyFromPrivate(fromHex(negative.seller.encryptionPrivateKey));
  const keys = (mer.keyIds as string[]).map((id) =>
    id === toHex(own.keyId) ? own : { privateKey: new Uint8Array(32), publicKey: new Uint8Array(33), keyId: fromHex(id) },
  );
  const stored: Envelope | undefined = mer.stored?.[auth.nonce.toLowerCase()];
  try {
    // The facilitator verifies the payment signature before the binding is checked (proposal A.6).
    // No vector fails both, so checking it first here does not change any expected stage.
    if (!(await signatureValid(tokenDomain, auth, w.paymentPayload.signature))) {
      return { stage: 'seller', reason: 'invalid_exact_evm_payload_signature' };
    }
    const payload: PaymentPayloadInfo | undefined = w.paymentPayload.extension?.info;
    checkBinding(payload, { authorizationNonce: auth.nonce, request: w.request, keys, skipKeyCheck: !!stored });
  } catch (err) {
    return reject('seller', err);
  }

  const envelope: Envelope = stored ?? w.envelope;
  const client = c.client;
  const binding = createBinding(key, client.request, {
    ephemeralPrivateKey: fromHex(client.ephemeralPrivateKey),
    nonceSalt: fromHex(w.paymentPayload.extension.info.nonceSalt),
  });
  try {
    openResponse(key, binding, network, authorizationDigest(tokenDomain, client.authorization), envelope);
  } catch (err) {
    return reject('client-response', err);
  }
  return null;
}

async function signatureValid(domain: TokenDomain, auth: TransferAuthorization, signature: `0x${string}`) {
  try {
    const signer = await recoverTypedDataAddress({ ...transferAuthorizationTypedData(domain, auth), signature });
    return getAddress(signer) === getAddress(auth.from);
  } catch {
    return false;
  }
}

describe('negative cases (core profile)', () => {
  for (const c of negative.cases.filter((x: any) => x.profile === 'core')) {
    it(c.id, async () => {
      expect(await runCase(c)).toEqual(c.expect);
    });
  }
});

describe('pinned payTo', () => {
  it('refuses a validly attested key for a different seller', async () => {
    const { inputs, intermediate } = vector;
    const info: PaymentRequiredInfo = {
      version: 1,
      required: true,
      suite: 'secp256k1-hkdf-sha256-aes256gcm',
      keyId: intermediate.keyId,
      publicKey: intermediate.sellerEncryptionPublicKey,
      attestation: { payTo: intermediate.payToAddress, ...inputs.attestation, signature: intermediate.attestationSignature },
    };
    const opts = { chainId: chainIdOf(inputs.network), payTo: intermediate.payToAddress, now: 1800000000 };
    await expect(verifySellerKey(info, { ...opts, pinnedPayTo: intermediate.payToAddress })).resolves.toBeDefined();
    await expect(verifySellerKey(info, { ...opts, pinnedPayTo: intermediate.payerAddress })).rejects.toMatchObject({
      reason: 'response_encryption_pay_to_mismatch',
    });
  });
});

describe('URL canonicalization', () => {
  for (const c of urlCases.cases) {
    it(c.description, () => {
      if (c.error) {
        expect(() => canonicalUrl(c.input)).toThrow(expect.objectContaining({ reason: c.error }));
      } else {
        expect(canonicalUrl(c.input)).toBe(c.canonical);
      }
    });
  }
});

describe('bytes', () => {
  it('base64url round-trips without padding', () => {
    for (let n = 0; n < 40; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const s = Buffer.from(b).toString('base64url');
      expect(fromBase64Url(s)).toEqual(b);
    }
  });
});
