// Seller side of x402 response encryption for Express.
//
// Two deployments (proposal 2.2):
//
// A. The seller runs x402 itself, possibly behind a CDN or reverse proxy.
//
//      app.use(enc.before);                         // raw body, retries
//      app.use(paymentMiddleware(routes, server));  // x402: 402, verify, settle
//      app.use(enc.after);                          // binding check, encrypt
//
//    x402's middleware buffers the handler's output and settles only for status < 400,
//    so `after` encrypts before settlement and a rejection here cancels it (proposal 5, 8).
//
// B. A payment gateway runs x402 and relays paid requests to the seller's origin.
//    The gateway advertises the key with `responseEncryptionExtension` and forwards the
//    payment payload; the origin mounts `createOriginEncryption` and encrypts.
import {
  ENVELOPE_CONTENT_TYPE,
  EXTENSION_KEY,
  ResponseEncryptionError,
  SUITE,
  VERSION,
  X402_EXACT_PERMIT2_PROXY,
  checkBinding,
  equalBytes,
  fromHex,
  paymentView,
  sellerKeyFromPrivate,
  sealResponse,
  toHex,
  type BoundRequest,
  type Envelope,
  type SellerKey,
  type PaymentPayloadInfo,
  type PaymentRequiredInfo,
  type ServerErrorReason,
  type AssetTransferMethod,
  type PaymentView,
  type TokenDomain,
} from '@x402-response-encryption/core';
import { decodePaymentSignatureHeader, encodePaymentRequiredHeader, encodePaymentResponseHeader } from '@x402/core/http';
import type { PaymentPayload, PaymentRequired, ResourceServerExtension, SettleResponse } from '@x402/core/types';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { brotliDecompress, gunzip, inflate, type InputType } from 'node:zlib';
import { promisify } from 'node:util';
import { getAddress, type Address, type Hex } from 'viem';

export interface SellerKeyConfig {
  privateKey: Uint8Array;
  attestation: { payTo: Address; notBefore: number; notAfter: number; signature: Hex };
  /** DID URL of the key, did:web profile only (proposal 4.5). */
  kid?: string;
}

/** Keyed by the signed commitment c (proposal 8.1), the authorization nonce in EIP-3009 and Permit2. */
export interface EnvelopeStore {
  get(commitment: string): Promise<StoredResponse | undefined>;
  set(commitment: string, value: StoredResponse, ttlSeconds: number): Promise<void>;
}

export interface StoredResponse {
  envelope: Envelope;
  /** authorizationDigest (EIP-712 digest) of the payment that produced the envelope; a retry must present the same one (proposal 8.1). */
  authorizationDigest: Hex;
  /** Present when this process settled the payment (deployment A). */
  settlement?: SettleResponse;
}

/**
 * The `resource.url` the resource server issued for this request (proposal 3.3). Under a
 * gateway that is the gateway's public URL, which the origin maps from its own route.
 */
export type ResourceUrlOf = (req: Request) => string;

interface CommonOptions {
  /** Advertised key first; the rest are old keys still in their grace period (proposal 4.4). */
  keys: [SellerKeyConfig, ...SellerKeyConfig[]];
  store?: EnvelopeStore;
  /** Envelope retention for retries (proposal 8.1). Default 24 hours. */
  retentionSeconds?: number;
}

export interface ResponseEncryptionOptions extends CommonOptions {
  /** Default: the URL x402 builds for the 402, from the request's scheme, Host and path. */
  resourceUrl?: ResourceUrlOf;
}

/**
 * A payment the origin accepts (deployment B). The origin does not trust the gateway or the
 * payload's own `accepted` fields, so it verifies the signature against this token domain.
 */
export interface AcceptedPayment {
  network: `${string}:${string}`;
  asset: Address;
  /** Default 'eip3009'. */
  assetTransferMethod?: AssetTransferMethod;
  /** EIP-712 domain name and version of the token, as in the route's `extra`. Required for EIP-3009. */
  name?: string;
  version?: string;
  /** Minimum `value` in the token's base units. */
  amount: string;
}

export interface OriginEncryptionOptions extends CommonOptions {
  resourceUrl: ResourceUrlOf;
  /**
   * True when the request came from the payment gateway over an authenticated channel
   * (mTLS, a gateway-signed token, authenticated origin pulls). Only the gateway knows that a
   * payment settled; a valid signature alone is not proof of payment (proposal 2.2).
   */
  fromGateway: (req: Request) => boolean | Promise<boolean>;
  /** Payments the gateway is configured to collect for this origin's routes. */
  accepts: [AcceptedPayment, ...AcceptedPayment[]];
  /** Unix seconds; injectable for tests. */
  now?: () => number;
}

declare module 'express-serve-static-core' {
  interface Request {
    rawBody?: Buffer;
  }
}

export function memoryEnvelopeStore(): EnvelopeStore {
  const map = new Map<string, { value: StoredResponse; expires: number }>();
  return {
    async get(nonce) {
      const hit = map.get(nonce);
      if (!hit) return undefined;
      if (hit.expires < Date.now()) {
        map.delete(nonce);
        return undefined;
      }
      return hit.value;
    },
    async set(nonce, value, ttl) {
      map.set(nonce, { value, expires: Date.now() + ttl * 1000 });
    },
  };
}

/** The 402 `info` for a key (proposal 7.1). Public data: a gateway can hold it. */
export function advertisedInfo(key: SellerKeyConfig): PaymentRequiredInfo {
  const { publicKey, keyId } = sellerKeyFromPrivate(key.privateKey);
  return {
    version: VERSION,
    required: true,
    suite: SUITE,
    keyId: toHex(keyId),
    ...(key.kid ? { kid: key.kid } : {}),
    publicKey: toHex(publicKey),
    attestation: key.attestation,
  };
}

// Key fields change on rotation; a payload signed against the previous 402 must still pass
// x402's echo check during the grace period (proposal 4.4).
const DYNAMIC_INFO_FIELDS = ['keyId', 'publicKey', 'attestation', 'kid', 'ephemeralPublicKey', 'nonceSalt'];

/**
 * resource server extension that advertises the seller key in the 402. For a gateway
 * (deployment B) this is all it needs: no private key, no access to the response.
 * Declare `declaration` in each covered route's extensions.
 */
export function responseEncryptionExtension(info: PaymentRequiredInfo): ResourceServerExtension {
  return {
    key: EXTENSION_KEY,
    dynamicInfoFields: DYNAMIC_INFO_FIELDS,
    enrichPaymentRequiredResponse: async () => ({ info }),
  };
}

export const declaration = { [EXTENSION_KEY]: {} };

const defaultResourceUrl: ResourceUrlOf = (req) => `${req.protocol}://${req.get('host')}${req.originalUrl}`;

function readRawBody(req: Request): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const MAX_DECODED_BODY = 16 * 1024 * 1024;
const decoders: Record<string, (b: InputType, o: { maxOutputLength: number }) => Promise<Buffer>> = {
  gzip: promisify(gunzip),
  'x-gzip': promisify(gunzip),
  deflate: promisify(inflate),
  br: promisify(brotliDecompress),
};

/** The request body cannot be decoded; sent as 415 before any payment step. */
class BodyEncodingError extends Error {}

// requestHash covers the body bytes after removing Content-Encoding (proposal 3.2); keep them and parse JSON ourselves.
async function keepRawBody(req: Request) {
  if (req.rawBody) return;
  let body = await readRawBody(req);
  const codings = (req.header('content-encoding') ?? '')
    .split(',')
    .map((c) => c.trim().toLowerCase())
    .filter((c) => c && c !== 'identity');
  for (const coding of codings.reverse()) {
    const decode = Object.hasOwn(decoders, coding) ? decoders[coding] : undefined;
    if (!decode) throw new BodyEncodingError(`unsupported content-encoding: ${coding}`);
    body = await decode(body, { maxOutputLength: MAX_DECODED_BODY }).catch(() => {
      throw new BodyEncodingError(`malformed ${coding} body`);
    });
  }
  delete req.headers['content-encoding'];
  req.rawBody = body;
  if (body.length && (req.header('content-type') ?? '').includes('json')) {
    try {
      req.body = JSON.parse(body.toString('utf8'));
    } catch {
      req.body = undefined;
    }
  }
}

/** Reads the body; on an encoding error answers 415 and returns false. */
async function readBodyOr415(req: Request, res: Response): Promise<boolean> {
  try {
    await keepRawBody(req);
    return true;
  } catch (err) {
    if (!(err instanceof BodyEncodingError)) throw err;
    res.status(415).json({ error: err.message });
    return false;
  }
}

/** Per-nonce mutex (proposal 8.1). `acquire` checks and takes the lock without an await in between. */
function nonceLocks() {
  const held = new Map<string, { done: Promise<void>; release: () => void }>();
  return {
    async acquire(nonce: string): Promise<() => void> {
      for (let lock = held.get(nonce); lock; lock = held.get(nonce)) await lock.done;
      let resolve!: () => void;
      const done = new Promise<void>((r) => (resolve = r));
      const entry = {
        done,
        release: () => {
          if (held.get(nonce) === entry) held.delete(nonce);
          resolve();
        },
      };
      held.set(nonce, entry);
      return entry.release;
    },
    release(nonce: string) {
      held.get(nonce)?.release();
    },
  };
}

function paymentFromRequest(req: Request): PaymentPayload | undefined {
  const header = req.header('payment-signature');
  if (!header) return undefined;
  try {
    return decodePaymentSignatureHeader(header);
  } catch {
    return undefined;
  }
}

const payloadInfoOf = (p: PaymentPayload) => (p.extensions?.[EXTENSION_KEY] as { info?: PaymentPayloadInfo } | undefined)?.info;
const domainOf = (network: string, asset: string, extra: { name?: string; version?: string } | undefined): TokenDomain | undefined =>
  extra?.name && extra.version
    ? { name: extra.name, version: extra.version, chainId: Number(network.split(':')[1]), verifyingContract: getAddress(asset) }
    : undefined;

/** The payment seen through its profile (proposal 3.5); the token domain comes from `accepted` unless given. */
type PaymentLike = Pick<PaymentPayload, 'payload'> & { accepted: Pick<PaymentPayload['accepted'], 'network' | 'asset' | 'extra'> };
const viewWith = (p: PaymentLike, tokenDomain: TokenDomain | undefined): PaymentView | undefined =>
  paymentView(p.payload, { chainId: Number(p.accepted.network.split(':')[1]), tokenDomain });

/** Deployment A: x402 has already matched `accepted` against the route's own requirements. */
const viewOf = (p: PaymentLike): PaymentView | undefined =>
  viewWith(p, domainOf(p.accepted.network, p.accepted.asset, p.accepted.extra as { name?: string; version?: string }));

const commitmentOf = (p: PaymentLike) => viewOf(p)?.commitment ?? '';

/** State and steps shared by both deployments. */
function sellerCore(opts: CommonOptions & { resourceUrl: ResourceUrlOf }) {
  const store = opts.store ?? memoryEnvelopeStore();
  const retention = opts.retentionSeconds ?? 24 * 60 * 60;
  const keys: SellerKey[] = opts.keys.map((k) => sellerKeyFromPrivate(k.privateKey));
  const info = advertisedInfo(opts.keys[0]);

  const requestOf = (req: Request) => ({
    method: req.method,
    url: opts.resourceUrl(req),
    body: req.rawBody ? new Uint8Array(req.rawBody) : new Uint8Array(),
  });

  const reject = (res: Response, payment: PaymentPayload, reason: ServerErrorReason) => {
    const paymentRequired: PaymentRequired = {
      x402Version: 2,
      error: reason,
      resource: payment.resource ?? { url: '' },
      accepts: [payment.accepted],
      extensions: { [EXTENSION_KEY]: { info: { ...info, errorReason: reason } } },
    };
    res.status(402).setHeader('PAYMENT-REQUIRED', encodePaymentRequiredHeader(paymentRequired));
    res.json(paymentRequired);
  };

  /** Binding check. On failure it sends the 402 itself and returns undefined (proposal 3.1, A.6). */
  const bind = (req: Request, res: Response, payment: PaymentPayload, view: PaymentView | undefined, skipKeyCheck = false): BoundRequest | undefined => {
    if (!view) {
      reject(res, payment, 'response_encryption_nonce_mismatch');
      return undefined;
    }
    try {
      return checkBinding(payloadInfoOf(payment), {
        signedCommitment: view.commitment,
        request: requestOf(req),
        keys,
        skipKeyCheck,
      });
    } catch (err) {
      if (err instanceof ResponseEncryptionError) {
        reject(res, payment, err.reason as ServerErrorReason);
        return undefined;
      }
      throw err;
    }
  };

  const sendStored = (res: Response, stored: StoredResponse) => {
    if (stored.settlement) res.setHeader('PAYMENT-RESPONSE', encodePaymentResponseHeader(stored.settlement));
    res.status(200).type(ENVELOPE_CONTENT_TYPE).send(JSON.stringify(stored.envelope));
  };

  /** Buffers the handler's output and replaces a 2xx body with its envelope. Never falls back to plaintext (proposal 8). */
  const sealOnEnd = (res: Response, payment: PaymentPayload, digest: Uint8Array, bound: BoundRequest, onSealed: (e: Envelope) => void) => {
    const chunks: Buffer[] = [];
    const write = res.write.bind(res);
    const end = res.end.bind(res);
    const toBuffer = (c: unknown, enc?: unknown) =>
      Buffer.isBuffer(c) ? c : typeof c === 'string' ? Buffer.from(c, (enc as BufferEncoding) ?? 'utf8') : Buffer.from(c as Uint8Array);

    res.write = ((chunk: unknown, encoding?: unknown, cb?: unknown) => {
      chunks.push(toBuffer(chunk, typeof encoding === 'string' ? encoding : undefined));
      if (typeof encoding === 'function') (encoding as () => void)();
      else if (typeof cb === 'function') (cb as () => void)();
      return true;
    }) as Response['write'];

    res.end = ((chunk?: unknown, encoding?: unknown) => {
      if (chunk && typeof chunk !== 'function') chunks.push(toBuffer(chunk, typeof encoding === 'string' ? encoding : undefined));
      res.write = write;
      res.end = end;
      const status = res.statusCode;
      // Not a paid success: x402 does not settle for >= 400, and the body is not a resource body.
      if (status < 200 || status > 299) return end(Buffer.concat(chunks));
      let envelope: Envelope;
      try {
        const contentType = String(res.getHeader('content-type') ?? 'application/octet-stream');
        envelope = sealResponse(bound, payment.accepted.network, digest, { status, contentType, body: new Uint8Array(Buffer.concat(chunks)) });
      } catch {
        res.status(500).type('application/json');
        res.removeHeader('content-length');
        return end(JSON.stringify({ errorReason: 'response_encryption_encryption_failed' }));
      }
      onSealed(envelope);
      // The resource status travels in the envelope; the wire status is always 200 so a 204 still has a body (proposal 7.3).
      res.statusCode = 200;
      const body = JSON.stringify(envelope);
      res.setHeader('content-type', ENVELOPE_CONTENT_TYPE);
      res.setHeader('content-length', Buffer.byteLength(body));
      return end(body);
    }) as Response['end'];
  };

  return { store, retention, info, keys, bind, sendStored, sealOnEnd };
}

/** Deployment A: the seller runs @x402/express itself. */
export function createResponseEncryption(opts: ResponseEncryptionOptions) {
  const m = sellerCore({ ...opts, resourceUrl: opts.resourceUrl ?? defaultResourceUrl });

  // Envelopes produced but not yet settled, and per-nonce locks (proposal 8.1).
  const pending = new Map<string, StoredResponse>();
  const locks = nonceLocks();
  const release = (nonce: string) => {
    pending.delete(nonce);
    locks.release(nonce);
  };

  /** Register on x402ResourceServer. */
  const extension: ResourceServerExtension = {
    ...responseEncryptionExtension(m.info),
    hooks: {
      onAfterSettle: async (_decl, ctx) => {
        const c = commitmentOf(ctx.paymentPayload);
        const sealed = pending.get(c);
        try {
          if (sealed && ctx.result.success) await m.store.set(c, { ...sealed, settlement: ctx.result as SettleResponse }, m.retention);
        } finally {
          release(c);
        }
      },
      onSettleFailure: async (_decl, ctx) => release(commitmentOf(ctx.paymentPayload)),
      onVerifiedPaymentCanceled: async (_decl, ctx) => release(commitmentOf(ctx.paymentPayload)),
    },
  };

  /** Mount before paymentMiddleware. */
  const before: RequestHandler = async (req, res, next) => {
    try {
      if (!(await readBodyOr415(req, res))) return;
      const payment = paymentFromRequest(req);
      const view = payment && viewOf(payment);
      if (!payment || !payloadInfoOf(payment) || !view) return next();
      const nonce = view.commitment;

      // Held until settlement finishes, so a duplicate waits and then finds the stored envelope.
      const unlock = await locks.acquire(nonce);
      let stored: StoredResponse | undefined;
      try {
        stored = await m.store.get(nonce);
      } catch (err) {
        unlock();
        throw err;
      }
      if (stored) {
        unlock();
        // Retry of a settled payment: the same signed authorization and binding, then the stored bytes (proposal 8.1).
        // Anything else goes to x402, whose facilitator rejects the used nonce.
        if (toHex(view.digest) !== stored.authorizationDigest || !(await view.signerMatches())) return next();
        if (m.bind(req, res, payment, view, true)) m.sendStored(res, stored);
        return;
      }
      // Requests that never reach settlement must not hold the lock.
      res.on('close', () => setTimeout(() => (pending.has(nonce) ? undefined : unlock()), 0));
      next();
    } catch (err) {
      next(err);
    }
  };

  /** Mount after paymentMiddleware. Runs only for verified payments. */
  const after: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    const payment = paymentFromRequest(req);
    if (!payment) return next();
    // A HEAD response has no body to carry the envelope; refusing here cancels settlement (proposal 7.3).
    if (req.method === 'HEAD') return void res.status(405).json({ error: 'HEAD is not supported for encrypted resources' });
    let bound;
    let view: PaymentView | undefined;
    try {
      view = viewOf(payment);
      bound = m.bind(req, res, payment, view);
    } catch (err) {
      return next(err);
    }
    if (!bound || !view) return;
    const { commitment, digest } = view;
    m.sealOnEnd(res, payment, digest, bound, (envelope) => pending.set(commitment, { envelope, authorizationDigest: toHex(digest) }));
    next();
  };

  return { extension, declaration, before, after };
}

/**
 * Deployment B: the origin behind a payment gateway. The gateway verifies and settles,
 * and the origin serves only requests that `fromGateway` authenticates. The gateway is
 * still an intermediary for the response, so the origin checks the payer's signature
 * against its own payment terms and the binding before it encrypts.
 */
export function createOriginEncryption(opts: OriginEncryptionOptions): RequestHandler {
  for (const a of opts.accepts) {
    if ((a.assetTransferMethod ?? 'eip3009') === 'eip3009' && (!a.name || !a.version)) {
      throw new Error(`accepts entry for ${a.asset} on ${a.network}: EIP-3009 terms need the token's EIP-712 name and version`);
    }
  }
  const m = sellerCore(opts);
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const locks = nonceLocks();
  const refuse = (res: Response, errorReason: string) => res.status(402).json({ errorReason });
  // Decodes keyId exactly as checkBinding does, so the key whose payTo is checked is the key that encrypts.
  const payToOf = (keyId: string | undefined) => {
    let id: Uint8Array;
    try {
      id = fromHex(keyId ?? '');
    } catch {
      return undefined;
    }
    const i = m.keys.findIndex((k) => equalBytes(k.keyId, id));
    return i < 0 ? undefined : getAddress(opts.keys[i]!.attestation.payTo);
  };

  return async (req, res, next) => {
    try {
      if (!(await opts.fromGateway(req))) return void res.status(403).json({ error: 'paid requests are accepted only from the payment gateway' });
      if (req.method === 'HEAD') return void res.status(405).json({ error: 'HEAD is not supported for encrypted resources' });
      if (!(await readBodyOr415(req, res))) return;
      const payment = paymentFromRequest(req);
      // The gateway did not forward a payment for a covered route.
      if (!payment || !payment.payload) return refuse(res, 'response_encryption_extension_missing');

      // Verify against the origin's own terms, never the payload's claimed token or price.
      const method: AssetTransferMethod = 'permit2Authorization' in payment.payload ? 'permit2' : 'eip3009';
      const terms = opts.accepts.find(
        (a) =>
          a.network === payment.accepted.network &&
          getAddress(a.asset) === getAddress(payment.accepted.asset) &&
          (a.assetTransferMethod ?? 'eip3009') === method,
      );
      // The token domain comes only from the origin's terms, never from the payload (EIP-3009 terms always carry one).
      const view = terms && viewWith(payment, domainOf(terms.network, terms.asset, terms));
      if (
        !terms ||
        !view ||
        view.method !== method ||
        view.token !== getAddress(terms.asset) ||
        (view.method === 'permit2' && view.spender !== getAddress(X402_EXACT_PERMIT2_PROXY)) ||
        view.value < BigInt(terms.amount) ||
        !(await view.signerMatches())
      ) {
        return refuse(res, 'invalid_payment_authorization');
      }
      const nonce = view.commitment;
      const digest = toHex(view.digest);

      const unlock = await locks.acquire(nonce);
      let sealing = false;
      try {
        const stored = await m.store.get(nonce);
        if (stored) {
          // Retry: the same signed authorization gets the same bytes, even after validBefore (proposal 8.1).
          if (stored.authorizationDigest !== digest) return refuse(res, 'invalid_payment_authorization');
          if (m.bind(req, res, payment, view, true)) m.sendStored(res, stored);
          return;
        }
        // A new execution: the authorization must still be spendable and pay the payTo that attested the key named in the payload.
        const t = now();
        const payTo = payToOf(payloadInfoOf(payment)?.keyId);
        if (view.validAfter > BigInt(t) || view.validBefore <= BigInt(t) || !payTo || view.to !== payTo) {
          return refuse(res, 'invalid_payment_authorization');
        }
        const bound = m.bind(req, res, payment, view);
        if (!bound) return;
        // Settlement happens at the gateway. Keep the envelope so a resend of the same payload gets the same bytes.
        sealing = true;
        let saved: Promise<void> = Promise.resolve();
        m.sealOnEnd(res, payment, view.digest, bound, (envelope) => {
          saved = m.store.set(nonce, { envelope, authorizationDigest: digest }, m.retention);
        });
        res.on('close', () => void saved.catch(() => undefined).finally(unlock));
        next();
      } finally {
        if (!sealing) unlock();
      }
    } catch (err) {
      next(err);
    }
  };
}
