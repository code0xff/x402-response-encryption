// Deployment B end-to-end: client -> payment gateway running the real @x402/express
// middleware, which relays paid requests to the seller's origin under a different path.
// The gateway issues resource.url, verifies and settles; the origin checks the payment
// against its own terms, checks the binding and encrypts. The gateway records everything it relays.
import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import express from 'express';
import { privateKeyToAccount } from 'viem/accounts';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { sellerKeyFromPrivate, toHex, transferAuthorizationTypedData } from '@x402-response-encryption/core';
import { wrapFetchWithEncryptedPayment } from '@x402-response-encryption/fetch';
import {
  advertisedInfo,
  createOriginEncryption,
  declaration,
  memoryEnvelopeStore,
  responseEncryptionExtension,
  type AcceptedPayment,
  type EnvelopeStore,
  type SellerKeyConfig,
} from '../src/index.js';
import { CHAIN_ID, LocalFacilitator, NETWORK, SECRET, hex, keyConfig, listen, payTo, payer, testKey } from './helpers.js';

const USDC: AcceptedPayment = { network: NETWORK, asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', name: 'USDC', version: '2', amount: '10000' };

let facilitator: LocalFacilitator;
let origin: Server;
let gateway: Server;
let gatewayUrl: string;
let originUrl: string;
let key: SellerKeyConfig;
const relayed: string[] = [];
/** Origin path the gateway relays /v1/report to; a test swaps it to simulate a misrouting gateway. */
let reportTarget = '/internal/report';
let forwardPayment = true;
let clock = 0;
/** Stands in for the authenticated gateway channel (mTLS, signed token) in these tests. */
const RELAY_SECRET = 'test-relay-secret';
let executions = 0;

/** Memory store with a delay, so concurrent duplicates overlap. */
function slowStore(): EnvelopeStore {
  const inner = memoryEnvelopeStore();
  const pause = () => new Promise((r) => setTimeout(r, 20));
  return {
    get: async (n) => (await pause(), inner.get(n)),
    set: async (n, v, t) => (await pause(), inner.set(n, v, t)),
  };
}

beforeAll(async () => {
  key = await keyConfig('enc-1');
  // A second key attested by a different payTo, as during a recipient change.
  const other = privateKeyToAccount(hex(testKey('other-payTo')));
  const otherKey = await keyConfig('enc-other', other);

  // Origin: holds the private keys, maps its routes to the gateway's public URLs.
  const app = express();
  const now = () => clock || Math.floor(Date.now() / 1000);
  const enc = (publicPath: string, keys: [SellerKeyConfig, ...SellerKeyConfig[]] = [key]) =>
    createOriginEncryption({
      keys,
      accepts: [USDC],
      fromGateway: (req) => req.header('x-relay-secret') === RELAY_SECRET,
      store: slowStore(),
      now,
      resourceUrl: (req) => gatewayUrl + publicPath + (req.originalUrl.split('?')[1] ? '?' + req.originalUrl.split('?')[1] : ''),
    });
  app.post('/internal/report', enc('/v1/report'), (_req, res) => {
    executions++;
    res.json(JSON.parse(SECRET));
  });
  app.post('/internal/summary', enc('/v1/summary'), (_req, res) => res.json({ summary: 'cheap data' }));
  app.post('/internal/mixed', enc('/v1/report', [key, otherKey]), (_req, res) => res.json(JSON.parse(SECRET)));
  origin = createServer(app);
  originUrl = await listen(origin);

  // Gateway: resource server with only the public key info; relays the payload and the body unchanged.
  facilitator = new LocalFacilitator();
  const resourceServer = new x402ResourceServer(facilitator)
    .register(NETWORK, new ExactEvmScheme())
    .registerExtension(responseEncryptionExtension(advertisedInfo(key)));
  const gw = express();
  const route = { accepts: { scheme: 'exact' as const, price: '$0.01', network: NETWORK, payTo: payTo.address }, extensions: declaration };
  gw.use(paymentMiddleware({ 'POST /v1/report': { ...route, description: 'Quarterly report' } }, resourceServer));
  gw.post('/v1/report', express.raw({ type: '*/*' }), async (req, res) => {
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    relayed.push(body.toString());
    const headers: Record<string, string> = { 'x-relay-secret': RELAY_SECRET };
    if (req.header('content-type')) headers['content-type'] = req.header('content-type')!;
    if (forwardPayment && req.header('payment-signature')) headers['payment-signature'] = req.header('payment-signature')!;
    const up = await fetch(originUrl + reportTarget, { method: 'POST', headers, body });
    const out = Buffer.from(await up.arrayBuffer());
    relayed.push(out.toString());
    for (const h of ['content-type', 'payment-required']) if (up.headers.get(h)) res.setHeader(h, up.headers.get(h)!);
    res.status(up.status).send(out);
  });
  gateway = createServer(gw);
  gatewayUrl = await listen(gateway);
});

afterAll(() => {
  origin?.close();
  gateway?.close();
});

beforeEach(() => {
  relayed.length = 0;
  reportTarget = '/internal/report';
  forwardPayment = true;
  clock = 0;
  executions = 0;
});

const BODY = '{"quarter":"Q3"}';

const pay = (f: typeof fetch = fetch) =>
  wrapFetchWithEncryptedPayment(f, { signer: payer, pinnedPayTo: payTo.address })(gatewayUrl + '/v1/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: BODY,
  });

/** The client's signed payment header for one request, captured before it reaches the gateway. */
async function signedHeader(): Promise<string> {
  let header: string | undefined;
  const capture: typeof fetch = async (input, init) => {
    const req = new Request(input, init);
    header = req.headers.get('PAYMENT-SIGNATURE') ?? undefined;
    if (header) throw new TypeError('captured');
    return fetch(req);
  };
  await pay(capture).catch(() => undefined);
  return header!;
}

const decode = (h: string) => JSON.parse(Buffer.from(h, 'base64').toString());
const encode = (p: unknown) => Buffer.from(JSON.stringify(p)).toString('base64');

/** Re-signs the captured payload with other authorization fields or token domain, keeping its nonce. */
async function resign(header: string, change: { auth?: Record<string, string>; domain?: Partial<AcceptedPayment>; signer?: typeof payer }) {
  const p = decode(header);
  const signer = change.signer ?? payer;
  const auth = { ...p.payload.authorization, from: signer.address, ...change.auth };
  const terms = { ...USDC, ...change.domain };
  p.accepted = { ...p.accepted, asset: terms.asset, extra: { ...p.accepted.extra, name: terms.name, version: terms.version } };
  const domain = { name: terms.name, version: terms.version, chainId: CHAIN_ID, verifyingContract: terms.asset };
  p.payload = { authorization: auth, signature: await signer.signTypedData(transferAuthorizationTypedData(domain, auth)) };
  return encode(p);
}

/** Relays a payment header to the origin as the gateway would, with whatever the gateway chose to forward. */
const toOrigin = (header: string, path = '/internal/report', init: RequestInit = {}) =>
  fetch(originUrl + path, {
    method: 'POST',
    ...init,
    headers: { 'content-type': 'application/json', 'payment-signature': header, 'x-relay-secret': RELAY_SECRET, ...(init.headers as Record<string, string>) },
    body: init.body ?? BODY,
  });

describe('paid request through a relaying payment gateway', () => {
  it('signs over the gateway URL, decrypts at the client, and keeps plaintext from the gateway', async () => {
    const before = facilitator.settlements;
    const res = await pay();
    expect(await res.json()).toEqual(JSON.parse(SECRET));
    expect(facilitator.settlements).toBe(before + 1);
    expect(relayed.join('\n')).toContain('"ciphertext"');
    expect(relayed.join('\n')).not.toContain('quarterly numbers');
  });

  it('rejects before settlement when the gateway relays to a different resource', async () => {
    const before = facilitator.settlements;
    reportTarget = '/internal/summary';
    await expect(pay()).rejects.toMatchObject({ reason: 'response_encryption_nonce_mismatch' });
    expect(facilitator.settlements).toBe(before);
    expect(relayed.join('\n')).not.toContain('cheap data');
  });

  it('rejects before settlement when the gateway swaps the ephemeral key', async () => {
    const before = facilitator.settlements;
    const tamper: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      const header = req.headers.get('PAYMENT-SIGNATURE');
      if (header) {
        const p = decode(header);
        p.extensions['response-encryption'].info.ephemeralPublicKey = hex(sellerKeyFromPrivate(testKey('attacker')).publicKey);
        req.headers.set('PAYMENT-SIGNATURE', encode(p));
      }
      return fetch(req);
    };
    await expect(pay(tamper)).rejects.toMatchObject({ reason: 'response_encryption_nonce_mismatch' });
    expect(facilitator.settlements).toBe(before);
  });

  it('serves nothing when the gateway does not forward the payment', async () => {
    const before = facilitator.settlements;
    forwardPayment = false;
    await expect(pay()).rejects.toThrow();
    expect(facilitator.settlements).toBe(before);
    expect(relayed.join('\n')).not.toContain('quarterly numbers');
  });
});

describe('origin checks its own payment terms', () => {
  it('refuses a validly signed payment that does not come from the gateway', async () => {
    const res = await toOrigin(await signedHeader(), '/internal/report', { headers: { 'x-relay-secret': 'guess' } });
    expect(res.status).toBe(403);
    expect(executions).toBe(0);
  });

  it.each([
    ['a token the origin does not accept', { domain: { asset: '0x000000000000000000000000000000000000dEaD' as const } }],
    ['the right token address under a fabricated domain name', { domain: { name: 'Fake USDC' } }],
    ['a value below the price', { auth: { value: '0' } }],
    ['an authorization not yet valid', { auth: { validAfter: String(Math.floor(Date.now() / 1000) + 3600) } }],
  ])('refuses %s without running the handler', async (_name, change) => {
    const res = await toOrigin(await resign(await signedHeader(), change));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
    expect(executions).toBe(0);
  });

  it('refuses a payment to one payTo that selects a key attested by another', async () => {
    const p = decode(await signedHeader());
    const otherKeyId = toHex(sellerKeyFromPrivate(testKey('enc-other')).keyId);
    p.extensions['response-encryption'].info.keyId = otherKeyId;
    const res = await toOrigin(encode(p), '/internal/mixed');
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
  });
});

describe('origin retries and duplicates', () => {
  it('runs the handler once for concurrent duplicates and returns the same envelope', async () => {
    const header = await signedHeader();
    const [a, b] = await Promise.all([toOrigin(header), toOrigin(header)]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(await a.text()).toBe(await b.text());
    expect(executions).toBe(1);
  });

  it('returns the stored envelope after validBefore, but refuses a new execution', async () => {
    const header = await signedHeader();
    const first = await (await toOrigin(header)).text();
    clock = Number(decode(header).payload.authorization.validBefore) + 3600;
    const retry = await toOrigin(header);
    expect(retry.status).toBe(200);
    expect(await retry.text()).toBe(first);
    const fresh = await toOrigin(await signedHeader());
    expect(fresh.status).toBe(402);
    expect(executions).toBe(1);
  });

  it('does not hand a stored envelope to a different authorization that reuses the nonce', async () => {
    const header = await signedHeader();
    expect((await toOrigin(header)).status).toBe(200);
    const attacker = privateKeyToAccount(hex(testKey('attacker')));
    const res = await toOrigin(await resign(header, { signer: attacker }));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
  });
});

describe('request content encoding', () => {
  it('hashes the decoded body of a gzip request', async () => {
    const { gzipSync } = await import('node:zlib');
    const res = await toOrigin(await signedHeader(), '/internal/report', { body: gzipSync(BODY), headers: { 'content-encoding': 'gzip' } });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/x402-encrypted+json');
  });

  it('refuses an unsupported or malformed encoding before any payment step', async () => {
    const header = await signedHeader();
    expect((await toOrigin(header, '/internal/report', { headers: { 'content-encoding': 'compress' } })).status).toBe(415);
    expect((await toOrigin(header, '/internal/report', { body: 'not gzip', headers: { 'content-encoding': 'gzip' } })).status).toBe(415);
    expect(executions).toBe(0);
  });
});
