// Deployment A end-to-end: client -> logging reverse proxy -> Express seller running the
// real @x402/express middleware, with an in-process facilitator that checks EIP-3009
// signatures and records used nonces.
import { createServer, request as httpRequest, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import express from 'express';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { gzipSync } from 'node:zlib';
import { privateKeyToAccount } from 'viem/accounts';
import { keyIdOf, sellerKeyFromPrivate, transferAuthorizationTypedData } from '@x402-response-encryption/core';
import { EncryptedFetchError, wrapFetchWithEncryptedPayment } from '@x402-response-encryption/fetch';
import { createResponseEncryption, memoryEnvelopeStore, type EnvelopeStore, type SellerKeyConfig } from '../src/index.js';
import { CHAIN_ID, LocalFacilitator, NETWORK, SECRET, hex, keyConfig, listen, payTo, payer, testKey } from './helpers.js';
/** Reverse proxy that records every request and response body it relays. */
function loggingProxy(target: string) {
  const log: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      log.push(body.toString());
      const up = httpRequest(target + req.url, { method: req.method, headers: req.headers }, (upRes) => {
        const out: Buffer[] = [];
        upRes.on('data', (c) => out.push(c));
        upRes.on('end', () => {
          const resBody = Buffer.concat(out);
          log.push(resBody.toString(), JSON.stringify(upRes.headers));
          res.writeHead(upRes.statusCode ?? 502, upRes.headers);
          res.end(resBody);
        });
      });
      up.end(body);
    });
  });
  return { server, log };
}

let facilitator: LocalFacilitator;
let seller: Server;
let proxy: ReturnType<typeof loggingProxy>;
let proxyUrl: string;
let keys: SellerKeyConfig[];
let setKeys: (k: SellerKeyConfig[]) => void;
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
  keys = [await keyConfig('enc-1')];
  facilitator = new LocalFacilitator();
  const resourceServer = new x402ResourceServer(facilitator).register(NETWORK, new ExactEvmScheme());

  // The encryption layer is rebuilt when a test rotates keys; routes stay fixed.
  let enc = createResponseEncryption({ keys: keys as [SellerKeyConfig], store: slowStore() });
  setKeys = (k) => {
    enc = createResponseEncryption({ keys: k as [SellerKeyConfig], store: slowStore() });
    resourceServer.registerExtension(enc.extension);
  };
  resourceServer.registerExtension(enc.extension);

  const app = express();
  app.use((req, res, next) => enc.before(req, res, next));
  app.use(
    paymentMiddleware(
      {
        'POST /v1/report': {
          accepts: { scheme: 'exact', price: '$0.01', network: NETWORK, payTo: payTo.address },
          description: 'Quarterly report',
          extensions: enc.declaration,
        },
        'POST /v1/ack': {
          accepts: { scheme: 'exact', price: '$0.01', network: NETWORK, payTo: payTo.address },
          description: 'Acknowledgement without a body',
          extensions: enc.declaration,
        },
      },
      resourceServer,
    ),
  );
  app.use((req, res, next) => enc.after(req, res, next));
  app.post('/v1/ack', (_req, res) => res.status(204).end());
  app.post('/v1/report', (req, res) => {
    executions++;
    res.json(JSON.parse(SECRET));
  });

  seller = createServer(app);
  const sellerUrl = await listen(seller);
  proxy = loggingProxy(sellerUrl);
  proxyUrl = await listen(proxy.server);
});

afterAll(() => {
  seller?.close();
  proxy?.server.close();
});

beforeEach(() => {
  proxy.log.length = 0;
  executions = 0;
});

/** The client's signed payment header for one request, captured before it is sent. */
async function signedHeader(body = '{}'): Promise<string> {
  let header: string | undefined;
  const capture: typeof fetch = async (input, init) => {
    const req = new Request(input, init);
    header = req.headers.get('PAYMENT-SIGNATURE') ?? undefined;
    if (header) throw new TypeError('captured');
    return fetch(req);
  };
  await wrapFetchWithEncryptedPayment(capture, { signer: payer, transportRetries: 0 })(proxyUrl + '/v1/report', { method: 'POST', body }).catch(() => undefined);
  return header!;
}

const sendPaid = (header: string, init: RequestInit = {}) =>
  fetch(proxyUrl + '/v1/report', { method: 'POST', body: '{}', ...init, headers: { 'PAYMENT-SIGNATURE': header, ...(init.headers as Record<string, string>) } });

const clientFetch = (overrides: Partial<Parameters<typeof wrapFetchWithEncryptedPayment>[1]> = {}) =>
  wrapFetchWithEncryptedPayment(fetch, { signer: payer, ...overrides });

describe('paid request through a logging intermediary', () => {
  it('decrypts the response and leaves no plaintext in the intermediary log', async () => {
    const before = facilitator.settlements;
    const res = await clientFetch()(proxyUrl + '/v1/report', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"quarter":"Q3"}',
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(JSON.parse(SECRET));
    expect(facilitator.settlements).toBe(before + 1);
    const logged = proxy.log.join('\n');
    expect(logged).toContain('application/x402-encrypted+json');
    expect(logged).not.toContain('quarterly numbers');
  });

  it('rejects before settlement when the intermediary swaps the ephemeral key', async () => {
    const before = facilitator.settlements;
    const tamper: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      const header = req.headers.get('PAYMENT-SIGNATURE');
      if (header) {
        const p = JSON.parse(Buffer.from(header, 'base64').toString());
        p.extensions['response-encryption'].info.ephemeralPublicKey = hex(sellerKeyFromPrivate(testKey('attacker')).publicKey);
        req.headers.set('PAYMENT-SIGNATURE', Buffer.from(JSON.stringify(p)).toString('base64'));
      }
      return fetch(req);
    };
    const f = wrapFetchWithEncryptedPayment(tamper, { signer: payer });
    await expect(f(proxyUrl + '/v1/report', { method: 'POST', body: '{}' })).rejects.toMatchObject({
      reason: 'response_encryption_nonce_mismatch',
    });
    expect(facilitator.settlements).toBe(before);
  });

  it('rejects before settlement when the intermediary alters the request body', async () => {
    const before = facilitator.settlements;
    const tamper: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      if (!req.headers.get('PAYMENT-SIGNATURE')) return fetch(req);
      return fetch(new Request(req, { body: '{"quarter":"Q4"}' }));
    };
    const f = wrapFetchWithEncryptedPayment(tamper, { signer: payer });
    await expect(f(proxyUrl + '/v1/report', { method: 'POST', body: '{"quarter":"Q3"}' })).rejects.toMatchObject({
      reason: 'response_encryption_nonce_mismatch',
    });
    expect(facilitator.settlements).toBe(before);
  });

  it('refuses to pay when the 402 key is swapped', async () => {
    const before = facilitator.settlements;
    const tamper: typeof fetch = async (input, init) => {
      const res = await fetch(input, init);
      if (res.status !== 402) return res;
      const pr = JSON.parse(Buffer.from(res.headers.get('PAYMENT-REQUIRED')!, 'base64').toString());
      const attacker = sellerKeyFromPrivate(testKey('attacker'));
      pr.extensions['response-encryption'].info.publicKey = hex(attacker.publicKey);
      pr.extensions['response-encryption'].info.keyId = hex(keyIdOf(attacker.publicKey));
      const headers = new Headers(res.headers);
      headers.set('PAYMENT-REQUIRED', Buffer.from(JSON.stringify(pr)).toString('base64'));
      return new Response(JSON.stringify(pr), { status: 402, headers });
    };
    const f = wrapFetchWithEncryptedPayment(tamper, { signer: payer });
    await expect(f(proxyUrl + '/v1/report', { method: 'POST', body: '{}' })).rejects.toMatchObject({
      reason: 'response_encryption_attestation_invalid',
    });
    expect(facilitator.settlements).toBe(before);
  });

  it('resends the stored envelope when the paid response is lost', async () => {
    const before = facilitator.settlements;
    let drops = 1;
    const flaky: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      const res = await fetch(req);
      if (req.headers.get('PAYMENT-SIGNATURE') && drops-- > 0) {
        await res.arrayBuffer();
        throw new TypeError('connection reset');
      }
      return res;
    };
    const res = await wrapFetchWithEncryptedPayment(flaky, { signer: payer })(proxyUrl + '/v1/report', { method: 'POST', body: '{}' });
    expect(await res.json()).toEqual(JSON.parse(SECRET));
    expect(drops).toBe(-1);
    expect(facilitator.settlements).toBe(before + 1);
  });

  it('retries once with the new key after a rotation', async () => {
    const old = keys[0]!;
    const fresh = await keyConfig('enc-2');
    let rotated = false;
    const reasons: string[] = [];
    // Rotate after the client has read the 402 but before the paid request arrives.
    const rotating: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      if (req.headers.get('PAYMENT-SIGNATURE') && !rotated) {
        rotated = true;
        setKeys([fresh]); // grace period over: old key dropped
      }
      const res = await fetch(req);
      if (res.status === 402 && req.headers.get('PAYMENT-SIGNATURE')) {
        const pr = JSON.parse(Buffer.from(res.headers.get('PAYMENT-REQUIRED')!, 'base64').toString());
        reasons.push(pr.extensions['response-encryption'].info.errorReason);
      }
      return res;
    };
    try {
      const res = await wrapFetchWithEncryptedPayment(rotating, { signer: payer })(proxyUrl + '/v1/report', { method: 'POST', body: '{}' });
      expect(await res.json()).toEqual(JSON.parse(SECRET));
      expect(reasons).toEqual(['response_encryption_unknown_key_id']);
    } finally {
      setKeys([old]);
    }
  });

  it('does not treat a failed settlement as a paid response', async () => {
    const before = facilitator.settlements;
    facilitator.failNextSettle = true;
    const sent: string[] = [];
    const recording: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      const header = req.headers.get('PAYMENT-SIGNATURE');
      if (header) sent.push(header);
      return fetch(req);
    };
    await expect(
      wrapFetchWithEncryptedPayment(recording, { signer: payer })(proxyUrl + '/v1/report', { method: 'POST', body: '{}' }),
    ).rejects.toMatchObject({ reason: 'invalid_exact_evm_transaction_failed' });
    expect(facilitator.settlements).toBe(before);
    // Neither the envelope nor the body was released.
    expect(proxy.log.join('\n')).not.toContain('x402-encrypted+json');
    expect(proxy.log.join('\n')).not.toContain('quarterly numbers');
    // No funds moved, so the same signed payload is still a valid payment: resending it
    // settles once and delivers an envelope, never a stored one from the failed attempt.
    const replay = await fetch(proxyUrl + '/v1/report', { method: 'POST', body: '{}', headers: { 'PAYMENT-SIGNATURE': sent[0]! } });
    expect(replay.headers.get('content-type')).toBe('application/x402-encrypted+json');
    expect(facilitator.settlements).toBe(before + 1);
  });

  it('refuses a plaintext success response', async () => {
    const strip: typeof fetch = async (input, init) => {
      const req = new Request(input, init);
      const res = await fetch(req);
      if (!req.headers.get('PAYMENT-SIGNATURE')) return res;
      return new Response('{"forged":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    };
    await expect(wrapFetchWithEncryptedPayment(strip, { signer: payer })(proxyUrl + '/v1/report', { method: 'POST', body: '{}' })).rejects.toBeInstanceOf(
      EncryptedFetchError,
    );
  });

  it('runs the handler and settles once for concurrent duplicates', async () => {
    const before = facilitator.settlements;
    const header = await signedHeader();
    const [a, b] = await Promise.all([sendPaid(header), sendPaid(header)]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(await a.text()).toBe(await b.text());
    expect(executions).toBe(1);
    expect(facilitator.settlements).toBe(before + 1);
  });

  it('does not hand a stored envelope to a different authorization that reuses the nonce', async () => {
    const header = await signedHeader();
    expect((await sendPaid(header)).status).toBe(200);
    const p = JSON.parse(Buffer.from(header, 'base64').toString());
    const attacker = privateKeyToAccount(hex(testKey('attacker')));
    const auth = { ...p.payload.authorization, from: attacker.address };
    const domain = { name: p.accepted.extra.name, version: p.accepted.extra.version, chainId: CHAIN_ID, verifyingContract: p.accepted.asset };
    p.payload = { authorization: auth, signature: await attacker.signTypedData(transferAuthorizationTypedData(domain, auth)) };
    const res = await sendPaid(Buffer.from(JSON.stringify(p)).toString('base64'));
    expect(res.status).toBe(402);
    expect(res.headers.get('content-type')).not.toContain('x402-encrypted');
    expect(executions).toBe(1);
  });

  it('commits the decoded body of a gzip request on both sides', async () => {
    const res = await clientFetch()(proxyUrl + '/v1/report', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: gzipSync('{"quarter":"Q3"}'),
    });
    expect(await res.json()).toEqual(JSON.parse(SECRET));
  });

  it('delivers a 204 inside a 200 envelope and restores it at the client', async () => {
    const res = await clientFetch()(proxyUrl + '/v1/ack', { method: 'POST', body: '{}' });
    expect(res.status).toBe(204);
    expect(proxy.log.join('\n')).toContain('x402-encrypted+json');
  });

  it('refuses to pay when the 402 names a different resource', async () => {
    const before = facilitator.settlements;
    const tamper: typeof fetch = async (input, init) => {
      const res = await fetch(input, init);
      if (res.status !== 402) return res;
      const pr = JSON.parse(Buffer.from(res.headers.get('PAYMENT-REQUIRED')!, 'base64').toString());
      pr.resource.url = pr.resource.url.replace('/v1/report', '/v1/ack');
      const headers = new Headers(res.headers);
      headers.set('PAYMENT-REQUIRED', Buffer.from(JSON.stringify(pr)).toString('base64'));
      return new Response(JSON.stringify(pr), { status: 402, headers });
    };
    await expect(wrapFetchWithEncryptedPayment(tamper, { signer: payer })(proxyUrl + '/v1/report', { method: 'POST', body: '{}' })).rejects.toMatchObject({
      reason: 'response_encryption_resource_url_mismatch',
    });
    expect(facilitator.settlements).toBe(before);
  });
});
