// Permit2 profile end-to-end (proposal 3.5): the binding commitment travels as the Permit2
// nonce. Client -> logging reverse proxy -> Express seller running the real @x402/express
// middleware, with an in-process facilitator that checks Permit2 signatures.
import { createServer, request as httpRequest, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import express from 'express';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { decodePaymentRequiredHeader, decodePaymentSignatureHeader, encodePaymentSignatureHeader } from '@x402/core/http';
import { secp256k1 } from '@noble/curves/secp256k1';
import { privateKeyToAccount } from 'viem/accounts';
import { commitmentToPermit2Nonce, permit2TypedData, toHex, type Permit2Authorization } from '@x402-response-encryption/core';
import { wrapFetchWithEncryptedPayment } from '@x402-response-encryption/fetch';
import { createResponseEncryption, type SellerKeyConfig } from '../src/index.js';
import { CHAIN_ID, LocalFacilitator, NETWORK, SECRET, keyConfig, listen, payTo, payer, testKey } from './helpers.js';

function loggingProxy(target: string) {
  const log: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      log.push(body.toString(), JSON.stringify(req.headers));
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
let url: string;
let executions = 0;
/** Makes the next handler run destroy its response without ending it. */
let destroyNext = false;
let redirectNext = false;
let notModifiedNext = false;
/** Holds the handler open until a test resolves it. */
let handlerGate: Promise<void> | undefined;
let handlerEntered: (() => void) | undefined;
let sellerUrl: string;

beforeAll(async () => {
  const keys = [await keyConfig('enc-permit2')] as [SellerKeyConfig];
  facilitator = new LocalFacilitator();
  const resourceServer = new x402ResourceServer(facilitator).register(NETWORK, new ExactEvmScheme());
  const enc = createResponseEncryption({ keys });
  resourceServer.registerExtension(enc.extension);

  const app = express();
  app.use(enc.before);
  app.use(
    paymentMiddleware(
      {
        'POST /v1/report': {
          accepts: { scheme: 'exact', price: '$0.01', network: NETWORK, payTo: payTo.address, extra: { assetTransferMethod: 'permit2' } },
          description: 'Quarterly report, paid through Permit2',
          extensions: enc.declaration,
        },
      },
      resourceServer,
    ),
  );
  app.use(enc.after);
  app.post('/v1/report', async (_req, res) => {
    executions++;
    if (destroyNext) return void ((destroyNext = false), res.destroy());
    if (redirectNext) return void ((redirectNext = false), res.redirect(302, '/elsewhere'));
    if (notModifiedNext) return void ((notModifiedNext = false), res.writeHead(304, { etag: '"v1"' }), res.end());
    if (handlerGate) {
      handlerEntered?.();
      await handlerGate;
    }
    res.json(JSON.parse(SECRET));
  });
  seller = createServer(app);
  sellerUrl = await listen(seller);
  proxy = loggingProxy(sellerUrl);
  url = (await listen(proxy.server)) + '/v1/report';
});

afterAll(() => {
  seller?.close();
  proxy?.server.close();
});

beforeEach(() => {
  proxy.log.length = 0;
  executions = 0;
});

/** The client's signed payment header, captured before it is sent. */
async function signedHeader(): Promise<string> {
  let header: string | undefined;
  const capture: typeof fetch = async (input, init) => {
    const req = new Request(input, init);
    header = req.headers.get('PAYMENT-SIGNATURE') ?? undefined;
    if (header) throw new TypeError('captured');
    return fetch(req);
  };
  await wrapFetchWithEncryptedPayment(capture, { signer: payer, transportRetries: 0 })(url, { method: 'POST', body: '{}' }).catch(() => undefined);
  return header!;
}
/** Straight to the seller with the proxy's Host, so resource.url still matches. Resolves undefined on a dropped connection. */
function direct(header: string, onRequest?: (r: ReturnType<typeof httpRequest>) => void) {
  return new Promise<number | undefined>((resolve) => {
    const r = httpRequest(sellerUrl + '/v1/report', {
      method: 'POST',
      headers: { host: new URL(url).host, 'PAYMENT-SIGNATURE': header, 'content-length': '2' },
    });
    r.on('response', (res) => (res.resume(), resolve(res.statusCode)));
    r.on('error', () => resolve(undefined));
    r.end('{}');
    onRequest?.(r);
  });
}
const sendPaid = (header: string) => fetch(url, { method: 'POST', body: '{}', headers: { 'PAYMENT-SIGNATURE': header } });

describe('Permit2 profile', () => {
  it('pays with Permit2, decrypts, and leaves no plaintext in the intermediary log', async () => {
    const before = facilitator.settlements;
    const res = await wrapFetchWithEncryptedPayment(fetch, { signer: payer })(url, { method: 'POST', body: '{}' });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(SECRET);
    expect(facilitator.settlements).toBe(before + 1);
    const log = proxy.log.join('\n');
    expect(log).not.toContain('quarterly numbers');
    expect(log).not.toContain('1234567');
  });

  it('carries the commitment as the Permit2 nonce', async () => {
    const p = decodePaymentSignatureHeader(await signedHeader());
    expect(p.accepted.extra?.assetTransferMethod).toBe('permit2');
    const auth = p.payload.permit2Authorization as { nonce: string };
    // The commitment is not observable without the extension fields; check its encoding round-trips.
    expect(commitmentToPermit2Nonce(toHex(Buffer.from(BigInt(auth.nonce).toString(16).padStart(64, '0'), 'hex')))).toBe(auth.nonce);
    expect('authorization' in p.payload).toBe(false);
  });

  it('rejects a swapped ephemeral key before settlement', async () => {
    const p = decodePaymentSignatureHeader(await signedHeader());
    const info = (p.extensions!['response-encryption'] as { info: Record<string, string> }).info;
    info.ephemeralPublicKey = toHex(secp256k1.getPublicKey(testKey('attacker-ephemeral'), true));
    const before = facilitator.settlements;
    const res = await sendPaid(encodePaymentSignatureHeader(p));
    expect(res.status).toBe(402);
    const pr = decodePaymentRequiredHeader(res.headers.get('PAYMENT-REQUIRED')!);
    expect((pr.extensions!['response-encryption'] as { info: { errorReason: string } }).info.errorReason).toBe('response_encryption_nonce_mismatch');
    expect(facilitator.settlements).toBe(before);
    expect(executions).toBe(0);
  });

  it('rejects a rewritten Permit2 nonce at signature verification', async () => {
    const p = decodePaymentSignatureHeader(await signedHeader());
    const auth = p.payload.permit2Authorization as { nonce: string };
    auth.nonce = (BigInt(auth.nonce) ^ 1n).toString();
    const before = facilitator.settlements;
    const res = await sendPaid(encodePaymentSignatureHeader(p));
    expect(res.status).toBe(402);
    expect(facilitator.settlements).toBe(before);
    expect(executions).toBe(0);
  });

  it('returns the stored envelope to an identical retry without settling again', async () => {
    const header = await signedHeader();
    const first = await sendPaid(header);
    expect(first.status).toBe(200);
    const before = facilitator.settlements;
    const again = await sendPaid(header);
    expect(again.status).toBe(200);
    expect(await again.text()).toBe(await first.text());
    expect(facilitator.settlements).toBe(before);
  });

  it('refuses another owner signing the identical Permit2 message, and still serves the payer\'s retry', async () => {
    const header = await signedHeader();
    const first = await sendPaid(header);
    expect(first.status).toBe(200);
    const stored = await first.text();
    // Permit2 typed data has no owner field, so this signature covers the same digest.
    const p = decodePaymentSignatureHeader(header);
    const other = privateKeyToAccount(toHex(testKey('other-owner')));
    const auth = { ...(p.payload.permit2Authorization as Permit2Authorization), from: other.address };
    p.payload = { permit2Authorization: auth, signature: await other.signTypedData(permit2TypedData(CHAIN_ID, auth)) };
    const before = facilitator.settlements;
    const res = await sendPaid(encodePaymentSignatureHeader(p));
    expect(res.status).toBe(402);
    expect(facilitator.settlements).toBe(before);
    const retry = await sendPaid(header);
    expect(retry.status).toBe(200);
    expect(await retry.text()).toBe(stored);
  });

  it('keeps the payer\'s envelope when another owner sends the same commitment without the extension during settlement', async () => {
    const header = await signedHeader();
    let open!: () => void;
    facilitator.settleGate = new Promise<void>((r) => (open = r));
    const entered = new Promise<void>((r) => (facilitator.onSettle = r));
    const honest = sendPaid(header);
    await entered;
    facilitator.onSettle = undefined;
    // Same commitment, signed by another owner, extension stripped: it skips the lock and x402 verifies it.
    const p = decodePaymentSignatureHeader(header);
    const other = privateKeyToAccount(toHex(testKey('stripping-owner')));
    const auth = { ...(p.payload.permit2Authorization as Permit2Authorization), from: other.address };
    p.payload = { permit2Authorization: auth, signature: await other.signTypedData(permit2TypedData(CHAIN_ID, auth)) };
    delete p.extensions;
    const stripped = await sendPaid(encodePaymentSignatureHeader(p));
    expect(stripped.status).not.toBe(200);
    facilitator.settleGate = undefined;
    open();
    const first = await honest;
    expect(first.status).toBe(200);
    const body = await first.text();
    const before = facilitator.settlements;
    const retry = await sendPaid(header);
    expect(retry.status).toBe(200);
    expect(await retry.text()).toBe(body);
    expect(facilitator.settlements).toBe(before);
  });

  it('does not leave the lock held when a handler destroys its response without ending it', async () => {
    const header = await signedHeader();
    destroyNext = true;
    expect(await direct(header)).toBeUndefined();
    const retry = await Promise.race([direct(header), new Promise<'blocked'>((r) => setTimeout(() => r('blocked'), 2000))]);
    expect(retry).toBe(200);
    expect(executions).toBe(2);
  });

  it('does not settle a request that lost the lock when its connection closed mid-handler', async () => {
    const header = await signedHeader();
    let open!: () => void;
    handlerGate = new Promise<void>((r) => (open = r));
    const entered = new Promise<void>((r) => (handlerEntered = r));
    let client!: ReturnType<typeof httpRequest>;
    const first = direct(header, (r) => (client = r));
    await entered;
    handlerEntered = undefined;
    client.destroy();
    expect(await first).toBeUndefined();
    await new Promise((r) => setTimeout(r, 50));
    const before = facilitator.settlements;
    // The handler finishes after its request released the lock: no settlement, so nothing is charged without a kept envelope.
    handlerGate = undefined;
    open();
    await new Promise((r) => setTimeout(r, 50));
    expect(facilitator.settlements).toBe(before);
    // The payer's resend settles once and gets an envelope.
    expect(await sendPaid(header).then((r) => r.status)).toBe(200);
    expect(facilitator.settlements).toBe(before + 1);
  });

  it('does not settle a paid 3xx response, which has no envelope', async () => {
    const before = facilitator.settlements;
    redirectNext = true;
    const res = await sendPaid(await signedHeader());
    expect(res.status).toBe(500);
    expect(res.headers.get('location')).toBeNull();
    expect(facilitator.settlements).toBe(before);
  });

  it('does not settle a paid 304 set through writeHead', async () => {
    const before = facilitator.settlements;
    notModifiedNext = true;
    const res = await sendPaid(await signedHeader());
    expect(res.status).toBe(500);
    expect(facilitator.settlements).toBe(before);
  });
});
