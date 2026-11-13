// Deployment B with Permit2 terms: the gateway collects through the x402 Permit2 proxy and
// relays to the origin, which checks the Permit2 authorization against its own terms
// (token, spender, value, window, recipient, signer) before it encrypts.
import { createServer, request as httpRequest, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import express from 'express';
import { privateKeyToAccount } from 'viem/accounts';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { permit2TypedData, type Permit2Authorization } from '@x402-response-encryption/core';
import { wrapFetchWithEncryptedPayment } from '@x402-response-encryption/fetch';
import {
  advertisedInfo,
  createOriginEncryption,
  declaration,
  responseEncryptionExtension,
  type AcceptedPayment,
  type SellerKeyConfig,
} from '../src/index.js';
import { CHAIN_ID, LocalFacilitator, NETWORK, SECRET, hex, keyConfig, listen, payTo, payer, testKey } from './helpers.js';

const USDC_PERMIT2: AcceptedPayment = {
  network: NETWORK,
  asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  assetTransferMethod: 'permit2',
  amount: '10000',
};
const RELAY_SECRET = 'test-relay-secret';
const BODY = '{"quarter":"Q3"}';

let facilitator: LocalFacilitator;
let origin: Server;
let gateway: Server;
let gatewayUrl: string;
let originUrl: string;
let key: SellerKeyConfig;
const relayed: string[] = [];
let clock = 0;
let executions = 0;
/** Holds the next handler run open until a test resolves it. */
let handlerGate: Promise<void> | undefined;
let handlerEntered: (() => void) | undefined;

beforeAll(async () => {
  key = await keyConfig('enc-gw-permit2');

  // Origin: Permit2 terms carry no token domain; Permit2 signs under its own domain.
  const app = express();
  app.post(
    '/internal/report',
    createOriginEncryption({
      keys: [key],
      accepts: [USDC_PERMIT2],
      fromGateway: (req) => req.header('x-relay-secret') === RELAY_SECRET,
      now: () => clock || Math.floor(Date.now() / 1000),
      resourceUrl: () => gatewayUrl + '/v1/report',
    }),
    async (_req, res) => {
      executions++;
      if (handlerGate) {
        const gate = handlerGate;
        handlerGate = undefined;
        handlerEntered?.();
        await gate;
      }
      res.json(JSON.parse(SECRET));
    },
  );
  origin = createServer(app);
  originUrl = await listen(origin);

  facilitator = new LocalFacilitator();
  const resourceServer = new x402ResourceServer(facilitator)
    .register(NETWORK, new ExactEvmScheme())
    .registerExtension(responseEncryptionExtension(advertisedInfo(key)));
  const gw = express();
  gw.use(
    paymentMiddleware(
      {
        'POST /v1/report': {
          accepts: { scheme: 'exact', price: '$0.01', network: NETWORK, payTo: payTo.address, extra: { assetTransferMethod: 'permit2' } },
          description: 'Quarterly report, paid through Permit2',
          extensions: declaration,
        },
      },
      resourceServer,
    ),
  );
  gw.post('/v1/report', express.raw({ type: '*/*' }), async (req, res) => {
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    relayed.push(body.toString());
    const headers: Record<string, string> = { 'x-relay-secret': RELAY_SECRET };
    if (req.header('content-type')) headers['content-type'] = req.header('content-type')!;
    if (req.header('payment-signature')) headers['payment-signature'] = req.header('payment-signature')!;
    const up = await fetch(originUrl + '/internal/report', { method: 'POST', headers, body });
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
  clock = 0;
  executions = 0;
});

const pay = (f: typeof fetch = fetch) =>
  wrapFetchWithEncryptedPayment(f, { signer: payer, pinnedPayTo: payTo.address })(gatewayUrl + '/v1/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: BODY,
  });

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

/** Re-signs the captured Permit2 authorization with other fields, keeping its nonce (the commitment). */
async function resign(
  header: string,
  change: { auth?: Partial<Permit2Authorization>; signer?: typeof payer },
): Promise<string> {
  const p = decode(header);
  const signer = change.signer ?? payer;
  const auth: Permit2Authorization = { ...p.payload.permit2Authorization, from: signer.address, ...change.auth };
  p.payload = { permit2Authorization: auth, signature: await signer.signTypedData(permit2TypedData(CHAIN_ID, auth)) };
  return encode(p);
}

const toOrigin = (header: string) =>
  fetch(originUrl + '/internal/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'payment-signature': header, 'x-relay-secret': RELAY_SECRET },
    body: BODY,
  });

describe('Permit2 payment through a relaying gateway', () => {
  it('settles at the gateway, decrypts at the client, and keeps plaintext from the gateway', async () => {
    const before = facilitator.settlements;
    const res = await pay();
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(SECRET);
    expect(facilitator.settlements).toBe(before + 1);
    expect(executions).toBe(1);
    expect(relayed.join('\n')).not.toContain('quarterly numbers');
  });

  it('accepts the unmodified signed payment at the origin', async () => {
    const res = await toOrigin(await signedHeader());
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/x402-encrypted+json');
  });
});

describe('origin checks Permit2 authorizations against its own terms', () => {
  const now = () => Math.floor(Date.now() / 1000);
  const attacker = privateKeyToAccount(hex(testKey('gateway-own-payTo')));
  it.each<[string, () => Partial<Permit2Authorization>]>([
    ['a token the origin does not accept', () => ({ permitted: { token: '0x000000000000000000000000000000000000dEaD', amount: '10000' } })],
    ['an amount below the price', () => ({ permitted: { token: USDC_PERMIT2.asset, amount: '9999' } })],
    ['a spender other than the x402 Permit2 proxy', () => ({ spender: attacker.address })],
    ['a recipient other than the attested payTo', () => ({ witness: { to: attacker.address, validAfter: '0' } })],
    ['an authorization not yet valid', () => ({ witness: { to: payTo.address, validAfter: String(now() + 3600) } })],
    ['an expired deadline', () => ({ deadline: String(now() - 1) })],
  ])('refuses %s without running the handler', async (_name, change) => {
    const res = await toOrigin(await resign(await signedHeader(), { auth: change() }));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
    expect(executions).toBe(0);
  });

  it('refuses a signature that does not recover the payer', async () => {
    const p = decode(await signedHeader());
    const forged = decode(await resign(encode(p), { signer: attacker }));
    forged.payload.permit2Authorization.from = payer.address;
    const res = await toOrigin(encode(forged));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
    expect(executions).toBe(0);
  });

  it('refuses an EIP-3009 payment when only Permit2 terms are configured', async () => {
    const p = decode(await signedHeader());
    const a = p.payload.permit2Authorization as Permit2Authorization;
    p.payload = {
      authorization: {
        from: a.from,
        to: payTo.address,
        value: a.permitted.amount,
        validAfter: '0',
        validBefore: a.deadline,
        nonce: '0x' + BigInt(a.nonce).toString(16).padStart(64, '0'),
      },
      signature: p.payload.signature,
    };
    const res = await toOrigin(encode(p));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
    expect(executions).toBe(0);
  });
});

describe('origin retries with Permit2', () => {
  it('returns the stored envelope after the deadline, but refuses a new execution', async () => {
    const header = await signedHeader();
    const first = await toOrigin(header);
    expect(first.status).toBe(200);
    const body = await first.text();
    clock = Number(decode(header).payload.permit2Authorization.deadline) + 3600;
    const retry = await toOrigin(header);
    expect(retry.status).toBe(200);
    expect(await retry.text()).toBe(body);
    expect((await toOrigin(await signedHeader())).status).toBe(402);
    expect(executions).toBe(1);
  });

  it('does not hand a stored envelope to another owner signing the identical Permit2 message', async () => {
    const header = await signedHeader();
    expect((await toOrigin(header)).status).toBe(200);
    const attacker = privateKeyToAccount(hex(testKey('attacker')));
    const res = await toOrigin(await resign(header, { signer: attacker }));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
    expect(executions).toBe(1);
    const retry = await toOrigin(header);
    expect(retry.status).toBe(200);
  });

  it('does not hand a stored envelope to a different authorization that reuses the nonce', async () => {
    const header = await signedHeader();
    expect((await toOrigin(header)).status).toBe(200);
    const res = await toOrigin(await resign(header, { auth: { deadline: String(Math.floor(Date.now() / 1000) + 7200) } }));
    expect(res.status).toBe(402);
    expect((await res.json()).errorReason).toBe('invalid_payment_authorization');
    expect(executions).toBe(1);
  });

  it('does not let a request that lost its connection overwrite the envelope a retry stored', async () => {
    const header = await signedHeader();
    let open!: () => void;
    handlerGate = new Promise<void>((r) => (open = r));
    const entered = new Promise<void>((r) => (handlerEntered = r));
    const first = httpRequest(originUrl + '/internal/report', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'payment-signature': header, 'x-relay-secret': RELAY_SECRET, 'content-length': String(BODY.length) },
    });
    first.on('error', () => undefined);
    first.end(BODY);
    await entered;
    handlerEntered = undefined;
    const closed = new Promise((r) => first.socket!.once('close', r));
    first.destroy();
    await closed;
    await new Promise((r) => setTimeout(r, 50));
    // The gateway resends; it runs and stores its envelope.
    const retry = await toOrigin(header);
    expect(retry.status).toBe(200);
    const stored = await retry.text();
    // The first handler finishes late; it must not replace the stored envelope.
    open();
    await new Promise((r) => setTimeout(r, 50));
    const again = await toOrigin(header);
    expect(again.status).toBe(200);
    expect(await again.text()).toBe(stored);
  });

  it('releases the lock for a request that disconnected while it waited for it', async () => {
    const header = await signedHeader();
    const send = () => {
      const r = httpRequest(originUrl + '/internal/report', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'payment-signature': header, 'x-relay-secret': RELAY_SECRET, 'content-length': String(BODY.length) },
      });
      r.on('error', () => undefined);
      r.end(BODY);
      return r;
    };
    const drop = async (r: ReturnType<typeof httpRequest>) => {
      const closed = new Promise((ok) => r.socket!.once('close', ok));
      r.destroy();
      await closed;
      await new Promise((ok) => setTimeout(ok, 50));
    };
    let open!: () => void;
    handlerGate = new Promise<void>((r) => (open = r));
    const entered = new Promise<void>((r) => (handlerEntered = r));
    const holder = send();
    await entered;
    handlerEntered = undefined;
    const queued = send();
    await new Promise((ok) => setTimeout(ok, 50));
    await drop(queued);
    // The holder disconnects too, so the lock passes to the queued request, whose connection is already gone.
    await drop(holder);
    open();
    const next = await Promise.race([toOrigin(header).then((r) => r.status), new Promise<'blocked'>((r) => setTimeout(() => r('blocked'), 2000))]);
    expect(next).toBe(200);
  });
});
