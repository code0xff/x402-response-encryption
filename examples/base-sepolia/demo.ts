// One paid, encrypted request on Base Sepolia through a logging reverse proxy.
// Settlement runs through an in-process facilitator built from the x402 SDK
// (gas paid by GAS_PRIVATE_KEY, default the payTo key), or through a hosted one
// when FACILITATOR_URL is set. Keys come from ../../.env.
// `--permit2` pays through Permit2 instead of EIP-3009 (proposal 3.5); the client then
// approves the Permit2 contract once, paying its own gas.
//
//   client (fetch wrapper) -> logging proxy -> Express seller (@x402/express) -> facilitator
import { readFileSync } from 'node:fs';
import { createServer, request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { HTTPFacilitatorClient, type FacilitatorClient } from '@x402/core/server';
import { x402Facilitator } from '@x402/core/facilitator';
import { ExactEvmScheme as ExactEvmFacilitator } from '@x402/evm/exact/facilitator';
import { toFacilitatorEvmSigner } from '@x402/evm';
import { decodePaymentResponseHeader } from '@x402/core/http';
import type { SupportedResponse } from '@x402/core/types';
import { createPublicClient, createWalletClient, erc20Abi, formatEther, formatUnits, http, maxUint256, publicActions, type Address, type Hex } from 'viem';
import { baseSepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { PERMIT2_ADDRESS, attestationTypedData, fromHex, sellerKeyFromPrivate } from '@x402-response-encryption/core';
import { createResponseEncryption } from '@x402-response-encryption/express';
import { wrapFetchWithEncryptedPayment } from '@x402-response-encryption/fetch';

const env: Record<string, string | undefined> = Object.fromEntries(
  readFileSync(new URL('../../.env', import.meta.url), 'utf8')
    .split('\n')
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.split('=')),
);
const secret = (name: string): Hex => {
  const value = env[name];
  if (!value) throw new Error(`${name} is missing from .env`);
  return value as Hex;
};
const NETWORK = 'eip155:84532';
const USDC: Address = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const FACILITATOR_URL = process.env.FACILITATOR_URL;
const METHOD = process.argv.includes('--permit2') ? 'permit2' : 'eip3009';
const SECRET = { report: 'Q3 revenue by region', apac: 412000, emea: 388000, amer: 951000 };

const client = privateKeyToAccount(secret('CLIENT_PRIVATE_KEY'));
const payTo = privateKeyToAccount(secret('PAYTO_PRIVATE_KEY'));
const chain = createPublicClient({ chain: baseSepolia, transport: http() });
const balance = async (a: Address) => formatUnits(await chain.readContract({ address: USDC, abi: erc20Abi, functionName: 'balanceOf', args: [a] }), 6);

// Seller encryption key, attested once by payTo (proposal 4.1).
const encKey = fromHex(secret('SELLER_ENCRYPTION_PRIVATE_KEY'));
const { publicKey, keyId } = sellerKeyFromPrivate(encKey);
const now = Math.floor(Date.now() / 1000);
const validity = { notBefore: now - 60, notAfter: now + 90 * 24 * 3600 };
const signature = await payTo.signTypedData(attestationTypedData({ chainId: 84532, payTo: payTo.address, keyId, publicKey, ...validity }));

const enc = createResponseEncryption({
  keys: [{ privateKey: encKey, attestation: { payTo: payTo.address, ...validity, signature } }],
});

function localFacilitator() {
  const gas = privateKeyToAccount(env.GAS_PRIVATE_KEY ? secret('GAS_PRIVATE_KEY') : secret('PAYTO_PRIVATE_KEY'));
  const wallet = createWalletClient({ account: gas, chain: baseSepolia, transport: http() }).extend(publicActions);
  // A viem wallet client works as the facilitator signer at runtime, but its simulateCalls
  // signature is stricter than the SDK's interface (x402 2.29.0, viem 2.57.8).
  const signer = Object.assign(wallet, { address: gas.address }) as unknown as Parameters<typeof toFacilitatorEvmSigner>[0];
  const facilitator = new x402Facilitator().register(NETWORK, new ExactEvmFacilitator(toFacilitatorEvmSigner(signer)));
  const facilitatorClient: FacilitatorClient = {
    verify: (p, r) => facilitator.verify(p, r),
    settle: (p, r) => facilitator.settle(p, r),
    // The facilitator reports networks as plain strings; FacilitatorClient wants CAIP-2 literals.
    getSupported: async () => facilitator.getSupported() as SupportedResponse,
  };
  return { gas, facilitatorClient };
}
const local = FACILITATOR_URL ? undefined : localFacilitator();
const resourceServer = new x402ResourceServer(local ? local.facilitatorClient : new HTTPFacilitatorClient({ url: FACILITATOR_URL }))
  .register(NETWORK, new ExactEvmScheme())
  .registerExtension(enc.extension);

const app = express();
app.use(enc.before);
app.use(
  paymentMiddleware(
    {
      'POST /v1/report': {
        accepts: {
          scheme: 'exact',
          price: '$0.01',
          network: NETWORK,
          payTo: payTo.address,
          ...(METHOD === 'permit2' && { extra: { assetTransferMethod: 'permit2' } }),
        },
        description: 'Quarterly regional revenue',
        extensions: enc.declaration,
      },
    },
    resourceServer,
  ),
);
app.use(enc.after);
app.post('/v1/report', (_req, res) => res.json(SECRET));

const listen = (server: Server) =>
  new Promise<string>((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
const seller = createServer(app);
const sellerUrl = await listen(seller);

// Intermediary that records every body it relays, like a CDN or proxy access log.
const proxyLog: string[] = [];
const proxy = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on('data', (c: Buffer) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    proxyLog.push(`> ${req.method} ${req.url} ${body}`);
    const up = httpRequest(sellerUrl + req.url, { method: req.method, headers: req.headers }, (upRes) => {
      const out: Buffer[] = [];
      upRes.on('data', (c: Buffer) => out.push(c));
      upRes.on('end', () => {
        const resBody = Buffer.concat(out);
        proxyLog.push(`< ${upRes.statusCode} ${upRes.headers['content-type']} ${resBody}`);
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        res.end(resBody);
      });
    });
    up.end(body);
  });
});
const proxyUrl = await listen(proxy);

console.log(local ? `facilitator in-process, gas ${local.gas.address} ETH ${formatEther(await chain.getBalance({ address: local.gas.address }))}` : `facilitator ${FACILITATOR_URL}`);
if (local && (await chain.getBalance({ address: local.gas.address })) === 0n) {
  console.error(`\nThe in-process facilitator pays settlement gas from ${local.gas.address}; fund it with Base Sepolia ETH.`);
  seller.close();
  proxy.close();
  process.exit(1);
}
console.log(`client ${client.address}  USDC ${await balance(client.address)}`);
console.log(`payTo  ${payTo.address}  USDC ${await balance(payTo.address)}`);
console.log(`asset transfer method: ${METHOD}\n`);

if (METHOD === 'permit2') {
  const allowance = await chain.readContract({ address: USDC, abi: erc20Abi, functionName: 'allowance', args: [client.address, PERMIT2_ADDRESS] });
  if (allowance < 10_000n) {
    // One-time approval of the canonical Permit2 contract (x402 scheme_exact_evm.md, Permit2 prerequisites).
    const wallet = createWalletClient({ account: client, chain: baseSepolia, transport: http() });
    const hash = await wallet.writeContract({ address: USDC, abi: erc20Abi, functionName: 'approve', args: [PERMIT2_ADDRESS, maxUint256] });
    await chain.waitForTransactionReceipt({ hash });
    console.log(`client approved Permit2: ${hash}\n`);
  }
}

try {
  const paidFetch = wrapFetchWithEncryptedPayment(fetch, { signer: client });
  const res = await paidFetch(`${proxyUrl}/v1/report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ quarter: 'Q3' }),
  });
  const plaintext = await res.text();
  const settlement = decodePaymentResponseHeader(res.headers.get('payment-response') ?? '');
  const tx = settlement.transaction as Hex;

  console.log('client decrypted:', plaintext);
  console.log('settlement tx:   ', tx, `https://sepolia.basescan.org/tx/${tx}`);
  console.log('\nintermediary log:');
  for (const line of proxyLog) console.log('  ' + (line.length > 220 ? line.slice(0, 220) + '…' : line));
  const leaked = proxyLog.some((l) => l.includes('Q3 revenue by region'));
  console.log(`\nplaintext in intermediary log: ${leaked ? 'YES (failure)' : 'no'}`);

  await chain.waitForTransactionReceipt({ hash: tx });
  console.log(`\nclient USDC ${await balance(client.address)}`);
  console.log(`payTo  USDC ${await balance(payTo.address)}`);
  if (leaked || plaintext !== JSON.stringify(SECRET)) process.exitCode = 1;
} finally {
  seller.close();
  proxy.close();
}
