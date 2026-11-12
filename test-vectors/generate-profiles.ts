// Generates the Permit2 and SVM profile vectors (proposal 3.5).
// The binding commitment c is the same value as the nonce in vector-1.json: it does not
// depend on the payment scheme. Only where c is carried, the digest used as HKDF salt and
// the signature check change between profiles.
import { createCipheriv, createHash, createPrivateKey, createPublicKey, hkdfSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { hashTypedData, recoverTypedDataAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { canonicalUrl } from './canonical-url.js';

const enc = new TextEncoder();
const hex = (u8: Uint8Array): `0x${string}` => `0x${Buffer.from(u8).toString('hex')}`;
const unhex = (h: string) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));
const cat = (...parts: (Uint8Array | number[])[]) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
const u16 = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const lp = (s: string) => { const b = enc.encode(s); return cat(u32(b.length), b); };
const sha256 = (b: Uint8Array) => Uint8Array.from(createHash('sha256').update(b).digest());
const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const fixed = (label: string) => sha256(enc.encode('x402-response-encryption/test-vector/' + label));

const TAG = {
  nonce: enc.encode('x402-response-encryption/v1/nonce'),
  request: enc.encode('x402-response-encryption/v1/request'),
  keyId: enc.encode('x402-response-encryption/v1/key-id'),
  response: enc.encode('x402-response-encryption/v1/response'),
  aad: enc.encode('x402-response-encryption/v1/aad'),
};

// ---- inputs shared with vector-1 ----
const e = fixed('client-ephemeral');
const m = fixed('seller-encryption');
const r = fixed('nonce-salt');
const iv = fixed('iv').slice(0, 12);
const E = secp256k1.getPublicKey(e, true);
const M = secp256k1.getPublicKey(m, true);
const keyId = keccak_256(cat(TAG.keyId, M));
const request = {
  method: 'POST',
  url: 'https://api.seller.example/v1/report?id=42',
  body: '{"query":"weather","city":"Seoul"}',
};
const response = {
  status: 200,
  contentType: 'application/json',
  body: '{"city":"Seoul","tempC":12.5,"condition":"clear"}',
};
type Req = typeof request;
const requestHashOf = (req: Req) =>
  sha256(cat(TAG.request, lp(req.method), lp(canonicalUrl(req.url)), sha256(enc.encode(req.body))));
const commitment = (eph: Uint8Array, kid: Uint8Array, req: Req, salt: Uint8Array) =>
  keccak_256(cat(TAG.nonce, eph, kid, requestHashOf(req), salt));
const requestHash = requestHashOf(request);
const c = commitment(E, keyId, request, r);

const attackerE = secp256k1.getPublicKey(fixed('attacker-ephemeral'), true);

function envelopeFor(network: string, authorizationDigest: Uint8Array) {
  const Z = secp256k1.getSharedSecret(e, M, true).slice(1);
  const Zs = secp256k1.getSharedSecret(m, E, true).slice(1);
  if (!Buffer.from(Z).equals(Buffer.from(Zs))) throw new Error('ECDH mismatch');
  const info = cat(TAG.response, E, M, keyId, lp(network), requestHash);
  const K = new Uint8Array(hkdfSync('sha256', Z, authorizationDigest, info, 32));
  const aad = cat(TAG.aad, [1], keyId, u16(response.status), lp(response.contentType));
  const cipher = createCipheriv('aes-256-gcm', K, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(enc.encode(response.body)), cipher.final(), cipher.getAuthTag()]);
  return {
    intermediate: { sharedSecretZ: hex(Z), hkdfInfo: hex(info), aesKey: hex(K), aad: hex(aad) },
    envelope: { version: 1, keyId: hex(keyId), status: response.status, contentType: response.contentType, iv: b64url(iv), ciphertext: b64url(ct) },
  };
}

const extensionInfo = (eph: Uint8Array = E) => ({ version: 1, keyId: hex(keyId), ephemeralPublicKey: hex(eph), nonceSalt: hex(r) });
const shared = {
  clientEphemeralPrivateKey: hex(e),
  sellerEncryptionPrivateKey: hex(m),
  nonceSalt: hex(r),
  iv: hex(iv),
  request,
  response,
};
const sharedIntermediate = {
  clientEphemeralPublicKey: hex(E),
  sellerEncryptionPublicKey: hex(M),
  keyId: hex(keyId),
  requestHash: hex(requestHash),
  commitment: hex(c),
};
// `reason` is the first check of the profile that rejects the case, run after the client
// signature check. `facilitatorFirst` names an earlier rejection by the default x402 facilitator.
type Expect = { stage: 'seller'; reason: string; facilitatorFirst?: string } | null;
const reject = (reason: string, facilitatorFirst?: string): Expect =>
  ({ stage: 'seller', reason, ...(facilitatorFirst && { facilitatorFirst }) });

// =====================================================================
// Permit2 (exact on EVM, assetTransferMethod "permit2")
// =====================================================================
const chainId = 84532;
const evmNetwork = `eip155:${chainId}`;
const payer = privateKeyToAccount(hex(fixed('payer-wallet')));
const payTo = privateKeyToAccount(hex(fixed('seller-payTo')));
// Canonical Permit2 and x402ExactPermit2Proxy addresses (x402 scheme_exact_evm.md).
const permit2Domain = { name: 'Permit2', chainId, verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3' as const };
const permit2Types = {
  PermitWitnessTransferFrom: [
    { name: 'permitted', type: 'TokenPermissions' },
    { name: 'spender', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
    { name: 'witness', type: 'Witness' },
  ],
  TokenPermissions: [
    { name: 'token', type: 'address' },
    { name: 'amount', type: 'uint256' },
  ],
  Witness: [
    { name: 'to', type: 'address' },
    { name: 'validAfter', type: 'uint256' },
  ],
} as const;
const permit2Message = (nonce: bigint) => ({
  permitted: { token: '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as const, amount: 10000n },
  spender: '0x402085c248EeA27D92E8b30b2C58ed07f9E20001' as const,
  nonce,
  deadline: 1893456000n,
  witness: { to: payTo.address, validAfter: 0n },
});
const permit2Typed = (nonce: bigint) => ({
  domain: permit2Domain,
  types: permit2Types,
  primaryType: 'PermitWitnessTransferFrom' as const,
  message: permit2Message(nonce),
});
const asUint = (b: Uint8Array) => BigInt(hex(b));
const permit2Wire = (msg: ReturnType<typeof permit2Message>) => ({
  permitted: { token: msg.permitted.token, amount: msg.permitted.amount.toString() },
  from: payer.address,
  spender: msg.spender,
  nonce: msg.nonce.toString(),
  deadline: msg.deadline.toString(),
  witness: { to: msg.witness.to, validAfter: msg.witness.validAfter.toString() },
});

const p2Typed = permit2Typed(asUint(c));
const p2Digest = unhex(hashTypedData(p2Typed));
const p2Signature = await payer.signTypedData(p2Typed);
if ((await recoverTypedDataAddress({ ...p2Typed, signature: p2Signature })) !== payer.address) throw new Error('permit2 recover');
const p2Env = envelopeFor(evmNetwork, p2Digest);

const p2Base = {
  payload: { signature: p2Signature, permit2Authorization: permit2Wire(p2Typed.message) },
  extension: extensionInfo(),
  request,
};
const otherC = commitment(attackerE, keyId, request, r);
const p2SigFor = async (nonce: bigint) => payer.signTypedData(permit2Typed(nonce));
type P2Wire = typeof p2Base;
const p2Cases: [string, string, (w: P2Wire) => void | Promise<void>, Expect][] = [
  ['valid', 'No tampering.', () => {}, null],
  ['nonce-changed', 'Intermediary rewrites permit2Authorization.nonce.',
    (w) => { w.payload.permit2Authorization.nonce = asUint(otherC).toString(); }, reject('invalid_permit2_signature')],
  ['ephemeral-key-swapped', 'Intermediary replaces the ephemeral public key in the extension.',
    (w) => { w.extension.ephemeralPublicKey = hex(attackerE); }, reject('response_encryption_nonce_mismatch')],
  ['ephemeral-key-and-nonce-swapped', 'Intermediary replaces the ephemeral key and rewrites the nonce to match.',
    (w) => { w.extension.ephemeralPublicKey = hex(attackerE); w.payload.permit2Authorization.nonce = asUint(otherC).toString(); },
    reject('invalid_permit2_signature')],
  ['witness-to-changed', 'Intermediary redirects witness.to.',
    (w) => { w.payload.permit2Authorization.witness.to = privateKeyToAccount(hex(fixed('attacker-payTo'))).address; },
    reject('invalid_permit2_signature')],
  ['request-path-changed', 'Intermediary changes the request path.',
    (w) => { w.request = { ...w.request, url: 'https://api.seller.example/v1/admin?id=42' }; }, reject('response_encryption_nonce_mismatch')],
  ['nonce-unrelated-to-commitment', 'Client signs a random Permit2 nonce, as an x402 client without this extension does.',
    async (w) => {
      const n = asUint(fixed('random-permit2-nonce'));
      w.payload.permit2Authorization.nonce = n.toString();
      w.payload.signature = await p2SigFor(n);
    }, reject('response_encryption_nonce_mismatch')],
];

const permit2Vector = {
  description: 'x402 response-encryption v1, Permit2 profile (proposal 3.5). All private keys are test-only.',
  profile: 'permit2',
  inputs: {
    ...shared,
    payerPrivateKey: hex(fixed('payer-wallet')),
    network: evmNetwork,
    permit2Domain,
    payTo: payTo.address,
  },
  intermediate: {
    ...sharedIntermediate,
    payerAddress: payer.address,
    permit2Nonce: asUint(c).toString(),
    authorizationDigest: hex(p2Digest),
    ...p2Env.intermediate,
  },
  output: { envelope: p2Env.envelope },
  cases: await Promise.all(p2Cases.map(async ([id, description, mutate, expect]) => {
    const wire = structuredClone(p2Base);
    await mutate(wire);
    return { id, description, wire, expect };
  })),
};
writeFileSync(new URL('./vector-permit2.json', import.meta.url), JSON.stringify(permit2Vector, null, 2) + '\n');

// =====================================================================
// SVM (exact on Solana)
// =====================================================================
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error('bad base58');
    n = n * 58n + BigInt(i);
  }
  const body = n === 0n ? [] : [...unhex(n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0'))];
  const zeros = s.length - s.replace(/^1+/, '').length;
  return Uint8Array.from([...new Array(zeros).fill(0), ...body]);
}
function b58encode(b: Uint8Array): string {
  let n = BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const x of b) { if (x !== 0) break; out = '1' + out; }
  return out;
}
const pk32 = (s: string) => { const b = b58decode(s); if (b.length !== 32) throw new Error('not 32 bytes: ' + s); return b; };

const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const edKey = (seed: Uint8Array) => createPrivateKey({ key: Buffer.concat([ED_PKCS8, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
const edPub = (seed: Uint8Array) =>
  Uint8Array.from(Buffer.from(createPublicKey(edKey(seed)).export({ format: 'jwk' }).x!, 'base64url'));

// Solana devnet CAIP-2 id.
const svmNetwork = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const ownerSeed = fixed('svm-client-owner');
const feePayerSeed = fixed('svm-fee-payer');
const owner = edPub(ownerSeed);
const feePayer = edPub(feePayerSeed);
// Placeholder token accounts: payment-outcome checks belong to the facilitator, not to these vectors.
const sourceAta = fixed('svm-source-ata');
const destinationAta = fixed('svm-destination-ata');
const mint = pk32('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'); // USDC on devnet
const PROGRAM = {
  token: pk32('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
  computeBudget: pk32('ComputeBudget111111111111111111111111111111'),
  memo: pk32('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
  memoV1: pk32('Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo'),
};
const blockhash = fixed('svm-recent-blockhash');

const compactU16 = (n: number) => {
  const out: number[] = [];
  for (;;) { const b = n & 0x7f; n >>= 7; if (n) out.push(b | 0x80); else { out.push(b); return out; } }
};
const le = (n: bigint, bytes: number) => { const b = Buffer.alloc(bytes); for (let i = 0; i < bytes; i++) b[i] = Number((n >> BigInt(8 * i)) & 0xffn); return b; };

// Account table, ordered as Solana requires: signed writable, signed read-only, unsigned writable, unsigned read-only.
const accounts = [feePayer, owner, sourceAta, destinationAta, mint, PROGRAM.token, PROGRAM.computeBudget, PROGRAM.memo, PROGRAM.memoV1];
const IDX = { feePayer: 0, owner: 1, source: 2, destination: 3, mint: 4, token: 5, computeBudget: 6, memo: 7, memoV1: 8 };
type Ix = { program: number; accounts: number[]; data: Uint8Array };
const memoIx = (data: string, program = IDX.memo): Ix => ({ program, accounts: [], data: enc.encode(data) });
const baseInstructions = (memos: Ix[]): Ix[] => [
  { program: IDX.computeBudget, accounts: [], data: cat([2], le(20000n, 4)) },  // SetComputeUnitLimit
  { program: IDX.computeBudget, accounts: [], data: cat([3], le(1n, 8)) },      // SetComputeUnitPrice
  { program: IDX.token, accounts: [IDX.source, IDX.mint, IDX.destination, IDX.owner], data: cat([12], le(10000n, 8), [6]) }, // TransferChecked
  ...memos,
];
function messageV0(ixs: Ix[]): Uint8Array {
  return cat(
    [0x80, 2, 1, accounts.length - 4], // version 0; 2 signers, 1 read-only signer, unsigned read-only accounts
    compactU16(accounts.length), ...accounts,
    blockhash,
    compactU16(ixs.length),
    ...ixs.map((ix) => cat([ix.program], compactU16(ix.accounts.length), ix.accounts, compactU16(ix.data.length), ix.data)),
    compactU16(0), // no address lookup tables
  );
}
// Partially signed transaction: the fee payer signs after verification, so its slot is zero.
function transaction(ixs: Ix[], signWith: Uint8Array = ownerSeed) {
  const message = messageV0(ixs);
  const sig = Uint8Array.from(sign(null, message, edKey(signWith)));
  return { message, base64: Buffer.from(cat(compactU16(2), new Uint8Array(64), sig, message)).toString('base64') };
}
const memoHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

const svmTx = transaction(baseInstructions([memoIx(memoHex(c))]));
const svmDigest = sha256(svmTx.message);
const svmEnv = envelopeFor(svmNetwork, svmDigest);
const svmBase = { payload: { transaction: svmTx.base64 }, extension: extensionInfo(), request };
type SvmWire = typeof svmBase;
const replaceMessage = (txB64: string, message: Uint8Array) => {
  const tx = Buffer.from(txB64, 'base64');
  return Buffer.concat([tx.subarray(0, 1 + 128), Buffer.from(message)]).toString('base64');
};
const svmCases: [string, string, (w: SvmWire) => void, Expect][] = [
  ['valid', 'No tampering.', () => {}, null],
  ['memo-replaced', 'Intermediary replaces the memo with a commitment to its own ephemeral key; the client signature no longer matches.',
    (w) => {
      w.payload.transaction = replaceMessage(w.payload.transaction, messageV0(baseInstructions([memoIx(memoHex(otherC))])));
      w.extension.ephemeralPublicKey = hex(attackerE);
    }, reject('invalid_exact_svm_payload_signature_invalid')],
  ['ephemeral-key-swapped', 'Intermediary replaces the ephemeral public key in the extension.',
    (w) => { w.extension.ephemeralPublicKey = hex(attackerE); }, reject('response_encryption_nonce_mismatch')],
  ['request-body-changed', 'Intermediary changes the request body.',
    (w) => { w.request = { ...w.request, body: '{"query":"weather","city":"Busan"}' }; }, reject('response_encryption_nonce_mismatch')],
  ['two-commitment-memos', 'Payer signs one transaction carrying commitments for two requests.',
    (w) => { w.payload.transaction = transaction(baseInstructions([memoIx(memoHex(c)), memoIx(memoHex(otherC))])).base64; },
    reject('response_encryption_nonce_mismatch')],
  ['extra-memo-v1', 'A second memo through the older Memo program.',
    (w) => { w.payload.transaction = transaction(baseInstructions([memoIx(memoHex(c)), memoIx('note', IDX.memoV1)])).base64; },
    // x402 SVM Path 1 recognizes only MemoSq4...; a smart-wallet path may let it through.
    reject('response_encryption_nonce_mismatch', 'invalid_exact_svm_payload_unknown_instruction')],
  ['memo-missing', 'Signed transaction without a memo.',
    (w) => { w.payload.transaction = transaction(baseInstructions([])).base64; }, reject('response_encryption_nonce_mismatch')],
  ['memo-uppercase-hex', 'Memo holds c in uppercase hex.',
    (w) => { w.payload.transaction = transaction(baseInstructions([memoIx(memoHex(c).toUpperCase())])).base64; },
    reject('response_encryption_nonce_mismatch')],
  ['memo-random-nonce', 'Memo holds a random 16-byte nonce, as an x402 client without this extension does.',
    (w) => { w.payload.transaction = transaction(baseInstructions([memoIx(memoHex(fixed('random-memo').slice(0, 16)))])).base64; },
    reject('response_encryption_nonce_mismatch')],
];

const svmVector = {
  description: 'x402 response-encryption v1, SVM profile (proposal 3.5). All private keys are test-only. Token accounts are placeholders.',
  profile: 'svm',
  inputs: {
    ...shared,
    network: svmNetwork,
    clientOwnerSeed: hex(ownerSeed),
    feePayerSeed: hex(feePayerSeed),
    // Fixture the verifier rebuilds the version-0 message from.
    accounts: { sourceAta: b58encode(sourceAta), destinationAta: b58encode(destinationAta), mint: b58encode(mint) },
    recentBlockhash: b58encode(blockhash),
    computeUnitLimit: 20000,
    computeUnitPriceMicrolamports: 1,
    amount: 10000,
    decimals: 6,
    programs: { memo: b58encode(PROGRAM.memo), memoV1: b58encode(PROGRAM.memoV1), token: b58encode(PROGRAM.token), computeBudget: b58encode(PROGRAM.computeBudget) },
  },
  intermediate: {
    ...sharedIntermediate,
    clientOwner: b58encode(owner),
    feePayer: b58encode(feePayer),
    memo: memoHex(c),
    message: Buffer.from(svmTx.message).toString('base64'),
    authorizationDigest: hex(svmDigest),
    ...svmEnv.intermediate,
  },
  output: { envelope: svmEnv.envelope },
  cases: svmCases.map(([id, description, mutate, expect]) => {
    const wire = structuredClone(svmBase);
    mutate(wire);
    return { id, description, wire, expect };
  }),
};
writeFileSync(new URL('./vector-svm.json', import.meta.url), JSON.stringify(svmVector, null, 2) + '\n');
console.log(`permit2: ${permit2Vector.cases.length} cases, svm: ${svmVector.cases.length} cases, c = ${hex(c)}`);
