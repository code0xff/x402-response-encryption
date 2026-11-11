// Generates test vectors for docs/response-encryption-proposal.md.
// Every fixed input is derived from a label so the vector is reproducible.
import { createECDH, createCipheriv, createDecipheriv, hkdfSync, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { hashTypedData, recoverTypedDataAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { canonicalUrl } from './canonical-url.mjs';

const enc = new TextEncoder();
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex');
const unhex = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));
const cat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const lp = (s) => { const b = enc.encode(s); return cat(u32(b.length), b); };
const sha256 = (b) => Uint8Array.from(createHash('sha256').update(b).digest());
const b64url = (b) => Buffer.from(b).toString('base64url');
const fixed = (label) => sha256(enc.encode('x402-response-encryption/test-vector/' + label));

const TAG = {
  nonce: enc.encode('x402-response-encryption/v1/nonce'),
  request: enc.encode('x402-response-encryption/v1/request'),
  keyId: enc.encode('x402-response-encryption/v1/key-id'),
  response: enc.encode('x402-response-encryption/v1/response'),
  aad: enc.encode('x402-response-encryption/v1/aad'),
};

// ---- fixed inputs ----
const chainId = 84532;
const caip2 = `eip155:${chainId}`;
// Test-only token domain. verifyingContract is a placeholder, not a real deployment.
const tokenDomain = {
  name: 'USD Coin',
  version: '2',
  chainId,
  verifyingContract: '0x000000000000000000000000000000000000dEaD',
};

const payerKey = fixed('payer-wallet');
const payToKey = fixed('seller-payTo');
const e = fixed('client-ephemeral');
const m = fixed('seller-encryption');
const r = fixed('nonce-salt');
const iv = fixed('iv').slice(0, 12);

const payer = privateKeyToAccount(hex(payerKey));
const payTo = privateKeyToAccount(hex(payToKey));
const E = secp256k1.getPublicKey(e, true);
const M = secp256k1.getPublicKey(m, true);

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

// ---- 3.2 requestHash ----
const requestHash = sha256(cat(
  TAG.request,
  lp(request.method),
  lp(canonicalUrl(request.url)),
  sha256(enc.encode(request.body)),
));

// ---- 4.1 keyId + attestation ----
const keyId = keccak_256(cat(TAG.keyId, M));

// ---- 3.1 nonce (commits E, the seller key from the 402 and the request) ----
const nonce = keccak_256(cat(TAG.nonce, E, keyId, requestHash, r));
const attestationTyped = {
  domain: { name: 'x402-response-encryption', version: '1', chainId },
  types: {
    EncryptionKeyAttestation: [
      { name: 'payTo', type: 'address' },
      { name: 'keyId', type: 'bytes32' },
      { name: 'publicKey', type: 'bytes' },
      { name: 'notBefore', type: 'uint64' },
      { name: 'notAfter', type: 'uint64' },
    ],
  },
  primaryType: 'EncryptionKeyAttestation',
  message: {
    payTo: payTo.address,
    keyId: hex(keyId),
    publicKey: hex(M),
    notBefore: 1793836800n,
    notAfter: 1825372800n,
  },
};
const attestationDigest = hashTypedData(attestationTyped);
const attestationSignature = await payTo.signTypedData(attestationTyped);

// ---- EIP-3009 authorization ----
const authorizationTyped = {
  domain: tokenDomain,
  types: {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ],
  },
  primaryType: 'TransferWithAuthorization',
  message: {
    from: payer.address,
    to: payTo.address,
    value: 10000n,
    validAfter: 0n,
    validBefore: 1893456000n,
    nonce: hex(nonce),
  },
};
const authorizationDigest = unhex(hashTypedData(authorizationTyped));
const authorizationSignature = await payer.signTypedData(authorizationTyped);

// ---- 6.1 key agreement and derivation ----
const Zclient = secp256k1.getSharedSecret(e, M, true).slice(1);
const Zseller = secp256k1.getSharedSecret(m, E, true).slice(1);
// Independent ECDH implementation as a cross-check.
const ecdh = createECDH('secp256k1');
ecdh.setPrivateKey(Buffer.from(m));
const Znode = Uint8Array.from(ecdh.computeSecret(Buffer.from(E)));

const info = cat(TAG.response, E, M, keyId, lp(caip2), requestHash);
const K = new Uint8Array(hkdfSync('sha256', Zclient, authorizationDigest, info, 32));

// ---- 6.3 AAD, 7.3 envelope ----
const version = 1;
const aad = cat(TAG.aad, [version], keyId, u16(response.status), lp(response.contentType));
const cipher = createCipheriv('aes-256-gcm', K, iv);
cipher.setAAD(aad);
const ct = Buffer.concat([cipher.update(enc.encode(response.body)), cipher.final(), cipher.getAuthTag()]);
const envelope = {
  version,
  keyId: hex(keyId),
  status: response.status,
  contentType: response.contentType,
  iv: b64url(iv),
  ciphertext: b64url(ct),
};

// ---- self checks ----
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const checks = {
  ecdhSymmetric: eq(Zclient, Zseller),
  ecdhMatchesNodeCrypto: eq(Zclient, Znode),
  attestationRecovers:
    (await recoverTypedDataAddress({ ...attestationTyped, signature: attestationSignature })) === payTo.address,
  authorizationRecovers:
    (await recoverTypedDataAddress({ ...authorizationTyped, signature: authorizationSignature })) === payer.address,
  decrypts: (() => {
    const d = createDecipheriv('aes-256-gcm', K, iv);
    d.setAAD(aad);
    d.setAuthTag(ct.subarray(ct.length - 16));
    return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString() === response.body;
  })(),
  swappedEphemeralKeyChangesNonce: (() => {
    const E2 = secp256k1.getPublicKey(fixed('attacker-ephemeral'), true);
    return !eq(keccak_256(cat(TAG.nonce, E2, keyId, requestHash, r)), nonce);
  })(),
};
for (const [k, v] of Object.entries(checks)) if (!v) throw new Error(`self check failed: ${k}`);

const vector = {
  description: 'x402 response-encryption v1, EIP-3009 exact. All private keys are test-only.',
  inputs: {
    clientEphemeralPrivateKey: hex(e),
    sellerEncryptionPrivateKey: hex(m),
    payerPrivateKey: hex(payerKey),
    payToPrivateKey: hex(payToKey),
    nonceSalt: hex(r),
    iv: hex(iv),
    network: caip2,
    tokenDomain,
    authorization: { ...authorizationTyped.message, value: '10000', validAfter: '0', validBefore: '1893456000', nonce: undefined },
    attestation: { notBefore: 1793836800, notAfter: 1825372800 },
    request,
    response,
  },
  intermediate: {
    clientEphemeralPublicKey: hex(E),
    sellerEncryptionPublicKey: hex(M),
    payerAddress: payer.address,
    payToAddress: payTo.address,
    requestBodySha256: hex(sha256(enc.encode(request.body))),
    requestHash: hex(requestHash),
    nonce: hex(nonce),
    keyId: hex(keyId),
    attestationDigest,
    attestationSignature,
    authorizationDigest: hex(authorizationDigest),
    authorizationSignature,
    sharedSecretZ: hex(Zclient),
    hkdfInfo: hex(info),
    aesKey: hex(K),
    aad: hex(aad),
  },
  output: { envelope },
  checks,
};

const json = JSON.stringify(vector, null, 2);
writeFileSync(new URL('./vector-1.json', import.meta.url), json + '\n');
console.log(json);

// ---- negative cases ----
// Each case is the valid exchange of vector-1 with one tampering applied, plus the
// first check that must reject it. Checks run in protocol order:
//   client-402 (before paying) -> seller (before settling) -> client-response.
// did:web DID document (proposal 4.3), as the client fetches it directly from the seller origin.
const did = 'did:web:api.seller.example';
const jwkOf = (pub) => {
  const p = secp256k1.ProjectivePoint.fromHex(pub).toAffine();
  const b = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').toString('base64url');
  return { kty: 'EC', crv: 'secp256k1', x: b(p.x), y: b(p.y) };
};
const encKid = (id) => `${did}#x402-re-${Buffer.from(id).toString('hex')}`;
const didDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
  id: did,
  verificationMethod: [
    {
      id: `${did}#payto-${caip2.replace(':', '-')}`,
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      controller: did,
      blockchainAccountId: `${caip2}:${payTo.address}`,
    },
    {
      id: encKid(keyId),
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: jwkOf(M),
      x402ResponseEncryption: { keyId: hex(keyId), payTo: payTo.address, notBefore: 1793836800, notAfter: 1825372800, signature: attestationSignature },
    },
  ],
  keyAgreement: [encKid(keyId)],
};
writeFileSync(new URL('./did-document.json', import.meta.url), JSON.stringify(didDocument, null, 2) + '\n');

const str = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
const baseWire = str({
  // The x402 PaymentRequirements field the client signs over as authorization.to.
  paymentRequirements: { payTo: payTo.address },
  paymentRequired: {
    resource: { url: request.url },
    version: 1,
    required: true,
    suite: 'secp256k1-hkdf-sha256-aes256gcm',
    keyId: hex(keyId),
    kid: encKid(keyId),
    publicKey: hex(M),
    attestation: { payTo: payTo.address, notBefore: 1793836800, notAfter: 1825372800, signature: attestationSignature },
  },
  paymentPayload: {
    authorization: authorizationTyped.message,
    signature: authorizationSignature,
    // The client echoes the advertised info and adds its own fields (proposal 7.2).
    extension: {
      info: {
        version: 1,
        required: true,
        suite: 'secp256k1-hkdf-sha256-aes256gcm',
        keyId: hex(keyId),
        kid: encKid(keyId),
        publicKey: hex(M),
        attestation: { payTo: payTo.address, notBefore: 1793836800, notAfter: 1825372800, signature: attestationSignature },
        ephemeralPublicKey: hex(E),
        nonceSalt: hex(r),
      },
    },
  },
  request,
  envelope,
});
const baseClient = str({
  ephemeralPrivateKey: hex(e),
  request,
  authorization: authorizationTyped.message,
  didDocument,
  now: 1800000000,
});
const baseSeller = { encryptionPrivateKey: hex(m), keyIds: [hex(keyId)] };

// A successor key for the rotation cases (proposal 4.5).
const rotatedKeyId = keccak_256(cat(TAG.keyId, secp256k1.getPublicKey(fixed('rotated-seller-encryption'), true)));

const attackerE = secp256k1.getPublicKey(fixed('attacker-ephemeral'), true);
const attackerM = secp256k1.getPublicKey(fixed('attacker-encryption'), true);
const attackerKeyId = keccak_256(cat(TAG.keyId, attackerM));
const attackerPayTo = privateKeyToAccount(hex(fixed('attacker-payTo')));
const attackerAttestation = await attackerPayTo.signTypedData({
  ...attestationTyped,
  message: { ...attestationTyped.message, payTo: attackerPayTo.address, keyId: hex(attackerKeyId), publicKey: hex(attackerM) },
});
// Intermediary alters resource.url in the 402; the client honestly signs over the altered URL.
const tamperedResource = 'https://api.seller.example/v1/report?id=43';
const reqHashOf = (req) => sha256(cat(TAG.request, lp(req.method), lp(canonicalUrl(req.url)), sha256(enc.encode(req.body))));
const tamperedAuth = {
  ...authorizationTyped.message,
  nonce: hex(keccak_256(cat(TAG.nonce, E, keyId, reqHashOf({ ...request, url: tamperedResource }), r))),
};
const tamperedSig = await payer.signTypedData({ ...authorizationTyped, message: tamperedAuth });

// Intermediary points payment to its own address but keeps the seller's real encryption key.
const attackerAttestationRealKey = await attackerPayTo.signTypedData({
  ...attestationTyped,
  message: { ...attestationTyped.message, payTo: attackerPayTo.address },
});

// Seller envelope store (proposal 8.1), keyed by authorization nonce.
const storedFor = (w) => ({ [w.paymentPayload.authorization.nonce.toLowerCase()]: w.envelope });

const flip = (b64) => { const b = Buffer.from(b64, 'base64url'); b[0] ^= 1; return b.toString('base64url'); };

const DID_CASES = new Set(['402-full-swap', 'did-jwk-swapped', '402-full-swap-own-did', '402-payto-redirected', 'did-key-revoked', 'valid-did-web']);

const cases = [
  ['valid', 'No tampering.', () => {}, null],
  ['valid-did-web', 'No tampering, client also checks the did:web DID document.', () => {}, null],
  ['402-full-swap-core', 'Core profile: intermediary replaces payTo, key and attestation with its own valid set. The client cannot tell; the payment goes to the substituted payTo on-chain.',
    (w) => {
      w.paymentRequired.publicKey = hex(attackerM);
      w.paymentRequired.keyId = hex(attackerKeyId);
      w.paymentRequired.attestation = { ...w.paymentRequired.attestation, payTo: attackerPayTo.address, signature: attackerAttestation };
      w.paymentRequirements.payTo = attackerPayTo.address;
    }, ['client-402', null]],
  ['402-pubkey-swapped', 'Intermediary replaces the 402 public key only.',
    (w) => { w.paymentRequired.publicKey = hex(attackerM); }, ['client-402', 'response_encryption_key_id_mismatch']],
  ['402-key-and-keyid-swapped', 'Intermediary replaces public key and keyId consistently, keeps the attestation signature.',
    (w) => { w.paymentRequired.publicKey = hex(attackerM); w.paymentRequired.keyId = hex(attackerKeyId); },
    ['client-402', 'response_encryption_attestation_invalid']],
  ['402-full-swap', 'Intermediary replaces payTo, key and attestation with its own valid set.',
    (w) => {
      w.paymentRequired.publicKey = hex(attackerM);
      w.paymentRequired.keyId = hex(attackerKeyId);
      w.paymentRequired.attestation = { ...w.paymentRequired.attestation, payTo: attackerPayTo.address, signature: attackerAttestation };
      w.paymentRequirements.payTo = attackerPayTo.address;
    }, ['client-402', 'response_encryption_did_key_not_found']],
  ['did-jwk-swapped', 'DID document lists a different JWK under the kid named in the 402.',
    (_, c) => { c.didDocument.verificationMethod[1].publicKeyJwk = jwkOf(attackerM); }, ['client-402', 'response_encryption_did_key_mismatch']],
  ['402-full-swap-own-did', 'Full swap, and kid also pointed at an attacker-controlled DID.',
    (w) => {
      w.paymentRequired.publicKey = hex(attackerM);
      w.paymentRequired.keyId = hex(attackerKeyId);
      w.paymentRequired.kid = `did:web:attacker.example#x402-re-${Buffer.from(attackerKeyId).toString('hex')}`;
      w.paymentRequired.attestation = { ...w.paymentRequired.attestation, payTo: attackerPayTo.address, signature: attackerAttestation };
      w.paymentRequirements.payTo = attackerPayTo.address;
    }, ['client-402', 'response_encryption_did_origin_mismatch']],
  ['402-payto-redirected', 'Intermediary keeps the real key but substitutes its own payTo with a valid attestation.',
    (w) => {
      w.paymentRequired.attestation = { ...w.paymentRequired.attestation, payTo: attackerPayTo.address, signature: attackerAttestationRealKey };
      w.paymentRequirements.payTo = attackerPayTo.address;
    }, ['client-402', 'response_encryption_did_pay_to_mismatch']],
  ['attestation-pay-to-differs', 'Intermediary attaches an attestation from another address; the payment requirements still name the seller payTo.',
    (w) => {
      w.paymentRequired.attestation = { ...w.paymentRequired.attestation, payTo: attackerPayTo.address, signature: attackerAttestationRealKey };
    }, ['client-402', 'response_encryption_pay_to_mismatch']],
  ['did-key-revoked', 'Key removed from keyAgreement in the DID document.',
    (_, c) => { c.didDocument.keyAgreement = []; }, ['client-402', 'response_encryption_did_key_not_found']],
  ['attestation-expired', 'Client clock is past notAfter.',
    (_, c) => { c.now = 1830000000; }, ['client-402', 'response_encryption_attestation_expired']],
  ['extension-missing', 'Intermediary strips the response-encryption extension.',
    (w) => { w.paymentPayload.extension = null; }, ['seller', 'response_encryption_extension_missing']],
  ['unsupported-version', 'Payload declares an extension version the seller does not implement.',
    (w) => { w.paymentPayload.extension.info.version = 2; }, ['seller', 'response_encryption_unsupported_version']],
  ['unsupported-suite', 'Intermediary advertises a suite the client does not implement.',
    (w) => { w.paymentRequired.suite = 'x25519-hkdf-sha256-aes256gcm'; }, ['client-402', 'response_encryption_unsupported_suite']],
  ['rotated-key-in-grace', 'Seller has rotated to a new key but still accepts the old one during the grace period; the client paid against the old 402.',
    (_, __, mer) => { mer.keyIds = [hex(rotatedKeyId), hex(keyId)]; }, null],
  ['rotated-key-after-grace', 'Seller has rotated and dropped the old key; the client paid against a stale 402.',
    (_, __, mer) => { mer.keyIds = [hex(rotatedKeyId)]; }, ['seller', 'response_encryption_unknown_key_id']],
  ['retry-after-settlement', 'Client resends the identical paid request after losing the response; the seller returns its stored envelope without settling again.',
    (w, _, mer) => { mer.stored = storedFor(w); w.envelope = null; }, null],
  ['retry-after-key-rotation', 'As retry-after-settlement, but the seller has since dropped the keyId; the stored envelope is still returned.',
    (w, _, mer) => { mer.stored = storedFor(w); mer.keyIds = [hex(rotatedKeyId)]; w.envelope = null; }, null],
  ['retry-request-changed', 'Settled payload replayed with a different request body; the stored envelope must not be released.',
    (w, _, mer) => { mer.stored = storedFor(w); w.envelope = null; w.request.body = '{"id":43}'; }, ['seller', 'response_encryption_nonce_mismatch']],
  ['unknown-key-id', 'Payload names a keyId the seller does not hold.',
    (w) => { w.paymentPayload.extension.info.keyId = hex(attackerKeyId); }, ['seller', 'response_encryption_unknown_key_id']],
  ['key-id-swapped-to-accepted-key', 'Intermediary replaces keyId with another key the seller still accepts, e.g. an old key it has obtained.',
    (w, _, mer) => { mer.keyIds = [hex(keyId), hex(rotatedKeyId)]; w.paymentPayload.extension.info.keyId = hex(rotatedKeyId); }, ['seller', 'response_encryption_nonce_mismatch']],
  ['ephemeral-key-swapped', 'Intermediary replaces the ephemeral public key in the payload.',
    (w) => { w.paymentPayload.extension.info.ephemeralPublicKey = hex(attackerE); }, ['seller', 'response_encryption_nonce_mismatch']],
  ['ephemeral-key-and-nonce-swapped', 'Intermediary replaces the ephemeral key and rewrites authorization.nonce to match.',
    (w) => {
      w.paymentPayload.extension.info.ephemeralPublicKey = hex(attackerE);
      w.paymentPayload.authorization.nonce = hex(keccak_256(cat(TAG.nonce, attackerE, keyId, requestHash, r)));
    }, ['seller', 'invalid_exact_evm_payload_signature']],
  ['nonce-salt-changed', 'Intermediary changes nonceSalt.',
    (w) => { w.paymentPayload.extension.info.nonceSalt = hex(fixed('other-salt')); }, ['seller', 'response_encryption_nonce_mismatch']],
  ['request-body-changed', 'Intermediary changes the request body.',
    (w) => { w.request.body = '{"query":"weather","city":"Busan"}'; }, ['seller', 'response_encryption_nonce_mismatch']],
  ['request-path-changed', 'Intermediary changes the request path.',
    (w) => { w.request.url = 'https://api.seller.example/v1/admin?id=42'; }, ['seller', 'response_encryption_nonce_mismatch']],
  ['request-query-changed', 'Intermediary changes a query parameter.',
    (w) => { w.request.url = 'https://api.seller.example/v1/report?id=43'; }, ['seller', 'response_encryption_nonce_mismatch']],
  ['equivalent-url-form', 'Seller sees a different but equivalent spelling of the URL.',
    (w) => { w.request.url = 'HTTPS://API.Seller.example:443/v1/./report?id=42#x'; }, null],
  ['resource-url-changed-in-402', 'Intermediary alters resource.url in the 402; client signs over it, seller receives the original request.',
    (w, c) => {
      w.paymentRequired.resource.url = tamperedResource;
      w.paymentPayload.authorization = str(tamperedAuth);
      w.paymentPayload.signature = tamperedSig;
      c.request = { ...c.request, url: tamperedResource };
      c.authorization = str(tamperedAuth);
    }, ['seller', 'response_encryption_nonce_mismatch']],
  ['request-method-changed', 'Intermediary changes the request method.',
    (w) => { w.request.method = 'GET'; }, ['seller', 'response_encryption_nonce_mismatch']],
  ['ciphertext-flipped', 'One ciphertext bit flipped.',
    (w) => { w.envelope.ciphertext = flip(w.envelope.ciphertext); }, ['client-response', 'response_encryption_decrypt_failed']],
  ['gcm-tag-truncated', 'Last byte of the GCM tag removed.',
    (w) => { const b = Buffer.from(w.envelope.ciphertext, 'base64url'); w.envelope.ciphertext = b.subarray(0, -1).toString('base64url'); },
    ['client-response', 'response_encryption_decrypt_failed']],
  ['iv-changed', 'IV changed.',
    (w) => { w.envelope.iv = flip(w.envelope.iv); }, ['client-response', 'response_encryption_decrypt_failed']],
  ['status-changed', 'Envelope status changed 200 -> 201.',
    (w) => { w.envelope.status = 201; }, ['client-response', 'response_encryption_decrypt_failed']],
  ['content-type-changed', 'Envelope contentType changed.',
    (w) => { w.envelope.contentType = 'text/plain'; }, ['client-response', 'response_encryption_decrypt_failed']],
  ['wrong-ephemeral-private-key', 'Client decrypts with a different ephemeral private key.',
    (_, c) => { c.ephemeralPrivateKey = hex(fixed('attacker-ephemeral')); }, ['client-response', 'response_encryption_decrypt_failed']],
].map(([id, description, mutate, expect]) => {
  const wire = structuredClone(baseWire);
  const client = structuredClone(baseClient);
  const mer = structuredClone(baseSeller);
  mutate(wire, client, mer);
  // Cases rejected by a DID check exercise the optional did:web profile (proposal 4.5);
  // all others need only the core checks.
  const profile = DID_CASES.has(id) ? 'did-web' : 'core';
  if (profile === 'core') {
    delete client.didDocument;
    delete wire.paymentRequired.kid;
    delete wire.paymentPayload.extension?.info.kid;
  }
  return { id, description, profile, wire, client, ...(JSON.stringify(mer) !== JSON.stringify(baseSeller) && { seller: mer }), expect: expect && { stage: expect[0], reason: expect[1] } };
});

writeFileSync(
  new URL('./negative-cases.json', import.meta.url),
  JSON.stringify({ description: 'Tampering cases derived from vector-1.', network: caip2, tokenDomain, seller: baseSeller, cases }, null, 2) + '\n',
);
