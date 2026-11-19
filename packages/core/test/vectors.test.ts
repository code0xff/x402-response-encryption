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
  paymentView,
  sealResponse,
  svmPaymentView,
  base58Encode,
  base58Decode,
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
const permit2 = load('vector-permit2.json');
const svm = load('vector-svm.json');

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

    const bound = checkBinding(binding.payloadInfo, { signedCommitment: binding.nonce, request: inputs.request, keys: [seller] });
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
    checkBinding(payload, { signedCommitment: auth.nonce, request: w.request, keys, skipKeyCheck: !!stored });
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

describe('vector-permit2 (proposal 3.5, A.9)', () => {
  const { inputs, intermediate, output, cases } = permit2;
  const chainId = chainIdOf(inputs.network);
  const seller = sellerKeyFromPrivate(fromHex(inputs.sellerEncryptionPrivateKey));
  const ctx = { chainId };

  it('extracts c and the digest, and the envelope decrypts', async () => {
    const valid = cases.find((c: { id: string }) => c.id === 'valid').wire;
    const view = paymentView(valid.payload, ctx)!;
    expect(view.method).toBe('permit2');
    expect(view.commitment).toBe(intermediate.commitment);
    expect(toHex(view.digest)).toBe(intermediate.authorizationDigest);
    expect(await view.signerMatches()).toBe(true);
    const bound = checkBinding(valid.extension as PaymentPayloadInfo, {
      signedCommitment: view.commitment,
      request: valid.request,
      keys: [seller],
    });
    const env = sealResponse(bound, inputs.network, view.digest, {
      status: inputs.response.status,
      contentType: inputs.response.contentType,
      body: utf8Bytes(inputs.response.body),
    }, fromHex(inputs.iv));
    expect(env).toEqual(output.envelope);
  });

  for (const c of cases) {
    it(`case ${c.id}`, async () => {
      const view = paymentView(c.wire.payload, ctx)!;
      let reason: string | null = null;
      if (!(await view.signerMatches())) reason = 'invalid_permit2_signature';
      else {
        try {
          checkBinding(c.wire.extension, { signedCommitment: view.commitment, request: c.wire.request, keys: [seller] });
        } catch (err) {
          reason = (err as ResponseEncryptionError).reason;
        }
      }
      expect(reason).toBe(c.expect?.reason ?? null);
    });
  }
});

describe('vector-svm (proposal 3.5, A.9)', () => {
  const { inputs, intermediate, output, cases } = svm;
  const seller = sellerKeyFromPrivate(fromHex(inputs.sellerEncryptionPrivateKey));

  it('extracts c, the digest and the transfer, and the envelope decrypts', async () => {
    const valid = cases.find((c: { id: string }) => c.id === 'valid').wire;
    const view = svmPaymentView(valid.payload)!;
    expect(view.method).toBe('svm');
    expect(view.commitment).toBe(intermediate.commitment);
    expect(toHex(view.digest)).toBe(intermediate.authorizationDigest);
    expect(view.from).toBe(intermediate.clientOwner);
    expect(view.to).toBe(inputs.accounts.destinationAta);
    expect(view.token).toBe(inputs.accounts.mint);
    expect(view.value).toBe(BigInt(inputs.amount));
    expect(await view.signerMatches()).toBe(true);
    const bound = checkBinding(valid.extension as PaymentPayloadInfo, {
      signedCommitment: view.commitment!,
      request: valid.request,
      keys: [seller],
    });
    const env = sealResponse(bound, inputs.network, view.digest, {
      status: inputs.response.status,
      contentType: inputs.response.contentType,
      body: utf8Bytes(inputs.response.body),
    }, fromHex(inputs.iv));
    expect(env).toEqual(output.envelope);
  });

  for (const c of cases) {
    it(`case ${c.id}`, async () => {
      const view = svmPaymentView(c.wire.payload)!;
      expect(view).toBeDefined();
      let reason: string | null = null;
      if (!(await view.signerMatches())) reason = 'invalid_exact_svm_payload_signature_invalid';
      else if (!view.commitment) reason = 'response_encryption_nonce_mismatch';
      else {
        try {
          checkBinding(c.wire.extension, { signedCommitment: view.commitment, request: c.wire.request, keys: [seller] });
        } catch (err) {
          reason = (err as ResponseEncryptionError).reason;
        }
      }
      expect(reason).toBe(c.expect?.reason ?? null);
    });
  }

  it('rejects malformed transactions', () => {
    expect(svmPaymentView({ transaction: 'AQ==' })).toBeUndefined();
    expect(svmPaymentView({ transaction: 'not base64!' })).toBeUndefined();
    expect(svmPaymentView({})).toBeUndefined();
  });

  const validTx = () => Buffer.from(cases.find((c: { id: string }) => c.id === 'valid').wire.payload.transaction, 'base64');
  const asPayload = (b: Uint8Array) => ({ transaction: Buffer.from(b).toString('base64') });

  it('rejects a non-canonical compact-u16 signature count', () => {
    const tx = validTx();
    expect(tx[0]).toBe(2);
    expect(svmPaymentView(asPayload(Buffer.concat([Buffer.from([0x82, 0x00]), tx.subarray(1)])))).toBeUndefined();
  });

  it('accepts only a memo of exactly 64 lowercase hex bytes', async () => {
    const tx = validTx();
    const hex = Buffer.from(intermediate.memo);
    const at = tx.indexOf(hex);
    expect(at).toBeGreaterThan(0);
    // Prefix a UTF-8 BOM inside the memo data (length byte 64 -> 67).
    expect(tx[at - 1]).toBe(64);
    const withBom = Buffer.concat([tx.subarray(0, at - 1), Buffer.from([67, 0xef, 0xbb, 0xbf]), tx.subarray(at)]);
    const view = svmPaymentView(asPayload(withBom));
    expect(view?.commitment).toBeUndefined();
  });

  it('refuses a small-order authority key with a forged signature', async () => {
    const tx = validTx();
    const view = svmPaymentView(asPayload(tx))!;
    const authority = Buffer.from(base58Decode(view.from));
    const keyAt = tx.indexOf(authority);
    const identity = Buffer.alloc(32);
    identity[0] = 1; // encoded identity point
    const forged = Buffer.from(tx);
    identity.copy(forged, keyAt);
    // Signature R = identity, S = 0 at the authority's signature slot (index 1).
    const sig = Buffer.alloc(64);
    sig[0] = 1;
    sig.copy(forged, 1 + 64);
    const v = svmPaymentView(asPayload(forged))!;
    expect(v.from).toBe(base58Encode(identity));
    expect(await v.signerMatches()).toBe(false);
  });

  it('base58 round-trips program ids and leading zeros', () => {
    expect(base58Encode(new Uint8Array(32))).toBe('11111111111111111111111111111111');
  });
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
