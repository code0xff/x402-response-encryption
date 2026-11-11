// Client side: check the seller key from the 402, bind a fresh ephemeral key into
// the payment nonce, and open the encrypted response.
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { getAddress, type Address } from 'viem';
import { verifyAttestationSignature, type ContractSignatureVerifier } from './attestation.js';
import { assertCompressedPoint, bindingNonce, keyIdOf, requestHash, type RequestDescriptor } from './binding.js';
import { equalBytes, fromHex, toHex, type Hex } from './bytes.js';
import { SUITE, VERSION } from './constants.js';
import { decryptResponse, type Envelope, type PlainResponse } from './envelope.js';
import { ResponseEncryptionError } from './errors.js';
import type { PaymentPayloadInfo, PaymentRequiredInfo } from './messages.js';

export interface VerifiedSellerKey {
  publicKey: Uint8Array;
  keyId: Uint8Array;
  payTo: Address;
}

export interface VerifyKeyOptions {
  chainId: number;
  /** payTo from the payment requirements the client is about to sign over. */
  payTo: Address;
  /** Unix seconds. */
  now: number;
  /** Seller payTo known out of band (proposal 4.3). When set, anything else is refused. */
  pinnedPayTo?: Address;
  contractVerifier?: ContractSignatureVerifier;
}

/** Core checks before paying (proposal 4.1, 4.3). The did:web profile (4.5) runs on top of these. */
export async function verifySellerKey(info: PaymentRequiredInfo, opts: VerifyKeyOptions): Promise<VerifiedSellerKey> {
  const fail = (r: ConstructorParameters<typeof ResponseEncryptionError>[0]) => new ResponseEncryptionError(r);
  if (info.version !== VERSION) throw fail('response_encryption_unsupported_version');
  if (info.suite !== SUITE) throw fail('response_encryption_unsupported_suite');

  let publicKey: Uint8Array;
  try {
    publicKey = assertCompressedPoint(fromHex(info.publicKey), 'response_encryption_invalid_public_key');
  } catch (err) {
    if (err instanceof ResponseEncryptionError) throw err;
    throw fail('response_encryption_invalid_public_key');
  }
  const keyId = keyIdOf(publicKey);
  if (!equalBytes(keyId, fromHex(info.keyId))) throw fail('response_encryption_key_id_mismatch');

  const att = info.attestation;
  const signed = await verifyAttestationSignature(
    { chainId: opts.chainId, payTo: att.payTo, keyId, publicKey, notBefore: att.notBefore, notAfter: att.notAfter },
    att.signature,
    opts.contractVerifier,
  );
  if (!signed) throw fail('response_encryption_attestation_invalid');
  if (opts.now < att.notBefore || opts.now > att.notAfter) throw fail('response_encryption_attestation_expired');

  // The key must belong to the address the client pays, and to the pinned seller if there is one.
  const payTo = getAddress(att.payTo);
  if (payTo !== getAddress(opts.payTo)) throw fail('response_encryption_pay_to_mismatch');
  if (opts.pinnedPayTo && payTo !== getAddress(opts.pinnedPayTo)) throw fail('response_encryption_pay_to_mismatch');

  return { publicKey, keyId, payTo };
}

/** Per-request secrets. Keep until decryption succeeds or envelope retention ends (proposal 8.1). */
export interface ClientBinding {
  ephemeralPrivateKey: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  nonceSalt: Uint8Array;
  requestHash: Uint8Array;
  /** Value to put in authorization.nonce before signing. */
  nonce: Hex;
  payloadInfo: PaymentPayloadInfo;
}

export interface BindingRandomness {
  ephemeralPrivateKey?: Uint8Array;
  nonceSalt?: Uint8Array;
}

/** Generates (e, E) and r and computes the nonce (proposal 3.1). Randomness is injectable for tests only. */
export function createBinding(key: VerifiedSellerKey, request: RequestDescriptor, rnd: BindingRandomness = {}): ClientBinding {
  const ephemeralPrivateKey = rnd.ephemeralPrivateKey ?? secp256k1.utils.randomPrivateKey();
  const ephemeralPublicKey = secp256k1.getPublicKey(ephemeralPrivateKey, true);
  const nonceSalt = rnd.nonceSalt ?? randomBytes(32);
  const reqHash = requestHash(request);
  const nonce = toHex(bindingNonce(ephemeralPublicKey, key.keyId, reqHash, nonceSalt));
  return {
    ephemeralPrivateKey,
    ephemeralPublicKey,
    nonceSalt,
    requestHash: reqHash,
    nonce,
    payloadInfo: {
      version: VERSION,
      keyId: toHex(key.keyId),
      ephemeralPublicKey: toHex(ephemeralPublicKey),
      nonceSalt: toHex(nonceSalt),
    },
  };
}

/** Decrypts the envelope with the client's own state. */
export function openResponse(
  key: VerifiedSellerKey,
  binding: ClientBinding,
  network: string,
  authorizationDigest: Uint8Array,
  envelope: Envelope,
): PlainResponse {
  return decryptResponse(
    binding.ephemeralPrivateKey,
    {
      ephemeralPublicKey: binding.ephemeralPublicKey,
      sellerPublicKey: key.publicKey,
      keyId: key.keyId,
      network,
      requestHash: binding.requestHash,
      authorizationDigest,
    },
    envelope,
  );
}
