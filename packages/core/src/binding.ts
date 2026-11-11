// Client key binding (proposal 3.1, 3.2) and seller key identity (4.1).
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { concat, lengthPrefixed, utf8Bytes } from './bytes.js';
import { TAG } from './constants.js';
import { ResponseEncryptionError } from './errors.js';
import { canonicalUrl } from './url.js';

export interface RequestDescriptor {
  /** HTTP method exactly as sent; methods are case-sensitive, so it is not normalized. */
  method: string;
  /** Resource URL in the seller's public namespace (proposal 3.3). Canonicalized here. */
  url: string;
  /** Body bytes after removing any Content-Encoding. Empty when there is no body. */
  body?: Uint8Array | string;
}

/** requestHash (proposal 3.2). */
export function requestHash(req: RequestDescriptor): Uint8Array {
  const body = req.body === undefined ? new Uint8Array() : typeof req.body === 'string' ? utf8Bytes(req.body) : req.body;
  return sha256(
    concat(TAG.request, lengthPrefixed(req.method), lengthPrefixed(canonicalUrl(req.url)), sha256(body)),
  );
}

/** EIP-3009 nonce committing the client's ephemeral key, the seller key from the 402 and the request (proposal 3.1). */
export function bindingNonce(ephemeralPublicKey: Uint8Array, keyId: Uint8Array, reqHash: Uint8Array, nonceSalt: Uint8Array): Uint8Array {
  if (keyId.length !== 32 || reqHash.length !== 32 || nonceSalt.length !== 32) throw new Error('keyId, requestHash and nonceSalt must be 32 bytes');
  return keccak_256(concat(TAG.nonce, ephemeralPublicKey, keyId, reqHash, nonceSalt));
}

/** keyId of a 33-byte compressed public key (proposal 4.1). */
export function keyIdOf(publicKey: Uint8Array): Uint8Array {
  return keccak_256(concat(TAG.keyId, publicKey));
}

/**
 * Parses a 33-byte compressed secp256k1 point, rejecting anything off the curve.
 * Returns the input unchanged so clients keep the exact bytes that were committed.
 */
export function assertCompressedPoint(
  publicKey: Uint8Array,
  reason: 'response_encryption_invalid_public_key' | 'response_encryption_invalid_ephemeral_key',
): Uint8Array {
  if (publicKey.length !== 33 || (publicKey[0] !== 2 && publicKey[0] !== 3)) throw new ResponseEncryptionError(reason);
  try {
    secp256k1.ProjectivePoint.fromHex(publicKey).assertValidity();
  } catch {
    throw new ResponseEncryptionError(reason);
  }
  return publicKey;
}
