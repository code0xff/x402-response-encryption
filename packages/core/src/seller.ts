// Seller side: check that the paid request carries a correctly bound ephemeral key,
// then encrypt the response to it.
import { secp256k1 } from '@noble/curves/secp256k1';
import { assertCompressedPoint, bindingNonce, keyIdOf, requestHash, type RequestDescriptor } from './binding.js';
import { equalBytes, fromHex, toHex, type Hex } from './bytes.js';
import { VERSION } from './constants.js';
import { encryptResponse, type Envelope, type PlainResponse } from './envelope.js';
import { ResponseEncryptionError } from './errors.js';
import type { PaymentPayloadInfo } from './messages.js';

export interface SellerKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  keyId: Uint8Array;
}

export function sellerKeyFromPrivate(privateKey: Uint8Array): SellerKey {
  const publicKey = secp256k1.getPublicKey(privateKey, true);
  return { privateKey, publicKey, keyId: keyIdOf(publicKey) };
}

export interface BoundRequest {
  ephemeralPublicKey: Uint8Array;
  requestHash: Uint8Array;
  /** Undefined only when skipKeyCheck was set and the keyId is no longer held. */
  key: SellerKey | undefined;
}

export interface CheckBindingOptions {
  /** The signed commitment the profile extracts (proposal 3.5). Its signature must already be verified (A.6). */
  signedCommitment: Hex;
  /** Request as served, with url = the resource.url the resource server issued for this route (proposal 3.3). */
  request: RequestDescriptor;
  /** Keys accepted now, including old ones still in their grace period (proposal 4.4). */
  keys: readonly SellerKey[];
  /** Set when an envelope is stored for this commitment: the key may since have been rotated out (proposal 8.1). */
  skipKeyCheck?: boolean;
}

/**
 * Pre-settlement checks (proposal 3.1, 7.4, 8). Throws ResponseEncryptionError with
 * a server reason code; the code calling this function turns it into a 402.
 */
export function checkBinding(info: PaymentPayloadInfo | undefined, opts: CheckBindingOptions): BoundRequest {
  const fail = (r: ConstructorParameters<typeof ResponseEncryptionError>[0]) => new ResponseEncryptionError(r);
  if (!info) throw fail('response_encryption_extension_missing');
  if (info.version !== VERSION) throw fail('response_encryption_unsupported_version');

  let keyId: Uint8Array;
  try {
    keyId = fromHex(info.keyId);
  } catch {
    throw fail('response_encryption_unknown_key_id');
  }
  const key = opts.keys.find((k) => equalBytes(k.keyId, keyId));
  if (!key && !opts.skipKeyCheck) throw fail('response_encryption_unknown_key_id');

  let ephemeralPublicKey: Uint8Array;
  try {
    ephemeralPublicKey = assertCompressedPoint(fromHex(info.ephemeralPublicKey), 'response_encryption_invalid_ephemeral_key');
  } catch (err) {
    if (err instanceof ResponseEncryptionError) throw err;
    throw fail('response_encryption_invalid_ephemeral_key');
  }

  let reqHash: Uint8Array;
  try {
    reqHash = requestHash(opts.request);
  } catch (err) {
    if (err instanceof ResponseEncryptionError) throw fail('response_encryption_invalid_url');
    throw err;
  }

  let nonce: Uint8Array;
  try {
    nonce = bindingNonce(ephemeralPublicKey, keyId, reqHash, fromHex(info.nonceSalt));
  } catch {
    throw fail('response_encryption_nonce_mismatch');
  }
  if (toHex(nonce) !== opts.signedCommitment.toLowerCase()) throw fail('response_encryption_nonce_mismatch');

  return { ephemeralPublicKey, requestHash: reqHash, key };
}

/** Encrypts the response for a bound request. */
export function sealResponse(
  bound: BoundRequest,
  network: string,
  authorizationDigest: Uint8Array,
  response: PlainResponse,
  iv?: Uint8Array,
): Envelope {
  if (!bound.key) throw new ResponseEncryptionError('response_encryption_unknown_key_id');
  return encryptResponse(
    bound.key.privateKey,
    {
      ephemeralPublicKey: bound.ephemeralPublicKey,
      sellerPublicKey: bound.key.publicKey,
      keyId: bound.key.keyId,
      network,
      requestHash: bound.requestHash,
      authorizationDigest,
    },
    response,
    iv,
  );
}
