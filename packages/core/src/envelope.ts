// Key agreement, key derivation and the encrypted envelope (proposal 6, 7.3).
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concat, fromBase64Url, fromHex, lengthPrefixed, toBase64Url, toHex, u16, type Hex } from './bytes.js';
import { TAG, VERSION } from './constants.js';
import { ResponseEncryptionError } from './errors.js';

export interface Envelope {
  version: number;
  keyId: Hex;
  status: number;
  contentType: string;
  iv: string;
  ciphertext: string;
}

export interface KeyContext {
  /** Client ephemeral public key E, 33 bytes compressed. */
  ephemeralPublicKey: Uint8Array;
  /** Seller encryption public key M, 33 bytes compressed. */
  sellerPublicKey: Uint8Array;
  keyId: Uint8Array;
  /** CAIP-2 network of the payment, e.g. "eip155:8453". */
  network: string;
  requestHash: Uint8Array;
  /** EIP-712 digest of the signed payment authorization, 32 bytes. */
  authorizationDigest: Uint8Array;
}

/** Z: 32-byte x-coordinate of the ECDH shared point (proposal 6.1). */
export function sharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  return secp256k1.getSharedSecret(privateKey, peerPublicKey, true).slice(1);
}

export function hkdfInfo(ctx: KeyContext): Uint8Array {
  return concat(TAG.response, ctx.ephemeralPublicKey, ctx.sellerPublicKey, ctx.keyId, lengthPrefixed(ctx.network), ctx.requestHash);
}

/** K = HKDF-SHA256(Z, salt = authorization digest, info) (proposal 6.1). */
export function deriveResponseKey(z: Uint8Array, ctx: KeyContext): Uint8Array {
  return hkdf(sha256, z, ctx.authorizationDigest, hkdfInfo(ctx), 32);
}

/** AAD (proposal 6.3). */
export function envelopeAad(version: number, keyId: Uint8Array, status: number, contentType: string): Uint8Array {
  return concat(TAG.aad, new Uint8Array([version]), keyId, u16(status), lengthPrefixed(contentType));
}

export interface PlainResponse {
  status: number;
  contentType: string;
  body: Uint8Array;
}

/**
 * Seller side. Each K encrypts exactly one response: on a retry, resend the stored
 * envelope instead of calling this again (proposal 6.2, 8.1).
 */
export function encryptResponse(
  sellerPrivateKey: Uint8Array,
  ctx: KeyContext,
  response: PlainResponse,
  iv: Uint8Array = randomBytes(12),
): Envelope {
  if (response.status < 200 || response.status > 299) throw new Error('only 2xx responses are enveloped');
  const k = deriveResponseKey(sharedSecret(sellerPrivateKey, ctx.ephemeralPublicKey), ctx);
  const aad = envelopeAad(VERSION, ctx.keyId, response.status, response.contentType);
  const ciphertext = gcm(k, iv, aad).encrypt(response.body);
  return {
    version: VERSION,
    keyId: toHex(ctx.keyId),
    status: response.status,
    contentType: response.contentType,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

/**
 * Client side. ctx must be rebuilt from the request the client sent and the
 * authorization it signed, never from values in the response (proposal 6.1).
 */
export function decryptResponse(ephemeralPrivateKey: Uint8Array, ctx: KeyContext, envelope: Envelope): PlainResponse {
  try {
    if (envelope.version !== VERSION) throw new Error('version');
    const k = deriveResponseKey(sharedSecret(ephemeralPrivateKey, ctx.sellerPublicKey), ctx);
    const aad = envelopeAad(envelope.version, fromHex(envelope.keyId), envelope.status, envelope.contentType);
    const body = gcm(k, fromBase64Url(envelope.iv), aad).decrypt(fromBase64Url(envelope.ciphertext));
    return { status: envelope.status, contentType: envelope.contentType, body };
  } catch {
    throw new ResponseEncryptionError('response_encryption_decrypt_failed');
  }
}
