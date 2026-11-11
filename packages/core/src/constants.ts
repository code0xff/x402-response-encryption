import { utf8Bytes } from './bytes.js';

export const EXTENSION_KEY = 'response-encryption';
export const VERSION = 1;
export const SUITE = 'secp256k1-hkdf-sha256-aes256gcm';
export const ENVELOPE_CONTENT_TYPE = 'application/x402-encrypted+json';

/** Domain tags (proposal 2.1). Fixed length, concatenated without a length prefix. */
export const TAG = {
  nonce: utf8Bytes('x402-response-encryption/v1/nonce'),
  request: utf8Bytes('x402-response-encryption/v1/request'),
  keyId: utf8Bytes('x402-response-encryption/v1/key-id'),
  response: utf8Bytes('x402-response-encryption/v1/response'),
  aad: utf8Bytes('x402-response-encryption/v1/aad'),
} as const;

/** EIP-712 domain name and version of the key attestation (proposal 4.1). */
export const ATTESTATION_DOMAIN = { name: 'x402-response-encryption', version: '1' } as const;
