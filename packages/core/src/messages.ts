// Wire formats (proposal 7.1, 7.2). JSON Schemas for these live in schemas/.
import type { Address } from 'viem';
import type { Hex } from './bytes.js';

export interface PaymentRequiredInfo {
  version: number;
  required: boolean;
  suite: string;
  keyId: Hex;
  /** did:web profile only (proposal 4.5). */
  kid?: string;
  publicKey: Hex;
  attestation: {
    payTo: Address;
    notBefore: number;
    notAfter: number;
    signature: Hex;
  };
}

/**
 * The advertised info echoed unchanged plus the client's fields (proposal 7.2).
 * x402 rejects a payload whose extension info does not contain the advertised fields.
 */
export interface PaymentPayloadInfo extends Partial<Omit<PaymentRequiredInfo, 'version' | 'keyId'>> {
  version: number;
  keyId: Hex;
  ephemeralPublicKey: Hex;
  nonceSalt: Hex;
}

/** Builds the payload info from the advertised info and the client's binding. */
export function payloadInfoFor(advertised: PaymentRequiredInfo, binding: { ephemeralPublicKey: Hex; nonceSalt: Hex }): PaymentPayloadInfo {
  // A rejection 402 carries errorReason/errorMessage next to the key info; they are not echoed (proposal 7.2).
  const { errorReason: _r, errorMessage: _m, ...info } = advertised as PaymentRequiredInfo & { errorReason?: string; errorMessage?: string };
  return { ...info, ephemeralPublicKey: binding.ephemeralPublicKey, nonceSalt: binding.nonceSalt };
}
