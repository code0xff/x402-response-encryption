// EncryptionKeyAttestation (proposal 4.1).
import { getAddress, hashTypedData, recoverTypedDataAddress, type Address } from 'viem';
import { toHex, type Hex } from './bytes.js';
import { ATTESTATION_DOMAIN } from './constants.js';

export interface Attestation {
  payTo: Address;
  notBefore: number;
  notAfter: number;
  signature: Hex;
}

export const ATTESTATION_TYPES = {
  EncryptionKeyAttestation: [
    { name: 'payTo', type: 'address' },
    { name: 'keyId', type: 'bytes32' },
    { name: 'publicKey', type: 'bytes' },
    { name: 'notBefore', type: 'uint64' },
    { name: 'notAfter', type: 'uint64' },
  ],
} as const;

export interface AttestationFields {
  chainId: number;
  payTo: Address;
  keyId: Uint8Array;
  publicKey: Uint8Array;
  notBefore: number;
  notAfter: number;
}

/** Typed data to hand to a wallet's signTypedData. */
export function attestationTypedData(f: AttestationFields) {
  return {
    domain: { ...ATTESTATION_DOMAIN, chainId: f.chainId },
    types: ATTESTATION_TYPES,
    primaryType: 'EncryptionKeyAttestation' as const,
    message: {
      payTo: f.payTo,
      keyId: toHex(f.keyId),
      publicKey: toHex(f.publicKey),
      notBefore: BigInt(f.notBefore),
      notAfter: BigInt(f.notAfter),
    },
  };
}

export function attestationDigest(f: AttestationFields): Hex {
  return hashTypedData(attestationTypedData(f));
}

/**
 * Checks a contract payTo through EIP-1271 isValidSignature. Supplied by the
 * application because it needs an RPC client; core stays offline.
 */
export type ContractSignatureVerifier = (payTo: Address, digest: Hex, signature: Hex) => Promise<boolean>;

/** True when the signature over f was produced by f.payTo (ecrecover, then EIP-1271 if given). */
export async function verifyAttestationSignature(
  f: AttestationFields,
  signature: Hex,
  contractVerifier?: ContractSignatureVerifier,
): Promise<boolean> {
  try {
    const signer = await recoverTypedDataAddress({ ...attestationTypedData(f), signature });
    if (getAddress(signer) === getAddress(f.payTo)) return true;
  } catch {
    // Not a valid 65-byte ECDSA signature; may still be a contract signature.
  }
  return contractVerifier ? contractVerifier(f.payTo, attestationDigest(f), signature) : false;
}
