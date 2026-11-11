// EIP-3009 TransferWithAuthorization digest, used as the HKDF salt (proposal 6.1).
import { hashTypedData, type Address } from 'viem';
import { fromHex, type Hex } from './bytes.js';

export interface TokenDomain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

export interface TransferAuthorization {
  from: Address;
  to: Address;
  value: bigint | string;
  validAfter: bigint | string;
  validBefore: bigint | string;
  nonce: Hex;
}

export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

export function transferAuthorizationTypedData(domain: TokenDomain, a: TransferAuthorization) {
  return {
    domain,
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: 'TransferWithAuthorization' as const,
    message: {
      from: a.from,
      to: a.to,
      value: BigInt(a.value),
      validAfter: BigInt(a.validAfter),
      validBefore: BigInt(a.validBefore),
      nonce: a.nonce,
    },
  };
}

export function authorizationDigest(domain: TokenDomain, a: TransferAuthorization): Uint8Array {
  return fromHex(hashTypedData(transferAuthorizationTypedData(domain, a)));
}
