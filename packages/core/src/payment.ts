// Scheme profiles (proposal 3.5): where the binding commitment c sits in a signed x402
// `exact` EVM payment, the digest the client signed, and the local signature check.
import { getAddress, hashTypedData, recoverTypedDataAddress, type Address } from 'viem';
import { fromHex, toHex, type Hex } from './bytes.js';
import { transferAuthorizationTypedData, type TokenDomain, type TransferAuthorization } from './eip3009.js';

export type AssetTransferMethod = 'eip3009' | 'permit2';

/** Canonical Permit2 and x402ExactPermit2Proxy addresses (x402 scheme_exact_evm.md). */
export const PERMIT2_ADDRESS: Address = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
export const X402_EXACT_PERMIT2_PROXY: Address = '0x402085c248EeA27D92E8b30b2C58ed07f9E20001';

export interface Permit2Authorization {
  from: Address;
  permitted: { token: Address; amount: string };
  spender: Address;
  /** Decimal uint256. In this extension it is the binding commitment c. */
  nonce: string;
  deadline: string;
  witness: { to: Address; validAfter: string };
}

export const PERMIT2_WITNESS_TYPES = {
  PermitWitnessTransferFrom: [
    { name: 'permitted', type: 'TokenPermissions' },
    { name: 'spender', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
    { name: 'witness', type: 'Witness' },
  ],
  TokenPermissions: [
    { name: 'token', type: 'address' },
    { name: 'amount', type: 'uint256' },
  ],
  Witness: [
    { name: 'to', type: 'address' },
    { name: 'validAfter', type: 'uint256' },
  ],
} as const;

export function permit2TypedData(chainId: number, a: Permit2Authorization) {
  return {
    domain: { name: 'Permit2', chainId, verifyingContract: PERMIT2_ADDRESS },
    types: PERMIT2_WITNESS_TYPES,
    primaryType: 'PermitWitnessTransferFrom' as const,
    message: {
      permitted: { token: getAddress(a.permitted.token), amount: BigInt(a.permitted.amount) },
      spender: getAddress(a.spender),
      nonce: BigInt(a.nonce),
      deadline: BigInt(a.deadline),
      witness: { to: getAddress(a.witness.to), validAfter: BigInt(a.witness.validAfter) },
    },
  };
}

/** Permit2 carries c as the decimal uint256 of its 32 bytes. */
export function commitmentToPermit2Nonce(c: Hex): string {
  return BigInt(c).toString();
}

function permit2NonceToCommitment(nonce: string): Hex | undefined {
  if (!/^(0|[1-9][0-9]*)$/.test(nonce)) return undefined;
  const n = BigInt(nonce);
  if (n >= 1n << 256n) return undefined;
  return toHex(fromHex(n.toString(16).padStart(64, '0')));
}

/** A signed payment seen through its profile. */
export interface PaymentView {
  method: AssetTransferMethod;
  /** The signed commitment, lowercase 32-byte hex (proposal 3.5 extraction rule). */
  commitment: Hex;
  from: Address;
  to: Address;
  /** Token the signature authorizes. For EIP-3009 it is the domain's verifying contract. */
  token: Address;
  value: bigint;
  validAfter: bigint;
  /** Exclusive upper bound: EIP-3009 validBefore, Permit2 deadline + 1. */
  validBefore: bigint;
  /** Permit2 spender; absent for EIP-3009. */
  spender?: Address;
  /** authorizationDigest (proposal 6.1). */
  digest: Uint8Array;
  /** Local signature check (proposal 3.5): recovers `from` from the digest. EOA payers only. */
  signerMatches(): Promise<boolean>;
}

export interface PaymentContext {
  chainId: number;
  /** Required for EIP-3009: the token's EIP-712 domain, taken from terms the verifier trusts. */
  tokenDomain?: TokenDomain;
}

const isObject = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null;

/** Reads `payload.payload` of an x402 `exact` EVM payment. Returns undefined when it fits no profile. */
export function paymentView(payload: unknown, ctx: PaymentContext): PaymentView | undefined {
  if (!isObject(payload) || typeof payload.signature !== 'string') return undefined;
  const signature = payload.signature as Hex;
  try {
    if (isObject(payload.authorization) && !('permit2Authorization' in payload)) {
      if (!ctx.tokenDomain) return undefined;
      const a = payload.authorization as unknown as TransferAuthorization;
      if (typeof a.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(a.nonce)) return undefined;
      const typed = transferAuthorizationTypedData(ctx.tokenDomain, a);
      return {
        method: 'eip3009',
        commitment: a.nonce.toLowerCase() as Hex,
        from: getAddress(a.from),
        to: getAddress(a.to),
        token: getAddress(ctx.tokenDomain.verifyingContract),
        value: BigInt(a.value),
        validAfter: BigInt(a.validAfter),
        validBefore: BigInt(a.validBefore),
        digest: fromHex(hashTypedData(typed)),
        signerMatches: () => recovers(typed, signature, a.from),
      };
    }
    if (isObject(payload.permit2Authorization) && !('authorization' in payload)) {
      const a = payload.permit2Authorization as unknown as Permit2Authorization;
      const commitment = typeof a.nonce === 'string' ? permit2NonceToCommitment(a.nonce) : undefined;
      if (!commitment) return undefined;
      const typed = permit2TypedData(ctx.chainId, a);
      return {
        method: 'permit2',
        commitment,
        from: getAddress(a.from),
        to: typed.message.witness.to,
        token: typed.message.permitted.token,
        value: typed.message.permitted.amount,
        validAfter: typed.message.witness.validAfter,
        validBefore: typed.message.deadline + 1n,
        spender: typed.message.spender,
        digest: fromHex(hashTypedData(typed)),
        signerMatches: () => recovers(typed, signature, a.from),
      };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

async function recovers(typed: object, signature: Hex, from: string): Promise<boolean> {
  const args = { ...typed, signature } as Parameters<typeof recoverTypedDataAddress>[0];
  const signer = await recoverTypedDataAddress(args).catch(() => undefined);
  return !!signer && getAddress(signer) === getAddress(from);
}
