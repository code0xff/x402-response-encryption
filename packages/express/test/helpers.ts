// Shared fixtures for the end-to-end tests.
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FacilitatorClient } from '@x402/core/server';
import type { PaymentPayload, PaymentRequirements, SettleResponse, SupportedResponse, VerifyResponse } from '@x402/core/types';
import { getAddress, recoverTypedDataAddress, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sha256 } from '@noble/hashes/sha256';
import {
  X402_EXACT_PERMIT2_PROXY,
  attestationTypedData,
  permit2TypedData,
  sellerKeyFromPrivate,
  transferAuthorizationTypedData,
  type Permit2Authorization,
  type TransferAuthorization,
} from '@x402-response-encryption/core';
import type { SellerKeyConfig } from '../src/index.js';

export const NETWORK = 'eip155:84532' as const;
export const CHAIN_ID = 84532;
export const testKey = (label: string) => sha256(new TextEncoder().encode('x402-response-encryption/test/' + label));
export const hex = (b: Uint8Array) => ('0x' + Buffer.from(b).toString('hex')) as Hex;

export const payTo = privateKeyToAccount(hex(testKey('payTo')));
export const payer = privateKeyToAccount(hex(testKey('payer')));
export const SECRET = '{"report":"quarterly numbers","revenue":1234567}';

export async function keyConfig(label: string, attester = payTo): Promise<SellerKeyConfig> {
  const privateKey = testKey(label);
  const { publicKey, keyId } = sellerKeyFromPrivate(privateKey);
  const fields = { chainId: CHAIN_ID, payTo: attester.address, keyId, publicKey, notBefore: 0, notAfter: 4102444800 };
  const signature = await attester.signTypedData(attestationTypedData(fields));
  return { privateKey, attestation: { payTo: attester.address, notBefore: 0, notAfter: 4102444800, signature } };
}

/** Facilitator stand-in: real signature check (EIP-3009 or Permit2), nonce replay protection, no chain. */
export class LocalFacilitator implements FacilitatorClient {
  used = new Set<string>();
  settlements = 0;
  failNextSettle = false;
  /** Awaited at the start of settle, so a test can hold a settlement open. */
  settleGate?: Promise<void>;
  /** Called when settle starts. */
  onSettle?: () => void;
  private async check(p: PaymentPayload, r: PaymentRequirements): Promise<{ from: string; nonce: string } | { invalid: string }> {
    if ('permit2Authorization' in p.payload) {
      const a = p.payload.permit2Authorization as Permit2Authorization;
      const signer = await recoverTypedDataAddress({ ...permit2TypedData(CHAIN_ID, a), signature: p.payload.signature as Hex }).catch(() => undefined);
      if (!signer || getAddress(signer) !== getAddress(a.from)) return { invalid: 'invalid_permit2_signature' };
      if (getAddress(a.spender) !== X402_EXACT_PERMIT2_PROXY) return { invalid: 'invalid_permit2_spender' };
      if (getAddress(a.witness.to) !== getAddress(r.payTo)) return { invalid: 'invalid_permit2_recipient_mismatch' };
      if (getAddress(a.permitted.token) !== getAddress(r.asset) || BigInt(a.permitted.amount) < BigInt(r.amount)) return { invalid: 'permit2_amount_mismatch' };
      // Permit2 nonces are per owner; key the replay set the same way.
      return { from: a.from, nonce: `permit2:${getAddress(a.from)}:${a.nonce}` };
    }
    const auth = p.payload.authorization as TransferAuthorization;
    const extra = r.extra as { name: string; version: string };
    const domain = { name: extra.name, version: extra.version, chainId: CHAIN_ID, verifyingContract: getAddress(r.asset) };
    const signer = await recoverTypedDataAddress({
      ...transferAuthorizationTypedData(domain, auth),
      signature: p.payload.signature as Hex,
    }).catch(() => undefined);
    if (!signer || getAddress(signer) !== getAddress(auth.from)) return { invalid: 'invalid_exact_evm_payload_signature' };
    if (getAddress(auth.to) !== getAddress(r.payTo)) return { invalid: 'invalid_exact_evm_payload_recipient_mismatch' };
    return { from: auth.from, nonce: auth.nonce };
  }
  async verify(p: PaymentPayload, r: PaymentRequirements): Promise<VerifyResponse> {
    const c = await this.check(p, r);
    if ('invalid' in c) return { isValid: false, invalidReason: c.invalid };
    if (this.used.has(c.nonce)) return { isValid: false, invalidReason: 'invalid_exact_evm_payload_authorization_nonce_used' };
    return { isValid: true, payer: c.from };
  }
  async settle(p: PaymentPayload, r: PaymentRequirements): Promise<SettleResponse> {
    this.onSettle?.();
    if (this.settleGate) await this.settleGate;
    const c = await this.check(p, r);
    if ('invalid' in c) return { success: false, errorReason: c.invalid, transaction: '', network: r.network };
    if (this.failNextSettle) {
      this.failNextSettle = false;
      return { success: false, errorReason: 'invalid_exact_evm_transaction_failed', transaction: '', network: r.network };
    }
    if (this.used.has(c.nonce)) return { success: false, errorReason: 'nonce_used', transaction: '', network: r.network };
    this.used.add(c.nonce);
    this.settlements++;
    return { success: true, transaction: '0x' + '11'.repeat(32), network: r.network, payer: c.from };
  }
  async getSupported(): Promise<SupportedResponse> {
    return { kinds: [{ x402Version: 2, scheme: 'exact', network: NETWORK }], extensions: [], signers: {} };
  }
}


export const listen = (s: Server) => new Promise<string>((r) => s.listen(0, () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)));
