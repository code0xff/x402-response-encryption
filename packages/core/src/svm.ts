// Solana profile (proposal 3.5): the binding commitment c travels as the transaction's single
// top-level SPL Memo, holding c as 64 lowercase hex characters. authorizationDigest is SHA-256
// of the serialized message the client signed; the local check verifies the client's ed25519
// signature over that message.
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { equalBytes, type Hex } from './bytes.js';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let out = '';
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const x of b) {
    if (x !== 0) break;
    out = '1' + out;
  }
  return out;
}

export function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('invalid base58');
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of s) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** SPL Memo programs; the profile counts instructions for either (proposal 3.5). */
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const MEMO_V1_PROGRAM = 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo';
export const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PE34ZRqY4f4CwzW';

const MEMO_KEYS = [base58Decode(MEMO_PROGRAM), base58Decode(MEMO_V1_PROGRAM)];
const TOKEN_KEYS = [base58Decode(TOKEN_PROGRAM), base58Decode(TOKEN_2022_PROGRAM)];
const TRANSFER_CHECKED = 12;

interface Instruction {
  program: number;
  accounts: number[];
  data: Uint8Array;
}

interface ParsedTransaction {
  signatures: Uint8Array[];
  message: Uint8Array;
  requiredSignatures: number;
  keys: Uint8Array[];
  instructions: Instruction[];
}

class Reader {
  o = 0;
  constructor(private b: Uint8Array) {}
  byte(): number {
    if (this.o >= this.b.length) throw new Error('truncated transaction');
    return this.b[this.o++]!;
  }
  bytes(n: number): Uint8Array {
    if (this.o + n > this.b.length) throw new Error('truncated transaction');
    const out = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return out;
  }
  /** Solana compact-u16: at most three bytes, canonical (no redundant zero continuation), at most 65535. */
  shortvec(): number {
    let n = 0;
    for (let i = 0; i < 3; i++) {
      const x = this.byte();
      if (i === 2 && x > 0x03) throw new Error('compact-u16 overflow');
      n |= (x & 0x7f) << (7 * i);
      if ((x & 0x80) === 0) {
        if (i > 0 && x === 0) throw new Error('non-canonical compact-u16');
        return n;
      }
    }
    throw new Error('invalid compact-u16');
  }
  done(): boolean {
    return this.o === this.b.length;
  }
}

/** Parses a serialized legacy or v0 transaction. Throws on malformed input. */
export function parseTransaction(tx: Uint8Array): ParsedTransaction {
  const r = new Reader(tx);
  const sigCount = r.shortvec();
  const signatures = Array.from({ length: sigCount }, () => r.bytes(64));
  const messageStart = r.o;
  const first = r.byte();
  let requiredSignatures: number;
  if (first & 0x80) {
    if ((first & 0x7f) !== 0) throw new Error('unsupported transaction version');
    requiredSignatures = r.byte();
  } else {
    requiredSignatures = first;
  }
  r.byte(); // readonly signed
  r.byte(); // readonly unsigned
  const keys = Array.from({ length: r.shortvec() }, () => r.bytes(32));
  r.bytes(32); // recent blockhash
  const instructions = Array.from({ length: r.shortvec() }, () => ({
    program: r.byte(),
    accounts: Array.from({ length: r.shortvec() }, () => r.byte()),
    data: r.bytes(r.shortvec()),
  }));
  if (first & 0x80) {
    for (let n = r.shortvec(); n > 0; n--) {
      r.bytes(32);
      r.bytes(r.shortvec());
      r.bytes(r.shortvec());
    }
  }
  if (!r.done()) throw new Error('trailing bytes after message');
  if (sigCount !== requiredSignatures || requiredSignatures > keys.length) throw new Error('signature count mismatch');
  return { signatures, message: tx.subarray(messageStart), requiredSignatures, keys, instructions };
}

/** A signed SVM `exact` payment seen through the Solana profile. */
export interface SvmPaymentView {
  method: 'svm';
  /**
   * The signed commitment, or undefined when the transaction does not carry exactly one top-level
   * Memo instruction holding 64 lowercase hex characters. The seller then rejects with
   * `response_encryption_nonce_mismatch` (proposal 3.5).
   */
  commitment?: Hex;
  /** Authority of the TransferChecked instruction, base58: the client. */
  from: string;
  /** Destination token account and mint of the TransferChecked instruction, base58. */
  to: string;
  token: string;
  value: bigint;
  /** authorizationDigest: SHA-256 of the serialized message (proposal 3.5, 6.1). */
  digest: Uint8Array;
  /** Local signature check: the client's ed25519 signature over the message. */
  signerMatches(): Promise<boolean>;
}

const isObject = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null;
const isKey = (k: Uint8Array | undefined, set: Uint8Array[]) => !!k && set.some((s) => equalBytes(s, k));

function base64Decode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('invalid base64');
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Reads `payload.payload` of an x402 `exact` SVM payment (`{ transaction }`, base64). Returns
 * undefined when the transaction is malformed or has no single top-level TransferChecked whose
 * authority signs it.
 *
 * Implementation limits: the TransferChecked must be top level (a smart-wallet transfer through
 * CPI is not read), and its mint and destination must be static account keys. Accounts loaded
 * from address lookup tables cannot be resolved without the tables' on-chain contents.
 */
export function svmPaymentView(payload: unknown): SvmPaymentView | undefined {
  if (!isObject(payload) || typeof payload.transaction !== 'string') return undefined;
  let tx: ParsedTransaction;
  try {
    tx = parseTransaction(base64Decode(payload.transaction));
  } catch {
    return undefined;
  }
  // Program ids cannot come from address lookup tables, so they index the static keys.
  const programOf = (ix: Instruction) => tx.keys[ix.program];

  const transfers = tx.instructions.filter((ix) => isKey(programOf(ix), TOKEN_KEYS) && ix.data[0] === TRANSFER_CHECKED);
  if (transfers.length !== 1) return undefined;
  const t = transfers[0]!;
  if (t.data.length !== 10 || t.accounts.length < 4) return undefined;
  // TransferChecked accounts: source, mint, destination, authority.
  const [, mint, destination, authority] = t.accounts as [number, number, number, number];
  const authorityKey = tx.keys[authority];
  const signerIndex = authority < tx.requiredSignatures ? authority : -1;
  if (!authorityKey || signerIndex < 0 || !tx.keys[mint] || !tx.keys[destination]) return undefined;
  let value = 0n;
  for (let i = 8; i >= 1; i--) value = (value << 8n) | BigInt(t.data[i]!);

  const memos = tx.instructions.filter((ix) => isKey(programOf(ix), MEMO_KEYS));
  // Byte-level check: exactly 64 ASCII lowercase hex characters, nothing else (no BOM, no whitespace).
  let commitment: Hex | undefined;
  const memo = memos.length === 1 ? memos[0]!.data : undefined;
  if (memo && memo.length === 64 && memo.every((x) => (x >= 0x30 && x <= 0x39) || (x >= 0x61 && x <= 0x66))) {
    commitment = ('0x' + String.fromCharCode(...memo)) as Hex;
  }

  const message = tx.message.slice();
  const signature = tx.signatures[signerIndex]!;
  return {
    method: 'svm',
    commitment,
    from: base58Encode(authorityKey),
    to: base58Encode(tx.keys[destination]!),
    token: base58Encode(tx.keys[mint]!),
    value,
    digest: sha256(message),
    signerMatches: async () => {
      try {
        // RFC 8032 rules (not ZIP-215), and no small-order key: such a key verifies a forged
        // signature over any message without anyone holding a private key.
        if (ed25519.ExtendedPoint.fromHex(authorityKey).isSmallOrder()) return false;
        return ed25519.verify(signature, message, authorityKey, { zip215: false });
      } catch {
        return false;
      }
    },
  };
}
