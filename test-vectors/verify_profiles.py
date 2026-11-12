"""Independent Python check of vector-permit2.json and vector-svm.json (proposal 3.5).

Shares no code with generate-profiles.ts. Nested EIP-712 encoding, the Solana v0
message parser and base58 are written here from the specifications; secp256k1 and
signer recovery come from verify.py, ed25519 verification, HKDF and AES-GCM from
the cryptography package.

For each profile it recomputes the commitment, the authorization digest, the key
and the envelope, then runs every case through the seller checks in order:
payment signature, commitment extraction, commitment recomputation.
"""
import base64
import json
import re
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).parent))
from verify import (AESGCM, G, HKDF, InvalidTag, canonical_url, checksum, address, compress,  # noqa: E402
                    decompress, h, hashes, k256, lp, mul, recover, sha256)

HERE = Path(__file__).parent
T = lambda s: f'x402-response-encryption/v1/{s}'.encode()


class Reject(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def request_hash(req):
    return sha256(T('request') + lp(req['method']) + lp(canonical_url(req['url'])) + sha256(req['body'].encode()))


def recompute_commitment(ext, req):
    return k256(T('nonce') + h(ext['ephemeralPublicKey']) + h(ext['keyId']) + request_hash(req) + h(ext['nonceSalt']))


# ---- EIP-712 with nested structs (EIP-712 "encodeType" and "encodeData") ----
PERMIT2_TYPES = {
    'PermitWitnessTransferFrom': [('permitted', 'TokenPermissions'), ('spender', 'address'), ('nonce', 'uint256'),
                                  ('deadline', 'uint256'), ('witness', 'Witness')],
    'TokenPermissions': [('token', 'address'), ('amount', 'uint256')],
    'Witness': [('to', 'address'), ('validAfter', 'uint256')],
    'EIP712Domain': [('name', 'string'), ('chainId', 'uint256'), ('verifyingContract', 'address')],
}


def deps(name, types, found=None):
    found = found if found is not None else []
    for _, t in types[name]:
        if t in types and t not in found:
            found.append(t)
            deps(t, types, found)
    return found


def encode_type(name, types):
    fmt = lambda n: f"{n}({','.join(f'{t} {f}' for f, t in types[n])})"
    return fmt(name) + ''.join(fmt(d) for d in sorted(deps(name, types)))


def hash_struct(name, types, value):
    out = k256(encode_type(name, types).encode())
    for field, t in types[name]:
        v = value[field]
        if t in types:
            out += hash_struct(t, types, v)
        elif t == 'string':
            out += k256(v.encode())
        elif t == 'address':
            out += h(v).rjust(32, b'\0')
        elif t.startswith('uint'):
            out += int(v).to_bytes(32, 'big')
        else:
            raise ValueError(t)
    return k256(out)


def permit2_digest(domain, auth):
    message = {k: auth[k] for k in ('permitted', 'spender', 'nonce', 'deadline', 'witness')}
    return k256(b'\x19\x01' + hash_struct('EIP712Domain', PERMIT2_TYPES, domain)
                + hash_struct('PermitWitnessTransferFrom', PERMIT2_TYPES, message))


# ---- Solana ----
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\0' * (len(s) - len(s.lstrip('1'))) + body


def b58encode(b):
    n = int.from_bytes(b, 'big')
    out = ''
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + out


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError('truncated')
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def compact(self):
        n = shift = 0
        while True:
            b = self.u8()
            n |= (b & 0x7f) << shift
            if not b & 0x80:
                return n
            shift += 7


def parse_transaction(raw):
    rd = Reader(raw)
    sigs = [rd.take(64) for _ in range(rd.compact())]
    message = raw[rd.pos:]
    m = Reader(message)
    if m.u8() != 0x80:
        raise ValueError('only version-0 messages are used in these vectors')
    n_signers, _, _ = m.u8(), m.u8(), m.u8()
    keys = [m.take(32) for _ in range(m.compact())]
    m.take(32)  # recent blockhash
    ixs = []
    for _ in range(m.compact()):
        program = keys[m.u8()]
        accts = [keys[m.u8()] for _ in range(m.compact())]
        ixs.append({'program': program, 'accounts': accts, 'data': m.take(m.compact())})
    if m.compact() != 0:
        raise ValueError('address lookup tables are not used in these vectors')
    if m.pos != len(message):
        raise ValueError('trailing bytes')
    return {'signatures': sigs, 'message': message, 'signers': keys[:n_signers], 'instructions': ixs}


# ---- seller checks ----
def permit2_seller(vec, wire):
    auth = wire['payload']['permit2Authorization']
    digest = permit2_digest(vec['inputs']['permit2Domain'], auth)
    try:
        if recover(digest, h(wire['payload']['signature'])) != auth['from']:
            raise Reject('invalid_permit2_signature')
    except ValueError:
        raise Reject('invalid_permit2_signature')
    signed = int(auth['nonce']).to_bytes(32, 'big')
    if recompute_commitment(wire['extension'], wire['request']) != signed:
        raise Reject('response_encryption_nonce_mismatch')
    return digest


def svm_seller(vec, wire):
    tx = parse_transaction(base64.b64decode(wire['payload']['transaction']))
    progs = vec['inputs']['programs']
    token, memo_programs = b58decode(progs['token']), {b58decode(progs['memo']), b58decode(progs['memoV1'])}
    transfers = [ix for ix in tx['instructions'] if ix['program'] == token and ix['data'][:1] == bytes([12])]
    if len(transfers) != 1:
        raise ValueError('vector must hold one TransferChecked')
    owner = transfers[0]['accounts'][3]
    if owner not in tx['signers']:
        raise Reject('invalid_exact_svm_payload_signature_invalid')
    try:
        Ed25519PublicKey.from_public_bytes(owner).verify(tx['signatures'][tx['signers'].index(owner)], tx['message'])
    except InvalidSignature:
        raise Reject('invalid_exact_svm_payload_signature_invalid')
    # Extraction rule: exactly one top-level Memo instruction, 64 lowercase hex characters.
    memos = [ix for ix in tx['instructions'] if ix['program'] in memo_programs]
    if len(memos) != 1 or not re.fullmatch(rb'[0-9a-f]{64}', memos[0]['data']):
        raise Reject('response_encryption_nonce_mismatch')
    signed = bytes.fromhex(memos[0]['data'].decode())
    if recompute_commitment(wire['extension'], wire['request']) != signed:
        raise Reject('response_encryption_nonce_mismatch')
    return sha256(tx['message'])


# ---- vector checks ----
def check_envelope(vec, digest, fail):
    inp, mid, env = vec['inputs'], vec['intermediate'], vec['output']['envelope']
    e = int.from_bytes(h(inp['clientEphemeralPrivateKey']), 'big')
    m = int.from_bytes(h(inp['sellerEncryptionPrivateKey']), 'big')
    E, M = compress(mul(e, G)), compress(mul(m, G))
    key_id = k256(T('key-id') + M)
    req_hash = request_hash(inp['request'])
    c = k256(T('nonce') + E + key_id + req_hash + h(inp['nonceSalt']))
    Z = mul(e, decompress(M))[0].to_bytes(32, 'big')
    if Z != mul(m, decompress(E))[0].to_bytes(32, 'big'):
        fail.append('ECDH(e,M) != ECDH(m,E)')
    info = T('response') + E + M + key_id + lp(inp['network']) + req_hash
    K = HKDF(hashes.SHA256(), 32, digest, info).derive(Z)
    resp = inp['response']
    aad = T('aad') + bytes([env['version']]) + key_id + struct.pack('>H', resp['status']) + lp(resp['contentType'])
    got = {'clientEphemeralPublicKey': E, 'sellerEncryptionPublicKey': M, 'keyId': key_id, 'requestHash': req_hash,
           'commitment': c, 'authorizationDigest': digest, 'sharedSecretZ': Z, 'hkdfInfo': info, 'aesKey': K, 'aad': aad}
    for k, v in got.items():
        if '0x' + v.hex() != mid[k].lower():
            fail.append(f'{k}: expected {mid[k]} got 0x{v.hex()}')
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    unb64 = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    if env['ciphertext'] != b64(AESGCM(K).encrypt(h(inp['iv']), resp['body'].encode(), aad)):
        fail.append('envelope.ciphertext')
    try:
        if AESGCM(K).decrypt(unb64(env['iv']), unb64(env['ciphertext']), aad).decode() != resp['body']:
            fail.append('decrypts to response body')
    except InvalidTag:
        fail.append('decrypts to response body')
    return c, len(got)


def run(path, seller, extra_checks):
    vec = json.loads(Path(path).read_text())
    fail = []
    valid = next(cs for cs in vec['cases'] if cs['id'] == 'valid')
    digest = seller(vec, valid['wire'])
    c, n = check_envelope(vec, digest, fail)
    n += extra_checks(vec, c, fail)
    passed = 0
    for cs in vec['cases']:
        try:
            seller(vec, cs['wire'])
            got = None
        except Reject as err:
            got = err.reason
        want = cs['expect'] and cs['expect']['reason']
        if got == want:
            passed += 1
        else:
            fail.append(f"case {cs['id']}: expected {want} got {got}")
    print(f"{vec['profile']}: {n} values, {passed}/{len(vec['cases'])} cases")
    return fail


def permit2_extra(vec, c, fail):
    mid = vec['intermediate']
    payer = checksum(address(mul(int.from_bytes(h(vec['inputs']['payerPrivateKey']), 'big'), G)))
    if payer != mid['payerAddress']:
        fail.append('payerAddress')
    if str(int.from_bytes(c, 'big')) != mid['permit2Nonce']:
        fail.append('permit2Nonce is not c as uint256')
    # Permit2 builds the type string as this stub plus the witness type string that
    # x402ExactPermit2Proxy passes (WITNESS_TYPE_STRING); it must equal EIP-712 encodeType.
    proxy = ('PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,'
             'Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)')
    if encode_type('PermitWitnessTransferFrom', PERMIT2_TYPES) != proxy:
        fail.append('type string differs from Permit2 + x402ExactPermit2Proxy')
    return 3


def compact_u16(n):
    out = b''
    while True:
        b, n = n & 0x7f, n >> 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def expected_svm_message(inp, c):
    """Builds the version-0 message from the fixture, following the Solana message format:
    accounts ordered signed-writable, signed-read-only, unsigned-writable, unsigned-read-only."""
    ed = lambda seed: Ed25519PrivateKey.from_private_bytes(h(seed)).public_key().public_bytes_raw()
    acc, progs = inp['accounts'], inp['programs']
    keys = [ed(inp['feePayerSeed']), ed(inp['clientOwnerSeed']),                      # signed: writable, read-only
            b58decode(acc['sourceAta']), b58decode(acc['destinationAta']),           # unsigned writable
            b58decode(acc['mint']), b58decode(progs['token']), b58decode(progs['computeBudget']),
            b58decode(progs['memo']), b58decode(progs['memoV1'])]                     # unsigned read-only
    idx = lambda k: keys.index(k)
    cb, token = b58decode(progs['computeBudget']), b58decode(progs['token'])
    ixs = [
        (idx(cb), [], b'\x02' + struct.pack('<I', inp['computeUnitLimit'])),
        (idx(cb), [], b'\x03' + struct.pack('<Q', inp['computeUnitPriceMicrolamports'])),
        (idx(token), [2, 4, 3, 1], b'\x0c' + struct.pack('<Q', inp['amount']) + bytes([inp['decimals']])),
        (idx(b58decode(progs['memo'])), [], c.hex().encode()),
    ]
    body = b''.join(bytes([p]) + compact_u16(len(a)) + bytes(a) + compact_u16(len(d)) + d for p, a, d in ixs)
    return (bytes([0x80, 2, 1, 5]) + compact_u16(len(keys)) + b''.join(keys) + b58decode(inp['recentBlockhash'])
            + compact_u16(len(ixs)) + body + compact_u16(0))


def svm_extra(vec, c, fail):
    mid = vec['intermediate']
    seed = h(vec['inputs']['clientOwnerSeed'])
    owner = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    if b58encode(owner) != mid['clientOwner']:
        fail.append('clientOwner')
    if mid['memo'] != c.hex():
        fail.append('memo is not c in lowercase hex')
    tx = parse_transaction(base64.b64decode(next(cs for cs in vec['cases'] if cs['id'] == 'valid')['wire']['payload']['transaction']))
    if tx['message'] != expected_svm_message(vec['inputs'], c):
        fail.append('message differs from the one rebuilt from the fixture')
    if base64.b64encode(tx['message']).decode() != mid['message']:
        fail.append('message')
    if len(tx['signatures']) != 2:
        fail.append('signature count')
    if tx['signatures'][0] != b'\0' * 64 or b58encode(tx['signers'][0]) != mid['feePayer']:
        fail.append('fee payer slot must be the unsigned first signer')
    return 4


def main():
    fail = run(HERE / 'vector-permit2.json', permit2_seller, permit2_extra)
    fail += run(HERE / 'vector-svm.json', svm_seller, svm_extra)
    v1 = json.loads((HERE / 'vector-1.json').read_text())
    for name in ('vector-permit2.json', 'vector-svm.json'):
        if json.loads((HERE / name).read_text())['intermediate']['commitment'] != v1['intermediate']['nonce']:
            fail.append(f'{name}: commitment differs from the EIP-3009 nonce of vector-1')
    if fail:
        print('FAIL\n  ' + '\n  '.join(fail))
        sys.exit(1)
    print('OK: both profiles reproduced independently; c is identical across EIP-3009, Permit2 and SVM')


if __name__ == '__main__':
    main()
