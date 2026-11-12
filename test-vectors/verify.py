"""Independent Python check of vector-1.json.

Shares no code with generate.ts. secp256k1 arithmetic, EIP-712 encoding and
signature recovery are written here from the specs; only keccak256 (pycryptodome)
and HKDF / AES-GCM (cryptography) come from libraries.
"""
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

from Crypto.Hash import keccak
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).parent))
from canonical_url import UrlError, canonical_url  # noqa: E402

# ---- secp256k1 ----
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = add(out, pt)
        pt = add(pt, pt)
        k >>= 1
    return out


def lift_x(x, odd):
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if (y * y - x**3 - 7) % P:
        raise ValueError('point not on curve')
    return x, (y if (y & 1) == odd else P - y)


def compress(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


def decompress(b):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError('bad compressed point')
    return lift_x(int.from_bytes(b[1:], 'big'), b[0] - 2)


# ---- hashing helpers ----
def k256(b):
    return keccak.new(digest_bits=256, data=b).digest()


def sha256(b):
    return hashlib.sha256(b).digest()


def h(s):
    return bytes.fromhex(s.removeprefix('0x'))


def lp(s):
    b = s.encode()
    return struct.pack('>I', len(b)) + b


def address(pt):
    return k256(pt[0].to_bytes(32, 'big') + pt[1].to_bytes(32, 'big'))[-20:]


def checksum(addr):
    hx = addr.hex()
    d = k256(hx.encode()).hex()
    return '0x' + ''.join(c.upper() if int(d[i], 16) >= 8 else c for i, c in enumerate(hx))


# ---- EIP-712 (only the field types used here) ----
def enc_value(typ, v):
    if typ == 'string':
        return k256(v.encode())
    if typ == 'bytes':
        return k256(h(v))
    if typ == 'bytes32':
        return h(v)
    if typ == 'address':
        return h(v).rjust(32, b'\0')
    if typ.startswith('uint'):
        return int(v).to_bytes(32, 'big')
    raise ValueError(typ)


def struct_hash(name, fields, values):
    type_str = f"{name}({','.join(f'{t} {n}' for n, t in fields)})"
    return k256(k256(type_str.encode()) + b''.join(enc_value(t, values[n]) for n, t in fields))


def typed_digest(domain_fields, domain, name, fields, message):
    sep = struct_hash('EIP712Domain', domain_fields, domain)
    return k256(b'\x19\x01' + sep + struct_hash(name, fields, message))


def recover(digest, sig):
    r, s, v = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:64], 'big'), sig[64]
    if v not in (27, 28) or not (0 < r < N and 0 < s < N):
        raise ValueError('bad signature')
    R = lift_x(r, v - 27)
    z = int.from_bytes(digest, 'big')
    rinv = pow(r, -1, N)
    Q = add(mul(s * rinv % N, R), mul((-z * rinv) % N, G))
    return checksum(address(Q))


# ---- vector ----
def main(path):
    vec = json.loads(Path(path).read_text())
    inp, mid, out = vec['inputs'], vec['intermediate'], vec['output']['envelope']
    got = {}
    T = lambda s: f'x402-response-encryption/v1/{s}'.encode()

    e = int.from_bytes(h(inp['clientEphemeralPrivateKey']), 'big')
    m = int.from_bytes(h(inp['sellerEncryptionPrivateKey']), 'big')
    E, M = mul(e, G), mul(m, G)
    got['clientEphemeralPublicKey'] = compress(E)
    got['sellerEncryptionPublicKey'] = compress(M)
    got['payerAddress'] = checksum(address(mul(int.from_bytes(h(inp['payerPrivateKey']), 'big'), G)))
    got['payToAddress'] = checksum(address(mul(int.from_bytes(h(inp['payToPrivateKey']), 'big'), G)))

    req = inp['request']
    got['requestBodySha256'] = sha256(req['body'].encode())
    got['requestHash'] = sha256(T('request') + lp(req['method']) + lp(canonical_url(req['url'])) + got['requestBodySha256'])
    got['keyId'] = k256(T('key-id') + compress(M))
    got['nonce'] = k256(T('nonce') + compress(E) + got['keyId'] + got['requestHash'] + h(inp['nonceSalt']))

    chain_id = int(inp['network'].split(':')[1])
    att_fields = [('payTo', 'address'), ('keyId', 'bytes32'), ('publicKey', 'bytes'),
                  ('notBefore', 'uint64'), ('notAfter', 'uint64')]
    att_msg = {'payTo': got['payToAddress'], 'keyId': '0x' + got['keyId'].hex(),
               'publicKey': '0x' + compress(M).hex(), **inp['attestation']}
    got['attestationDigest'] = typed_digest(
        [('name', 'string'), ('version', 'string'), ('chainId', 'uint256')],
        {'name': 'x402-response-encryption', 'version': '1', 'chainId': chain_id},
        'EncryptionKeyAttestation', att_fields, att_msg)

    auth_fields = [('from', 'address'), ('to', 'address'), ('value', 'uint256'),
                   ('validAfter', 'uint256'), ('validBefore', 'uint256'), ('nonce', 'bytes32')]
    auth_msg = {**inp['authorization'], 'nonce': '0x' + got['nonce'].hex()}
    got['authorizationDigest'] = typed_digest(
        [('name', 'string'), ('version', 'string'), ('chainId', 'uint256'), ('verifyingContract', 'address')],
        inp['tokenDomain'], 'TransferWithAuthorization', auth_fields, auth_msg)

    # Recovery checks the signatures in the vector against independently computed digests.
    att_signer = recover(got['attestationDigest'], h(mid['attestationSignature']))
    auth_signer = recover(got['authorizationDigest'], h(mid['authorizationSignature']))

    Z1, Z2 = mul(e, M), mul(m, E)
    got['sharedSecretZ'] = Z1[0].to_bytes(32, 'big')
    got['hkdfInfo'] = (T('response') + compress(E) + compress(M) + got['keyId']
                       + lp(inp['network']) + got['requestHash'])
    got['aesKey'] = HKDF(hashes.SHA256(), 32, got['authorizationDigest'], got['hkdfInfo']).derive(got['sharedSecretZ'])

    resp = inp['response']
    got['aad'] = T('aad') + bytes([out['version']]) + got['keyId'] + struct.pack('>H', resp['status']) + lp(resp['contentType'])
    iv = h(inp['iv'])
    ct = AESGCM(got['aesKey']).encrypt(iv, resp['body'].encode(), got['aad'])

    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    unb64 = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    try:
        plain = AESGCM(got['aesKey']).decrypt(unb64(out['iv']), unb64(out['ciphertext']), got['aad']).decode()
    except InvalidTag:
        plain = None

    fail = []
    for k, v in got.items():
        v = v if isinstance(v, str) else '0x' + v.hex()
        if v.lower() != mid[k].lower():
            fail.append(f'{k}: expected {mid[k]} got {v}')
    extra = {
        'ECDH(e,M) == ECDH(m,E)': Z1 == Z2,
        'attestation signer == payTo': att_signer == got['payToAddress'],
        'authorization signer == payer': auth_signer == got['payerAddress'],
        'envelope.keyId': out['keyId'].lower() == '0x' + got['keyId'].hex(),
        'envelope.iv': out['iv'] == b64(iv),
        'envelope.ciphertext': out['ciphertext'] == b64(ct),
        'decrypts to response body': plain == resp['body'],
    }
    fail += [k for k, ok in extra.items() if not ok]

    print(f'{len(got)} intermediate values, {len(extra)} extra checks')
    if fail:
        print('FAIL\n  ' + '\n  '.join(fail))
        sys.exit(1)
    print('OK: vector reproduced independently')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name('vector-1.json'))
