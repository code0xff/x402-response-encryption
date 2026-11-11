"""Runs negative-cases.json through the protocol checks in order and asserts
each case is rejected at the expected stage with the expected reason.

Primitives come from verify.py; the checks below follow the proposal:
client-402 (4.1, 4.3; DID checks only in the did-web profile, 4.5), seller (3.1, 8), client-response (6.1-6.3).
"""
import base64
import json
import struct
import urllib.parse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify import (G, AESGCM, HKDF, InvalidTag, compress, decompress, h, hashes, k256, lp,  # noqa: E402
                    UrlError, canonical_url, mul, recover, sha256, typed_digest)

T = lambda s: f'x402-response-encryption/v1/{s}'.encode()
DOMAIN_712 = [('name', 'string'), ('version', 'string'), ('chainId', 'uint256')]
TOKEN_712 = DOMAIN_712 + [('verifyingContract', 'address')]
ATT_FIELDS = [('payTo', 'address'), ('keyId', 'bytes32'), ('publicKey', 'bytes'),
              ('notBefore', 'uint64'), ('notAfter', 'uint64')]
AUTH_FIELDS = [('from', 'address'), ('to', 'address'), ('value', 'uint256'),
               ('validAfter', 'uint256'), ('validBefore', 'uint256'), ('nonce', 'bytes32')]


class Reject(Exception):
    def __init__(self, stage, reason):
        super().__init__(f'{stage}/{reason}')
        self.stage, self.reason = stage, reason


def request_hash(req):
    return sha256(T('request') + lp(req['method']) + lp(canonical_url(req['url'])) + sha256(req['body'].encode()))


def auth_digest(ctx, auth):
    return typed_digest(TOKEN_712, ctx['tokenDomain'], 'TransferWithAuthorization', AUTH_FIELDS, auth)


def did_web_matches_resource(did, resource_url):
    """Proposal 4.5 step 1: the DID's host (and path, if any) must cover the URL the client requested."""
    parts = did.split(':')
    if parts[:2] != ['did', 'web'] or len(parts) < 3:
        return False
    host = urllib.parse.unquote(parts[2]).lower()
    path = '/'.join(urllib.parse.unquote(p) for p in parts[3:])
    canon = canonical_url(resource_url)
    rest = canon.split('://', 1)[1]
    r_host, _, r_path = rest.partition('/')
    if r_host != host:
        return False
    return not path or ('/' + r_path).startswith('/' + path + '/')


def jwk_to_compressed(jwk):
    if jwk.get('kty') != 'EC' or jwk.get('crv') != 'secp256k1':
        raise ValueError('not a secp256k1 JWK')
    unb = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    x, y = int.from_bytes(unb(jwk['x']), 'big'), int.from_bytes(unb(jwk['y']), 'big')
    return compress((x, y))


def check_did(info, att, doc, ctx, fail, requested_url):
    kid = info['kid']
    did, _, frag = kid.partition('#')
    if not did_web_matches_resource(did, requested_url):
        raise fail('response_encryption_did_origin_mismatch')
    if doc.get('id') != did or kid not in doc.get('keyAgreement', []):
        raise fail('response_encryption_did_key_not_found')
    methods = {m['id']: m for m in doc.get('verificationMethod', [])}
    method = methods.get(kid)
    if not method or frag != 'x402-re-' + info['keyId'].removeprefix('0x').lower():
        raise fail('response_encryption_did_key_not_found')
    try:
        if jwk_to_compressed(method['publicKeyJwk']) != h(info['publicKey']):
            raise fail('response_encryption_did_key_mismatch')
    except (KeyError, ValueError):
        raise fail('response_encryption_did_key_mismatch')
    accounts = {m.get('blockchainAccountId', '').lower() for m in methods.values()}
    if f"{ctx['network']}:{att['payTo']}".lower() not in accounts:
        raise fail('response_encryption_did_pay_to_mismatch')


def client_402(w, c, ctx, profile):
    info, att = w['paymentRequired'], w['paymentRequired']['attestation']
    fail = lambda r: Reject('client-402', r)
    if info.get('version') != 1:
        raise fail('response_encryption_unsupported_version')
    if info.get('suite') != 'secp256k1-hkdf-sha256-aes256gcm':
        raise fail('response_encryption_unsupported_suite')
    try:
        decompress(h(info['publicKey']))
    except ValueError:
        raise fail('response_encryption_invalid_public_key')
    if k256(T('key-id') + h(info['publicKey'])) != h(info['keyId']):
        raise fail('response_encryption_key_id_mismatch')
    chain_id = int(ctx['network'].split(':')[1])
    digest = typed_digest(DOMAIN_712, {'name': 'x402-response-encryption', 'version': '1', 'chainId': chain_id},
                          'EncryptionKeyAttestation', ATT_FIELDS,
                          {'payTo': att['payTo'], 'keyId': info['keyId'], 'publicKey': info['publicKey'],
                           'notBefore': att['notBefore'], 'notAfter': att['notAfter']})
    try:
        signer = recover(digest, h(att['signature']))
    except ValueError:
        signer = None
    if signer != att['payTo']:
        raise fail('response_encryption_attestation_invalid')
    if not att['notBefore'] <= c['now'] <= att['notAfter']:
        raise fail('response_encryption_attestation_expired')
    # The attested key must belong to the address the client signs the payment to.
    if att['payTo'].lower() != w['paymentRequirements']['payTo'].lower():
        raise fail('response_encryption_pay_to_mismatch')
    if profile == 'did-web':
        check_did(info, att, c['didDocument'], ctx, fail, c['request']['url'])


def seller(w, mer, ctx):
    """Returns the stored envelope when the payload repeats a settled authorization
    (proposal 8.1), otherwise None after all pre-settlement checks pass."""
    p, fail = w['paymentPayload'], lambda r: Reject('seller', r)
    ext, auth = (p['extension'] or {}).get('info'), p['authorization']
    if not ext:
        raise fail('response_encryption_extension_missing')
    if ext.get('version') != 1:
        raise fail('response_encryption_unsupported_version')
    stored = mer.get('stored', {}).get(auth['nonce'].lower())
    # A retry may name a key rotated out since settlement; the stored envelope does not need it.
    if stored is None and ext['keyId'] not in mer['keyIds']:
        raise fail('response_encryption_unknown_key_id')
    try:
        signer = recover(auth_digest(ctx, auth), h(p['signature']))
    except ValueError:
        signer = None
    if signer != auth['from']:
        raise fail('invalid_exact_evm_payload_signature')
    try:
        E = decompress(h(ext['ephemeralPublicKey']))
    except ValueError:
        raise fail('response_encryption_invalid_ephemeral_key')
    try:
        rh = request_hash(w['request'])
    except UrlError:
        raise fail('response_encryption_invalid_url')
    nonce = k256(T('nonce') + compress(E) + h(ext['keyId']) + rh + h(ext['nonceSalt']))
    if nonce != h(auth['nonce']):
        raise fail('response_encryption_nonce_mismatch')
    return stored


def client_response(w, c, ctx):
    info, env = w['paymentRequired'], w['envelope']
    e = int.from_bytes(h(c['ephemeralPrivateKey']), 'big')
    M = decompress(h(info['publicKey']))
    keyId, rh = h(info['keyId']), request_hash(c['request'])
    Z = mul(e, M)[0].to_bytes(32, 'big')
    info_bytes = T('response') + compress(mul(e, G)) + compress(M) + keyId + lp(ctx['network']) + rh
    K = HKDF(hashes.SHA256(), 32, auth_digest(ctx, c['authorization']), info_bytes).derive(Z)
    aad = (T('aad') + bytes([env['version']]) + h(env['keyId'])
           + struct.pack('>H', env['status']) + lp(env['contentType']))

    unb64 = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    try:
        return AESGCM(K).decrypt(unb64(env['iv']), unb64(env['ciphertext']), aad).decode()
    except (InvalidTag, ValueError):
        raise Reject('client-response', 'response_encryption_decrypt_failed')


def run(case, ctx):
    """Returns the first rejection, or None. An expectation with reason None and a
    stage means "passes up to and including that stage" (only the core full-swap case)."""
    w, c, want = case['wire'], case['client'], case['expect']
    try:
        client_402(w, c, ctx, case['profile'])
        if want and want['stage'] == 'client-402' and want['reason'] is None:
            return want
        resent = seller(w, case.get('seller', ctx['seller']), ctx)
        client_response({**w, 'envelope': resent} if resent else w, c, ctx)
    except Reject as r:
        return {'stage': r.stage, 'reason': r.reason}
    return None


def main(path):
    ctx = json.loads(Path(path).read_text())
    bad = 0
    for case in ctx['cases']:
        got, want = run(case, ctx), case['expect']
        ok = got == want
        bad += not ok
        show = lambda x: 'accepted' if x is None else (f"passes {x['stage']}" if x['reason'] is None else f"{x['stage']}/{x['reason']}")
        print(f"{'ok  ' if ok else 'FAIL'} {case['profile']:8} {case['id']:34} {show(got)}" + ('' if ok else f'  (expected {show(want)})'))
    print(f"\n{len(ctx['cases']) - bad}/{len(ctx['cases'])} cases as expected")
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name('negative-cases.json'))
