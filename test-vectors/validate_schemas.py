"""Checks the generated messages against schemas/*.schema.json.

Every case that is not rejected for a format reason must produce schema-valid
messages; a few hand-made malformed messages must be rejected.
"""
import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = {p.name.removesuffix('.schema.json'): Draft202012Validator(json.loads(p.read_text()))
           for p in (ROOT / 'schemas').glob('*.schema.json')}
for v in SCHEMAS.values():
    Draft202012Validator.check_schema(v.schema)

# Cases whose tampering is a format violation the schema itself is expected to catch.
FORMAT_CASES = {'unsupported-version', 'unsupported-suite', 'extension-missing'}


def messages(wire):
    pr = {k: v for k, v in wire['paymentRequired'].items() if k != 'resource'}
    ext = wire['paymentPayload']['extension']
    # Retry cases carry no envelope on the wire: the seller resends its stored copy.
    return [('payment-required-info', pr),
            ('payment-payload-info', ext and ext['info']),
            *([('envelope', wire['envelope'])] if wire['envelope'] is not None else [])]


def errors(name, doc):
    return [e.message for e in SCHEMAS[name].iter_errors(doc)] if doc is not None else ['missing']


def main():
    cases = json.loads((Path(__file__).parent / 'negative-cases.json').read_text())['cases']
    bad = 0
    for c in cases:
        found = {n: errors(n, d) for n, d in messages(c['wire'])}
        invalid = {n: e for n, e in found.items() if e}
        expected_invalid = c['id'] in FORMAT_CASES
        if bool(invalid) != expected_invalid:
            bad += 1
            print(f"FAIL {c['id']}: {'unexpected errors ' + str(invalid) if invalid else 'expected a schema error'}")

    valid = next(c for c in cases if c['id'] == 'valid')['wire']
    pr = {k: v for k, v in valid['paymentRequired'].items() if k != 'resource'}
    malformed = [
        ('payment-required-info', {**pr, 'publicKey': '0x04' + '00' * 64}, 'uncompressed key'),
        ('payment-required-info', {**pr, 'kid': 'did:web:api.seller.example#key-1'}, 'kid fragment'),
        ('payment-required-info', {**pr, 'extra': 1}, 'unknown property'),
        ('payment-payload-info', {**valid['paymentPayload']['extension']['info'], 'nonceSalt': '0x1234'}, 'short salt'),
        ('envelope', {**valid['envelope'], 'iv': valid['envelope']['iv'] + '='}, 'padded base64url'),
        ('envelope', {**valid['envelope'], 'status': 402}, 'non-2xx status'),
        ('error-info', {'errorReason': 'something_else'}, 'unknown error code'),
    ]
    for name, doc, label in malformed:
        if not errors(name, copy.deepcopy(doc)):
            bad += 1
            print(f'FAIL malformed {label}: accepted by {name}')
    if errors('error-info', {'errorReason': 'response_encryption_nonce_mismatch'}):
        bad += 1
        print('FAIL error-info rejects a valid code')
    # A rejection 402 is the key info plus errorReason (7.4); the retry echoes it without the error fields (7.2).
    rejection = {**pr, 'errorReason': 'response_encryption_unknown_key_id', 'errorMessage': 'key rotated'}
    if errors('payment-required-info', rejection):
        bad += 1
        print('FAIL payment-required-info rejects a rejection 402')
    if not errors('payment-payload-info', {**valid['paymentPayload']['extension']['info'], 'errorReason': rejection['errorReason']}):
        bad += 1
        print('FAIL payment-payload-info accepts an echoed errorReason')

    total = len(cases) + len(malformed) + 3
    print(f'{total - bad}/{total} schema checks as expected')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
