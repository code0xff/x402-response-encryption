"""URL canonicalization for requestHash (proposal 3.3), written from the rule text."""
import json
import re
import sys
from pathlib import Path

UNRESERVED = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')
PCHAR = UNRESERVED | set(b"!$&'()*+,;=:@")
PATH_OK = PCHAR | {ord('/')}
QUERY_KEY_OK = (PCHAR - set(b'&=')) | set(b'/?')
QUERY_VAL_OK = (PCHAR - set(b'&')) | set(b'/?')
HEX = set(b'0123456789abcdefABCDEF')


class UrlError(ValueError):
    pass


def norm_percent(s, ok):
    raw, out, i = s.encode('utf-8'), [], 0
    while i < len(raw):
        b = raw[i]
        if b == 0x25:  # '%'
            pair = raw[i + 1:i + 3]
            if len(pair) != 2 or not set(pair) <= HEX:
                raise UrlError('url_invalid_percent_encoding')
            v = int(pair, 16)
            out.append(chr(v) if v in UNRESERVED else '%' + pair.decode().upper())
            i += 3
        elif b in ok:
            out.append(chr(b))
            i += 1
        else:
            out.append('%%%02X' % b)
            i += 1
    return ''.join(out)


def remove_dot_segments(path):
    out = []
    for seg in path.split('/')[1:]:
        if seg == '..':
            if out:
                out.pop()
        elif seg != '.':
            out.append(seg)
    trailing = path.endswith(('/.', '/..'))
    return '/' + '/'.join(out) + ('/' if trailing and out else '')


def canonical_url(url):
    m = re.fullmatch(r'(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?', url, re.S)
    if not m or not m.group(2) or m.group(3) is None:
        raise UrlError('url_not_absolute')
    scheme = m.group(2).lower()
    if scheme not in ('https', 'http'):
        raise UrlError('url_unsupported_scheme')

    authority = m.group(4)
    if '@' in authority:
        raise UrlError('url_userinfo_not_allowed')
    if any(not 0x21 <= ord(c) <= 0x7E for c in authority):
        raise UrlError('url_non_ascii_host')
    am = re.fullmatch(r'(\[[0-9A-Fa-f:.]+\]|[^:\[\]]+)(:([0-9]*))?', authority)
    if not am:
        raise UrlError('url_invalid_authority')
    host = am.group(1).lower().removesuffix('.')
    if not host:
        raise UrlError('url_invalid_authority')
    port = am.group(3) or ''
    if port:
        n = int(port)
        if n > 65535:
            raise UrlError('url_invalid_port')
        port = '' if (scheme, n) in (('https', 443), ('http', 80)) else str(n)

    raw_path = m.group(5)
    for seg in raw_path.split('/'):
        if '%2e' in seg.lower() and re.fullmatch(r'(\.|%2[eE]){1,2}', seg):
            raise UrlError('url_encoded_dot_segment')
    path = norm_percent(raw_path, PATH_OK)
    if not path.startswith('/'):
        path = '/' + path
    path = remove_dot_segments(path)

    query = ''
    if m.group(7):
        pairs = []
        for piece in m.group(7).split('&'):
            if not piece:
                continue
            k, sep, v = piece.partition('=')
            pairs.append((norm_percent(k, QUERY_KEY_OK), norm_percent(v, QUERY_VAL_OK) if sep else None))
        query = '&'.join(k if v is None else f'{k}={v}' for k, v in pairs)

    return f"{scheme}://{host}{':' + port if port else ''}{path}{'?' + query if query else ''}"


def main(path):
    cases = json.loads(Path(path).read_text())['cases']
    bad = 0
    for c in cases:
        try:
            got = {'canonical': canonical_url(c['input'])}
        except UrlError as e:
            got = {'error': str(e)}
        want = {k: c[k] for k in ('canonical', 'error') if k in c}
        if got != want:
            bad += 1
            print(f"FAIL {c['description']}: {c['input']!r} expected {want} got {got}")
    print(f'{len(cases) - bad}/{len(cases)} URL cases as expected')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name('url-cases.json'))
