// URL canonicalization for requestHash (proposal 3.3). Written from RFC 3986;
// deliberately does not use the WHATWG URL parser, whose fixups are not part of the rule.
import { utf8Bytes } from './bytes.js';
import { ResponseEncryptionError } from './errors.js';

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const PCHAR_EXTRA = "!$&'()*+,;=:@";
const PATH_ALLOWED = PCHAR_EXTRA + '/';
const QUERY_KEY_ALLOWED = "!$'()*+,;:@/?";
const QUERY_VALUE_ALLOWED = "!$'()*+,;=:@/?";

const fail = (reason: ConstructorParameters<typeof ResponseEncryptionError>[0]) => new ResponseEncryptionError(reason);

function normalizePercent(s: string, allowed: string): string {
  let out = '';
  for (let i = 0; i < s.length; ) {
    const ch = s[i]!;
    if (ch === '%') {
      const hx = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hx)) throw fail('url_invalid_percent_encoding');
      const c = String.fromCharCode(parseInt(hx, 16));
      out += UNRESERVED.test(c) ? c : '%' + hx.toUpperCase();
      i += 3;
    } else if (UNRESERVED.test(ch) || allowed.includes(ch)) {
      out += ch;
      i += 1;
    } else {
      const cp = s.codePointAt(i)!;
      for (const b of utf8Bytes(String.fromCodePoint(cp))) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
      i += cp > 0xffff ? 2 : 1;
    }
  }
  return out;
}

// RFC 3986 5.2.4
function removeDotSegments(path: string): string {
  let input = path;
  let output = '';
  const popSegment = () => {
    output = output.slice(0, Math.max(0, output.lastIndexOf('/')));
  };
  while (input.length) {
    if (input.startsWith('../')) input = input.slice(3);
    else if (input.startsWith('./')) input = input.slice(2);
    else if (input.startsWith('/./')) input = input.slice(2);
    else if (input === '/.') input = '/';
    else if (input.startsWith('/../')) {
      input = input.slice(3);
      popSegment();
    } else if (input === '/..') {
      input = '/';
      popSegment();
    } else if (input === '.' || input === '..') input = '';
    else {
      const next = input.indexOf('/', input.startsWith('/') ? 1 : 0);
      const end = next === -1 ? input.length : next;
      output += input.slice(0, end);
      input = input.slice(end);
    }
  }
  return output;
}

/** Canonical form of an absolute http(s) URL. Throws ResponseEncryptionError with a url_* reason. */
export function canonicalUrl(url: string): string {
  // RFC 3986 Appendix B
  const m = /^(([^:/?#]+):)?(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$/s.exec(url);
  if (!m || !m[2] || m[3] === undefined) throw fail('url_not_absolute');
  const scheme = m[2].toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') throw fail('url_unsupported_scheme');

  const authority = m[4] ?? '';
  if (authority.includes('@')) throw fail('url_userinfo_not_allowed');
  if (/[^\x21-\x7e]/.test(authority)) throw fail('url_non_ascii_host');
  const am = /^(\[[0-9A-Fa-f:.]+\]|[^:[\]]+)(:([0-9]*))?$/.exec(authority);
  if (!am) throw fail('url_invalid_authority');
  let host = am[1]!.toLowerCase();
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (!host) throw fail('url_invalid_authority');
  let port = am[3] ?? '';
  if (port) {
    const n = Number(port);
    if (n > 65535) throw fail('url_invalid_port');
    port = (scheme === 'https' && n === 443) || (scheme === 'http' && n === 80) ? '' : String(n);
  }

  // A percent-encoded dot segment may be routed literally by the server but would
  // collapse under normalization, so two different routes could share a hash.
  const rawPath = m[5] ?? '';
  if (rawPath.split('/').some((seg) => /%2e/i.test(seg) && /^(\.|%2e){1,2}$/i.test(seg))) {
    throw fail('url_encoded_dot_segment');
  }
  let path = removeDotSegments(normalizePercent(rawPath, PATH_ALLOWED)) || '/';
  if (!path.startsWith('/')) path = '/' + path;

  let query = '';
  if (m[7]) {
    const pairs = m[7]
      .split('&')
      .filter(Boolean)
      .map((piece): [string, string | null] => {
        const eq = piece.indexOf('=');
        const k = normalizePercent(eq === -1 ? piece : piece.slice(0, eq), QUERY_KEY_ALLOWED);
        const v = eq === -1 ? null : normalizePercent(piece.slice(eq + 1), QUERY_VALUE_ALLOWED);
        return [k, v];
      });
    query = pairs.map(([k, v]) => (v === null ? k : `${k}=${v}`)).join('&');
  }

  return `${scheme}://${host}${port ? ':' + port : ''}${path}${query ? '?' + query : ''}`;
}
