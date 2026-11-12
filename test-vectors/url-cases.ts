import { writeFileSync } from 'node:fs';
import { canonicalUrl, UrlError } from './canonical-url.js';

const inputs: [string, string][] = [
  ['already canonical', 'https://api.seller.example/v1/report?id=42'],
  ['scheme and host case', 'HTTPS://API.Seller.Example/v1/report'],
  ['default https port', 'https://api.seller.example:443/v1/report'],
  ['default http port', 'http://localhost:80/v1/report'],
  ['non-default port kept', 'https://api.seller.example:8443/v1/report'],
  ['port leading zeros', 'https://api.seller.example:0443/v1/report'],
  ['empty port', 'https://api.seller.example:/v1/report'],
  ['trailing dot in host', 'https://api.seller.example./v1/report'],
  ['empty path', 'https://api.seller.example'],
  ['empty path with query', 'https://api.seller.example?b=2&a=1'],
  ['dot segments', 'https://api.seller.example/v1/./tmp/../report'],
  ['leading dot-dot', 'https://api.seller.example/../v1/report'],
  ['percent-encoded unreserved decoded', 'https://api.seller.example/%7Euser/%41bc'],
  ['percent hex uppercased', 'https://api.seller.example/a%2fb?q=%e2%82%ac'],
  ['encoded dot segment rejected', 'https://api.seller.example/v1/%2E%2E/report'],
  ['encoded single dot rejected', 'https://api.seller.example/v1/%2e/report'],
  ['encoded dots inside segment kept', 'https://api.seller.example/v1/a%2Eb/%2E%2E%2E'],
  ['raw space and unicode encoded', 'https://api.seller.example/a b/€'],
  ['trailing slash preserved', 'https://api.seller.example/v1/report/'],
  ['double slash preserved', 'https://api.seller.example/v1//report'],
  ['query order preserved', 'https://api.seller.example/r?z=1&a=2&m=3'],
  ['repeated keys keep position', 'https://api.seller.example/r?a=2&b=1&a=1'],
  ['empty query dropped', 'https://api.seller.example/r?'],
  ['empty pairs dropped', 'https://api.seller.example/r?a=1&&b=2&'],
  ['key without value', 'https://api.seller.example/r?flag&a=1'],
  ['plus kept literal', 'https://api.seller.example/r?q=a+b'],
  ['equals inside value', 'https://api.seller.example/r?q=a=b'],
  ['fragment dropped', 'https://api.seller.example/r?a=1#section'],
  ['ipv6 host', 'https://[2001:DB8::1]:443/r'],
  ['userinfo rejected', 'https://user:pw@api.seller.example/r'],
  ['non-ascii host rejected', 'https://bücher.example/r'],
  ['bad percent rejected', 'https://api.seller.example/a%zz'],
  ['unsupported scheme rejected', 'ftp://api.seller.example/r'],
  ['relative url rejected', '/v1/report'],
  ['port out of range rejected', 'https://api.seller.example:70000/r'],
];

const cases = inputs.map(([description, input]) => {
  try {
    return { description, input, canonical: canonicalUrl(input) };
  } catch (err) {
    if (!(err instanceof UrlError)) throw err;
    return { description, input, error: err.message };
  }
});

writeFileSync(new URL('./url-cases.json', import.meta.url), JSON.stringify({ cases }, null, 2) + '\n');
for (const c of cases) console.log(`${c.description.padEnd(38)} ${c.input}\n${''.padEnd(38)} -> ${c.canonical ?? 'ERROR ' + c.error}`);
