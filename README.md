# x402 Response Encryption

A proposed [x402](https://github.com/x402-foundation/x402) extension that lets only the paying client read a paid response.

An x402 response usually crosses CDNs, reverse proxies, API gateways or marketplaces that terminate TLS and can log or cache it in plaintext. With this extension the seller encrypts the response body to a per-request ephemeral key that the client commits into the EIP-3009 payment `nonce`. The seller's encryption key carries an attestation signed by `payTo`. An intermediary cannot swap either key without breaking the payment signature or redirecting the payment on-chain.

Status: design draft. Nothing here has been adopted into the x402 specification.

## Contents

| Path | What it is |
| --- | --- |
| [`docs/response-encryption-proposal.md`](docs/response-encryption-proposal.md) | The proposal: threat model, key binding, cryptographic construction, message formats, errors, key rotation, retries, optional did:web profile |
| [`schemas/`](schemas/) | JSON Schemas (draft 2020-12) for the extension messages |
| [`packages/core/`](packages/core/) | TypeScript implementation of the primitives: URL canonicalization, nonce binding, key attestation, envelope encryption. Tested against the shared vectors |
| [`packages/express/`](packages/express/) | Express middleware for both deployments: a seller running `@x402/express` itself, or an origin behind a payment gateway that runs x402. Checks the binding before settlement, encrypts, stores envelopes for retries |
| [`packages/fetch/`](packages/fetch/) | Client `fetch` wrapper: verifies the seller key, signs an EIP-3009 authorization with the binding nonce, decrypts, refuses plaintext |
| [`test-vectors/`](test-vectors/) | Test vectors generated in TypeScript and an independent Python verifier |

## Verifying the test vectors

The Python verifier shares no code with the generator. It implements secp256k1 arithmetic, EIP-712 encoding and signer recovery from the specifications.

```sh
cd test-vectors
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

.venv/bin/python -I verify.py vector-1.json        # valid exchange, every intermediate value
.venv/bin/python -I verify_cases.py                # 37 tampering cases, each rejected at the expected check
.venv/bin/python -I canonical_url.py url-cases.json  # 35 URL canonicalization cases
.venv/bin/python -I validate_schemas.py            # messages against schemas/
.venv/bin/python -I verify_profiles.py             # Permit2 and SVM profile vectors and their tampering cases
```

The TypeScript packages run the same vectors, plus end-to-end tests with the real `@x402/express` middleware and an in-process facilitator: one with the seller behind a logging reverse proxy, one with a payment gateway that issues the 402 and relays to the origin:

```sh
npm install
npm test
```

## Scope of the implementation

The packages are a reference implementation for evaluating the proposal, not production middleware. They show that the protocol works with the real x402 SDK and catch the attacks in section 10 of the proposal. Production concerns are left out: locks shared across workers, persistence failures and crash recovery, request size limits, and eviction in the in-memory envelope store.

## Running on Base Sepolia

`examples/base-sepolia` makes one paid, encrypted request through a logging reverse proxy and settles it on Base Sepolia with an in-process facilitator from the x402 SDK. It needs a `.env` at the repository root with `CLIENT_PRIVATE_KEY` (holding test USDC), `PAYTO_PRIVATE_KEY` (holding a little Base Sepolia ETH for settlement gas) and `SELLER_ENCRYPTION_PRIVATE_KEY`. Set `FACILITATOR_URL` to use a hosted facilitator instead.

```sh
npm run demo
```

It prints the decrypted body, the settlement transaction, everything the proxy recorded, and whether any plaintext appeared there.

To regenerate the vectors (requires Node.js 20 or later):

```sh
cd test-vectors
npm install
npm run generate      # vector-1.json, negative-cases.json, did-document.json
npm run generate:urls # url-cases.json
npm run generate:profiles  # vector-permit2.json, vector-svm.json
```

`vector-1.json` is deterministic. All private keys in it are test-only values derived from fixed labels.

## Status

The design is ready for review and is proposed in [x402-foundation/x402#4223](https://github.com/x402-foundation/x402/issues/4223); discussion happens there. The TypeScript packages settle real payments on Base Sepolia through the x402 SDK, with no plaintext reaching the intermediary. Open items are listed in section 11 of the proposal.

## License

[Apache License 2.0](LICENSE)
