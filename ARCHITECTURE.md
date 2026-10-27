# Architecture

`@axlabs/venice-e2ee` is a standalone, dependency-light TypeScript library that
implements the end-to-end encryption (E2EE) protocol used by
[Venice AI](https://venice.ai)'s TEE-backed inference. It is designed to run in
both browsers (Web Crypto + ESM) and Node.js with no bundler required.

## Background

Venice AI runs LLM inference inside Intel TDX Trusted Execution Environments
(TEEs). The E2EE protocol ensures prompts are encrypted on the client and only
decrypted inside the TEE, so the provider never sees plaintext.

The cryptographic flow is:

```
ECDH (secp256k1) key exchange
  → HKDF-SHA256 key derivation
    → AES-256-GCM encryption
```

Streaming responses use per-chunk ephemeral keys: each response chunk carries
its own server ephemeral public key, nonce, and ciphertext, so every chunk is
derived and decrypted independently.

## Module layout

| Module | Responsibility |
|--------|----------------|
| `crypto.ts` | Key generation, ECDH + HKDF key derivation, AES-256-GCM encrypt/decrypt, hex helpers |
| `attestation.ts` | TDX quote parsing and binding checks (nonce, signing-key address, debug-mode rejection, server cross-check) |
| `dcap.ts` | Optional adapter for full DCAP quote verification via an injectable verifier |
| `stream.ts` | Server-Sent Events parser that yields decrypted text, tool-call deltas, and finish reasons |
| `index.ts` | Public `createVeniceE2EE` factory, session lifecycle, and re-exports |
| `types.ts` | Shared public types |

## Public API

```ts
import { createVeniceE2EE } from '@axlabs/venice-e2ee';

const e2ee = createVeniceE2EE({ apiKey: '...' });

// Create a session: fetches attestation, verifies the TEE, derives keys.
const session = await e2ee.createSession(modelId);

// Encrypt messages for the Venice API.
const { encryptedMessages, headers, veniceParameters } =
  await e2ee.encrypt(messages, session);

// Decrypt a streaming response.
for await (const event of e2ee.decryptStream(responseBody, session)) {
  // event.kind is 'content' | 'tool_calls' | 'finish'
}

// Session management.
e2ee.clearSession();
```

Sessions are cached per model with a configurable TTL (30 minutes by default).
Private keys are zeroized when a session is cleared or replaced, and ECDH
intermediates are zeroized immediately after key derivation.

## Dependencies

- [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) — ECDH key exchange
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — Keccak-256 for Ethereum address derivation
- Web Crypto API — HKDF and AES-256-GCM (browser-native, zero dependencies)
- [`@phala/dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) — **optional** peer dependency for full DCAP verification

No Node.js-specific APIs are used in the core paths, so the library runs
unchanged in modern browsers.

## Attestation verification

Venice runs on **Intel TDX**. The attestation endpoint returns a TDX DCAP quote
with a PCK certificate chain. Verification is layered:

### Level 1 — Quote parsing and binding checks (always on)

1. Parse the TDX quote and verify the client nonce in `REPORTDATA` (bytes 32–63), accepting either the raw nonce or its SHA-256.
2. Verify the signing key's Ethereum address in `REPORTDATA` (bytes 0–19).
3. Reject debug-mode TEEs (`TD_ATTRIBUTES` debug bit).
4. Cross-check the provider's own `server_verification` result for inconsistencies.

### Level 2 — Full client-side DCAP verification (optional)

When a DCAP verifier is injected (`createVeniceE2EE({ dcapVerifier })`):

1. Verify the PCK certificate chain up to the pinned Intel SGX Root CA.
2. Verify the QE report and quote signatures.
3. Evaluate the TCB level and reject revoked platforms.

### Future work

- TEE code-measurement (MRTD/RTMR) whitelisting once expected values are published.
- NVIDIA GPU attestation.
- CRL freshness policies and event-log replay.

> **Important:** Level 1 binding checks confirm that fields *inside* a quote
> match client-supplied values, but they do not by themselves prove the quote
> was issued by genuine Intel hardware. For a strong trust guarantee, enable the
> optional DCAP verifier. See [`SECURITY.md`](SECURITY.md) for the full threat model.

## Build and distribution

- TypeScript compiled to ESM (`tsc`); no bundler required for the npm package.
- An optional single-file browser bundle can be produced with `esbuild`.
- Published artifacts live in `dist/` and are generated at publish time; the
  directory is not committed to source control.

## Testing

- Unit tests cover crypto round-trips, attestation binding checks, SSE stream decryption (including tool-call deltas), and tool-message encryption.
- An integration test runs against the live attestation and chat endpoints when
  `VENICE_API_KEY` is set in the environment.
