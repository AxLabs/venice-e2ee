# TODO

Security and hardening backlog derived from the code audit of `src/`. Items are
ordered by severity. Checked boxes are not yet implemented — this is a tracking
document, not a changelog.

## High — Attestation trust model

- [ ] **Make quote signature verification the default, or fail loudly without it.**
  In the default configuration `verifyAttestation: true` runs only Level‑1
  binding checks (`src/attestation.ts`). Those checks read the nonce and
  signing-key address from `REPORTDATA` but do **not** verify the quote's Intel
  signature / PCK certificate chain unless a `dcapVerifier` is injected. Because
  the quote bytes come from the same response being validated, a MITM or a
  malicious provider can forge a quote that passes every Level‑1 check.
  - Option A: enable a bundled DCAP verifier by default.
  - Option B: when no `dcapVerifier` is provided, surface a clear, unmissable
    warning (or require an explicit `allowUnverifiedQuote: true` opt-in) so
    callers cannot mistake Level‑1 for real attestation.

- [ ] **Validate TEE code measurements (MRTD / RTMR).**
  Even with full DCAP signature verification, the code never checks the TD
  measurement against Venice's expected values. A validly-signed quote from any
  genuine TDX machine running attacker-controlled code (embedding the attacker's
  own signing address and the client nonce) would still pass. Add measurement
  whitelisting once Venice publishes expected values.

- [ ] **Treat `server_verification` as untrusted.**
  Cross-checks against `response.server_verification` (`src/attestation.ts`) are
  self-attested by the same server and provide no independent guarantee. Keep
  them only as defense-in-depth and ensure they can never be the sole basis for
  a "verified" result. Document this clearly.

## Medium — Stream integrity

- [ ] **Unauthenticated plaintext passthrough.**
  `decryptChunk` (`src/crypto.ts`) returns content verbatim when it is `< 154`
  chars, non-hex, or lacks the `0x04` EC-point prefix (intended for whitespace
  tokens). These chunks bypass AES-GCM authentication, allowing a network/infra
  attacker to inject arbitrary unauthenticated text into the decrypted stream.
  Investigate constraining passthrough (e.g. only known whitespace tokens) or
  documenting the limitation prominently.

## Medium — Concurrency / session lifecycle

The crypto paths (`encrypt`, `decryptChunk`, `decryptStream`) are
concurrency-safe when they share a single, already-created session: they take an
explicit `session` argument, only read `session.privateKey`, and use an
immutable `CryptoKey` with per-call random IVs. The problems below are all in the
session manager in `src/index.ts`.

- [ ] **Session rotation / `clearSession` zeroizes a key that may still be in use.**
  There is a single `_session` slot. `_createSessionInner` runs
  `if (_session) _session.privateKey.fill(0)` before replacing the session, and
  `clearSession` does the same. If an in-flight `decryptStream`/`decryptChunk`
  still references that session object, its `privateKey` `Uint8Array` is wiped
  in place, so subsequent per-chunk ECDH derives from an all-zero key and
  decryption fails. Don't zeroize a session that may still be referenced — e.g.
  only zeroize on explicit `clearSession`, track in-flight usage/refcount, or
  drop the reference and let GC reclaim it on rotation.

- [ ] **Single-slot cache cannot hold multiple model sessions at once.**
  Because there is one `_session` slot, calling `createSession` for a second
  model evicts (and zeroizes) the first. Two models cannot be used concurrently
  through one `createVeniceE2EE` instance. Key the cache by `modelId` (a `Map`)
  so independent model sessions coexist. (Workaround today: one instance per
  model, or serialize.)

- [ ] **Per-model concurrent session dedup.**
  `if (_pendingSession) return _pendingSession` (`src/index.ts`) returns the
  in-flight promise regardless of `modelId`, so overlapping `createSession`
  calls for different models can resolve to the wrong session. Key the pending
  promise by `modelId` (pairs naturally with the `Map`-based cache above).

## Low — Robustness / correctness

- [ ] **Strict hex parsing in `fromHex`.**
  `parseInt(pair, 16)` (`src/crypto.ts`) silently accepts a malformed second
  nibble (e.g. `"1z"` parses as `1`) instead of throwing. Validate each pair
  against `[0-9a-fA-F]{2}` (or check both characters) before parsing.

- [ ] **Document AES-GCM IV/key usage bounds.**
  Outgoing messages reuse a single static session AES key with random 96-bit
  IVs. This is safe for chat-scale volumes but approaches the GCM birthday bound
  at very high message counts. Document the limit (and the session TTL that
  mitigates it).

## Notes

- The core primitives (ECDH via `@noble/secp256k1`, HKDF + AES-256-GCM via Web
  Crypto) are standard and used correctly; no custom cryptography.
- Existing good practices to preserve: constant-time comparisons for nonce and
  address checks, zeroization of ECDH intermediates and session private keys,
  debug-mode TEE rejection, and nonce-based replay protection.
- Several behaviors above (plaintext passthrough, empty HKDF salt, static
  session key) are required for Venice protocol interoperability — changing them
  may break compatibility and must be validated against the live API.
