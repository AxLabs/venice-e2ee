# Security Policy

`@axlabs/venice-e2ee` is maintained by [AxLabs](https://axlabs.com).

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/AxLabs/venice-e2ee/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

We aim to acknowledge receipt within 48 hours and to release a fix within
7 days for critical issues.

## Scope

In scope for security reports:

- ECDH key exchange (secp256k1)
- HKDF-SHA256 key derivation
- AES-256-GCM encryption/decryption
- TDX attestation parsing and binding checks
- Per-chunk streaming decryption
- Session management and key zeroization

## Trust model and known limitations

This library implements Venice AI's E2EE protocol. Users should understand the
guarantees it does — and does not — provide:

- **Level 1 binding checks (default).** The library parses the TDX quote and
  verifies that the client nonce and the signing key's Ethereum address appear
  in `REPORTDATA`, and it rejects debug-mode TEEs. These checks confirm that
  fields inside a quote match client-supplied values, but on their own they do
  **not** prove the quote was issued by genuine Intel hardware. Always pair them
  with the DCAP verifier when a strong trust guarantee is required.
- **Full DCAP verification (optional).** Inject a verifier via
  `createVeniceE2EE({ dcapVerifier })` to validate the PCK certificate chain,
  quote signatures, and TCB level.
- **Code-measurement whitelisting is not yet performed.** Even a fully
  signature-verified quote is not currently checked against a known-good TEE
  measurement (MRTD/RTMR). This is planned future work.
- **Plaintext passthrough.** Short, non-hex stream chunks (e.g. whitespace
  tokens) are surfaced as-is and are not authenticated by AES-GCM.
- **Tool-call metadata is plaintext.** Tool names, JSON schemas, call ids, and
  arguments are not part of the encrypted `content` channel — the enclave chat
  template reads them as JSON. Prompts and tool-result bodies are encrypted.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full verification design.
