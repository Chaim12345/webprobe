# Dependency security pass, 2026-11-20

Scope: app/Cargo.lock at hardening 4cddee0. This is a targeted pass, not a full security audit.

## Scan and change

cargo-audit 0.23.0 checked 558 locked dependencies against RustSec database commit f291af9b1cc0d21dfcea1709d6b037963cef262b, updated 2026-11-20.

Before: 2 vulnerability advisories, 5 unmaintained-package warnings.
After: 1 vulnerability advisory, 4 unmaintained-package warnings. The remaining vulnerability is RSA, discussed below. Do not label this branch audit-clean.

Replaced hpack 0.3.0 with the dependency alias `hpack = { package = "hpack-patched", version = "=0.3.0" }`.

- Advisory: RUSTSEC-2023-0085, https://github.com/mlalic/hpack-rs/issues/11
- Exact replacement: https://crates.io/crates/hpack-patched/0.3.0
- Fork repository: https://github.com/sno2/hpack-rs-patched
- Repository owner identifier: sno2. Original package author metadata: Marko Lalic. No claim of independent personal identity verification or current active maintenance.
- Trust basis: RustSec recommends this patched package and links its fix. A local recursive diff of the downloaded registry source directories showed only decoder.rs changed: dynamic-table size parsing propagates an error instead of unwrapping, plus one regression test. Same MIT license and log dependency, no build script. The repository is not archived, but its last push is September 2023.
- The exact version is pinned and Cargo.lock records its registry checksum. This keeps a minimal reviewed change; it is not a substitute for future dependency reviews.

Existing client/server catch_unwind guards remain. The server also prevalidates HPACK blocks. Therefore the advisory does not establish an unhandled process-wide panic in WebProbe. The direct dependency regression reproduces the panic before the replacement and returns an error after it, without relying on the production guards.

## RSA migration note, not implemented

RUSTSEC-2023-0071 flags rsa 0.9.10. The current advisory identifies >=0.10.0 as patched: https://github.com/RustCrypto/RSA/issues/626 . No RSA version was changed in this branch.

Relevant uses:

- support/src/tls.rs generates the local CA RSA key and serializes PKCS#8. TLS itself uses rustls with ring, so this should not be described as the RSA crate handling every TLS private operation.
- core/src/interactsh.rs generates a separate RSA key, serializes its public key, and performs RSA-OAEP-SHA256 private-key decryption of an AES key returned by the OAST server. This is the concrete private-operation path requiring review. Exploitability has not been demonstrated.

Proposed migration sequence:

1. Inspect the stable 0.10 API and its RNG, digest, PKCS#8 and MSRV requirements. Both core and support currently declare rsa separately and use rand 0.8; do not upgrade only one declaration or casually replace the workspace RNG stack.
2. Build a separate branch updating both declarations and only the required related dependencies. Confirm PKCS#8 private/public encoding remains compatible with existing saved CAs and the interactsh registration protocol.
3. Test existing saved CA loading and fresh RSA CA generation, PEM/PKCS#8 round trips, local TLS issuance/handshake, deterministic OAEP interoperability, invalid-ciphertext failures, AES-CTR interaction decrypt, and an opt-in live OAST registration/poll smoke test. Do not send private CA material to an OAST service.
4. Run core/support tests and clippy, compile the desktop targets, and repeat cargo-audit. Compare key-generation and decrypt timings to catch regressions, but do not treat timing measurements alone as proof of constant-time behavior.
5. Retain rollback compatibility for saved CA files. Review the migration diff independently before landing.

Other unmaintained warnings after the HPACK change: paste, zbus_names, zvariant and zvariant_derive. These are not counted as demonstrated vulnerabilities by this scan.
