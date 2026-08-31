# Security Policy

## Current Status: Alpha Scaffold - Not Production Secure

Phantom-FHE is at an alpha, correctness-scaffold stage. Every crate in this
workspace prioritizes correct APIs and testable behavior over cryptographic
hardness or performance. Concretely, as of this release:

- `phantom-ring` sampling includes a placeholder Gaussian-like sampler that
  is not cryptographically appropriate.
- `phantom-lattice::rlwe` uses toy exact secret-key/public-key encryption,
  placeholder relinearization, and placeholder key switching.
- `phantom-lattice::rgsw` uses a plaintext-backed ciphertext scaffold rather
  than an encrypted representation.
- `phantom-schemes::bgv` and `phantom-schemes::bfv` use transparent
  (non-encrypted) ciphertext semantics.
- `phantom-schemes::ckks` implements approximate encoding and rescale
  bookkeeping without real noise/precision analysis.
- `phantom-bootstrapping::ckks` is message-preserving scaffolding, not a
  production refresh pipeline. BGV/BFV bootstrapping modules are reserved
  but unimplemented.
- `phantom-multiparty` protocol scaffolds have not had an adversarial
  security review. Collective key generation, relinearization-key
  generation, and Galois-key generation currently aggregate shares into
  placeholder key material (e.g. an all-zero public key) rather than real
  cryptographic key material, and the transcript hash used for protocol
  transcripts (`phantom_multiparty::common::transcript::stable_hash_256`) is
  a small hand-rolled mixer, not a vetted cryptographic hash function.
- All example and test parameter presets (see
  `docs/user-guide.md#choosing-parameters`) are toy sizes chosen for speed,
  not security.

For the precise, per-operation account of what each of the above means in
code, see `docs/technical-manual.md`.

**Do not use this repository to protect real secrets, in any deployment, at
any parameter size, until this notice is updated.** The workstreams tracked
in `docs/internal/implementation-plan.md` describe the path from this scaffold to
production-hardened cryptography.

## Reporting a Vulnerability

Because the project has not reached a security-reviewed state, most
cryptographic weaknesses are already known and tracked in
`docs/internal/implementation-plan.md` rather than being reportable surprises. Still, if
you find:

- a memory-safety or panic-safety issue reachable from public APIs,
- a logic bug that breaks correctness guarantees the current scaffold does
  claim (for example, a documented round-trip or test that can be broken
  with valid inputs), or
- a supply-chain or build-process concern,

please open a GitHub issue with a minimal reproduction. If the issue is
sensitive (for example, it affects a downstream consumer who has already
deployed a preset from this repository), contact the maintainer directly
instead of filing a public issue.

## Scope Boundary

Reports about the *absence* of production hardening that is already listed
in `docs/internal/implementation-plan.md` (real noise management, optimized NTT/RNS,
secure parameter sets, protocol security review, etc.) are welcome as
general feedback but are not treated as new vulnerabilities - they are
tracked, expected gaps at this stage of the project.
