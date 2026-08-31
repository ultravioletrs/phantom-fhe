# Phantom-FHE Implementation Plan

## 1. Goal

Build `phantom-fhe` as a best-of-breed Rust-native FHE library with broad feature parity to leading FHE libraries and an architecture designed for Rust from the ground up:

```text
phantom-ring
  |
  v
phantom-lattice::{rlwe,rgsw}
  |
  v
phantom-schemes::{bfv,bgv,ckks}
  |
  v
phantom-circuits::{common,bgv,bfv,ckks}
  |
  v
phantom-bootstrapping::{ckks,bgv,bfv}
  |
  v
phantom-multiparty::{mpbgv,mpbfv,mpckks}

phantom-utils is a sidecar support crate.
phantom-fhe is a thin facade crate.
```

Compatible open-source projects and public papers may be used for understanding algorithms, terminology, parameters, and validation behavior. The implementation should be original Rust code authored for this repository; third-party source, comments, tests, examples, serialization formats, and internal layouts should not be copied or mechanically translated.

---

## 2. Current Roadmap Status

Current position: Phase 18 is implemented as a correctness scaffold. The roadmap implementation pass is complete; remaining work is production hardening and Phase 0 cleanup.

| Phase | Area | Status | Notes |
| --- | --- | --- | --- |
| 0 | Repository foundation | Partial | Workspace, README, `.gitignore`, and initial crates exist; CI/security/contributing/facade work remains. |
| 1 | `phantom-utils` | Done | Minimal support crate with sampling, buffers, serialization helpers, and tests. |
| 2 | `phantom-ring` | Done | Correctness-first ring arithmetic, RNS helpers, NTT backend, samplers, and tests. |
| 3 | `phantom-lattice::rlwe` | Done | Scheme-agnostic RLWE scaffolding with toy exact encryption/decryption and evaluator surfaces. |
| 4 | `phantom-lattice::rgsw` | Done | RGSW ciphertexts, gadget decomposition, and toy external product scaffolding. |
| 5 | `phantom-schemes::bgv` | Done | Exact arithmetic scheme facade with BGV parameters, encoder, wrappers, evaluator, and tests. |
| 6 | `phantom-schemes::bfv` | Done | Distinct BFV API over shared exact-arithmetic scaffold with signed/unsigned encoding and tests. |
| 7 | `phantom-schemes::ckks` | Done | Approximate arithmetic scheme facade with complex/real encoding, scale/rescale, precision tracking, and tests. |
| 8 | `phantom-circuits::common` | Done | Shared lintrans and polynomial evaluation planning. |
| 9 | `phantom-circuits::bgv` | Done | BGV lintrans and polynomial evaluation. |
| 10 | `phantom-circuits::bfv` | Done | BFV lintrans and polynomial evaluation. |
| 11 | `phantom-circuits::ckks` | Done | CKKS lintrans, polynomial, minimax, comparison, inverse, mod1, DFT. |
| 12 | `phantom-bootstrapping` | Done | CKKS centralized bootstrapping first; BGV/BFV module locations reserved. |
| 13 | `phantom-multiparty::common` | Done | Participants, sessions, transcripts, shares, aggregation. |
| 14 | `phantom-multiparty::mpbgv` | Done | Collective keygen, partial decryption, refresh/re-encryption. |
| 15 | `phantom-multiparty::mpbfv` | Done | BFV threshold workflows and interactive bootstrapping. |
| 16 | `phantom-multiparty::mpckks` | Done | CKKS threshold workflows and interactive bootstrapping. |
| 17 | Serialization and compatibility | Done | Stable canonical encoding decisions for public objects. |
| 18 | Examples, benches, release hardening | Done | Examples, smoke benches, docs, parameter presets. |

Status labels:

- `Partial`: started, but not all phase deliverables are complete.
- `Done`: implemented at the current scaffold/correctness level.
- `Next`: next planned implementation target.
- `Pending`: not started.

---

## 3. Engineering Principles

- Implement in dependency order. A phase may not depend on an unstable higher layer.
- Prefer simple, explicit Rust types before introducing generic abstractions.
- Keep all parameter construction behind builders and validation.
- Provide in-place APIs for hot paths and out-of-place wrappers for ergonomics.
- Keep secret-bearing types zeroized, redacted in `Debug`, and hard to serialize accidentally.
- Keep toy parameters behind test/example gates.
- Keep implementation, tests, examples, docs, and serialization formats original so project files can carry this repository's own copyright.
- Avoid `unsafe` until benchmarks prove a need; isolate and document every `unsafe` block when introduced.
- Treat tests, examples, Rustdoc, and benchmarks as part of each feature, not cleanup work.

---

## 4. Phase 0 - Repository Foundation

### Owned Areas

- Workspace root
- `crates/phantom-fhe`
- `crates/phantom-utils`
- Documentation and CI

### Deliverables

- Cargo workspace with all planned crates scaffolded.
- Thin `phantom-fhe` facade crate.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`.
- Shared error and feature-flag conventions.
- CI jobs for fmt, clippy, test, doc, and audit.
- Baseline dependency policy.

### Initial Dependencies

Recommended first dependencies:

- `thiserror`
- `rand_core`
- `rand_chacha`
- `zeroize`
- `subtle`
- `serde` behind a feature flag
- `rayon` behind a feature flag
- `proptest` for tests
- `criterion` for benches

### Tests

- Workspace compiles.
- Feature matrix compiles for default, no-default, serde, zeroize, parallel, and experimental.
- `cargo doc --workspace --no-deps` succeeds.

### Exit Criteria

- All crates exist with stable ownership.
- Original implementation policy is documented.
- CI can run before cryptographic code is implemented.

---

## 5. Phase 1 - `phantom-utils`

`phantom-utils` must remain a small support crate, not a dumping ground. If a helper has clear mathematical or cryptographic ownership, implement it in that owner crate instead.

### Owned Areas

- Secure byte sampling helpers
- Buffer reader/writer helpers
- Serialization domain/version helpers
- Deterministic test RNG helpers

### Deliverables

- CSPRNG wrapper APIs using `rand_core::CryptoRng`.
- Deterministic test RNG helpers clearly limited to tests.
- Buffer APIs for canonical binary IO primitives.
- Serialization domain tags and version helpers.

### Tests

- CSPRNG APIs reject non-crypto RNGs where possible.
- Buffer round trips are deterministic.
- Serialization domain/version helpers reject malformed data.

### Exit Criteria

- Utilities have no dependency on crypto crates.
- Ring can depend on utilities without cycle risk.
- Ring-owned factorization, circuit-owned polynomial approximation, and scheme-owned data structures are not placed here.

---

## 6. Phase 2 - `phantom-ring`

### Owned Areas

- Moduli
- Modular reduction
- Polynomial storage
- Ring context
- RNS basis operations
- NTT backend abstraction
- Samplers

### Deliverables

- Strong types: `Degree`, `Modulus`, `Level`, `RnsBasis`.
- `Poly` with RNS layout `coeffs[modulus_index][coefficient_index]`.
- `Ring` with validated power-of-two degree and NTT-compatible moduli.
- Modular add, sub, neg, mul, Barrett reduction, Montgomery reduction, lazy reduction.
- Polynomial add, sub, neg, scalar mul, coefficient-wise mul.
- Schoolbook negacyclic multiplication for tests and small parameters.
- Forward/inverse NTT with table generation.
- RNS decomposition, basis extension, CRT reconstruction for tests/debugging.
- Rescaling and modulus dropping.
- Uniform, ternary, and discrete Gaussian samplers.
- `NttBackend` trait with `CpuNttBackend`.

### Tests

- Modular arithmetic property tests.
- NTT round-trip property tests.
- NTT multiplication equals schoolbook multiplication for small rings.
- CRT reconstruction round trips.
- Basis extension preserves represented values on small cases.
- Rescale/modulus drop tests.
- Sampler dimension and range tests.

### Benchmarks

- Modular multiplication.
- Forward/inverse NTT.
- Polynomial multiplication.
- RNS basis extension and rescale.

### Exit Criteria

- Ring APIs are allocation-aware and documented.
- All higher layers can reuse ring contexts without duplicating arithmetic.

---

## 7. Phase 3 - `phantom-lattice::rlwe`

### Owned Areas

- Scheme-agnostic RLWE data types
- Secret/public/evaluation keys
- Key generation
- Encryption/decryption primitives
- Key switching
- Relinearization
- Automorphisms and rotations
- Repacking foundations

### Deliverables

- `RlweParams` builder and validator.
- `Plaintext`, `Ciphertext`, `SecretKey`, `PublicKey`, `EvaluationKey`.
- Secret key generation with ternary/Gaussian options.
- Public key generation.
- Symmetric and public-key encryption.
- Decryption.
- Add/sub/neg and plaintext/ciphertext primitive operations.
- Multiplication output shape support before scheme-specific scaling rules.
- Gadget decomposition and key switching.
- Relinearization keys and evaluator support.
- Galois keys and automorphism application.
- Repacking primitives needed by later circuits and bootstrapping.

### Tests

- Toy-parameter encrypt/decrypt cycles.
- Homomorphic add/sub preserve plaintext semantics.
- Key switching preserves decryptability.
- Relinearization preserves decryptability.
- Automorphisms and rotations pass small-ring tests.
- Secret-bearing types zeroize and redact debug output.

### Benchmarks

- Key generation.
- Encryption/decryption.
- Key switching.
- Relinearization.

### Exit Criteria

- RLWE is fully scheme-agnostic.
- BFV, BGV, and CKKS can wrap RLWE types instead of duplicating them.

---

## 8. Phase 4 - `phantom-lattice::rgsw`

### Owned Areas

- Ring-GSW ciphertexts
- Gadget decomposition
- External product
- RLWE integration

### Deliverables

- `RgswParams`, `RgswCiphertext`, `RgswKey`.
- Full-RNS gadget decomposition.
- RGSW encryption of small test messages.
- External product with RLWE ciphertexts.
- Prepared representation for bootstrapping.

### Tests

- Gadget decomposition/recomposition tests.
- RGSW encrypt/decrypt semantics for toy cases where applicable.
- External product correctness on small rings.

### Benchmarks

- Gadget decomposition.
- External product.

### Exit Criteria

- Bootstrapping and advanced circuits have the RGSW foundation they need.

---

## 9. Phase 5 - `phantom-schemes::bgv`

### Owned Areas

- Full-RNS BGV parameters
- Integer encoding/decoding
- Exact arithmetic
- Modulus switching
- Rotations and batching

### Deliverables

- `BgvParams` builder and `BgvContext`.
- Plaintext modulus handling.
- SIMD batching encoder.
- Encryptor/decryptor/evaluator wrappers over RLWE.
- Add, sub, neg, mul, plaintext operations.
- Relinearization and rotations.
- Modulus switching.
- Slot summation helpers.

### Tests

- Encode/decode exactness.
- Encrypt/decrypt exactness.
- Add/mul exactness.
- Modulus switching correctness.
- Rotation and slot-sum correctness.

### Benchmarks

- BGV encode/decode.
- BGV encrypt/decrypt.
- BGV add/mul/relinearize/rotate.

### Exit Criteria

- BGV can serve as the exact-arithmetic base used directly and by BFV where appropriate.

---

## 10. Phase 6 - `phantom-schemes::bfv`

### Owned Areas

- Full-RNS BFV wrapper/specialization
- Exact integer arithmetic
- Batching and rotations

### Deliverables

- `BfvParams` builder and `BfvContext`.
- Encoder for unsigned/signed integer slots.
- Encryptor/decryptor/evaluator wrappers.
- Add, sub, neg, mul, plaintext operations.
- Relinearization, rotations, slot summation.
- Clear code sharing with BGV where mathematically sound.

### Tests

- BFV exact encode/decode.
- BFV encrypt/decrypt.
- BFV add/mul exactness modulo plaintext modulus.
- Rotation and slot-sum correctness.

### Benchmarks

- BFV encode/decode.
- BFV encrypt/decrypt.
- BFV add/mul/relinearize/rotate.

### Exit Criteria

- BFV public API is distinct and ergonomic, even where internals reuse BGV machinery.

---

## 11. Phase 7 - `phantom-schemes::ckks`

### Owned Areas

- CKKS parameters
- Complex and real encoders
- Scale and level tracking
- Approximate arithmetic
- Rescaling
- Conjugate-invariant variant

### Deliverables

- `CkksParams` builder and `CkksContext`.
- `Scale` and `Precision` domain types.
- Complex vector encoding/decoding.
- Real vector encoding/decoding.
- Encryptor/decryptor/evaluator wrappers.
- Add, sub, neg, mul, plaintext operations.
- Relinearization, rotations, conjugation.
- Rescale-to-next and explicit level alignment.
- Initial precision/noise reporting.

### Tests

- Encode/decode within tolerance.
- Encrypt/decrypt within tolerance.
- Add/mul/rescale within tolerance.
- Rotation and conjugation correctness.
- Level/scale mismatch rejection.
- Conjugate-invariant variant tests.

### Benchmarks

- CKKS encode/decode.
- CKKS encrypt/decrypt.
- CKKS add/mul/rescale/rotate.

### Exit Criteria

- CKKS supports enough stable approximate arithmetic for circuits.

---

## 12. Phase 8 - `phantom-circuits::common`

### Owned Areas

- Shared linear transformation representations
- Shared polynomial evaluation strategies
- Diagonal matrices and BSGS planning

### Deliverables

- Linear transformation descriptors.
- Diagonal representation.
- Baby-step giant-step planning.
- Polynomial evaluator planning.
- Paterson-Stockmeyer strategy.

### Tests

- Planning correctness independent of schemes.
- Matrix/diagonal conversion tests.
- Polynomial evaluation plan tests.

### Exit Criteria

- BGV, BFV, and CKKS circuits can share planning without sharing scheme-specific arithmetic incorrectly.

---

## 13. Phase 9 - BGV Circuits

### Owned Areas

- `phantom-circuits::bgv::lintrans`
- `phantom-circuits::bgv::polynomial`

### Deliverables

- Packed-slot linear transformations.
- Slot permutations.
- Exact modular polynomial evaluation.
- Rotation-key requirement planning.

### Tests

- Linear transformation exactness.
- Slot permutation exactness.
- Polynomial evaluation exactness.
- Missing-key errors are clear.

### Benchmarks

- BGV linear transform.
- BGV polynomial evaluation.

### Exit Criteria

- Exact-arithmetic circuit layer is usable and documented.

---

## 14. Phase 10 - BFV Circuits

### Owned Areas

- `phantom-circuits::bfv::lintrans`
- `phantom-circuits::bfv::polynomial`

### Deliverables

- Packed-slot linear transformations.
- Slot permutations.
- Exact modular polynomial evaluation over BFV plaintext slots.
- Rotation-key requirement planning.
- BFV-specific validation for plaintext modulus and signed/unsigned encoding semantics.

### Tests

- Linear transformation exactness.
- Slot permutation exactness.
- Polynomial evaluation exactness.
- Signed and unsigned BFV encoding behavior through circuits.
- Missing-key errors are clear.

### Benchmarks

- BFV linear transform.
- BFV polynomial evaluation.

### Exit Criteria

- BFV exact-arithmetic circuit layer is usable and documented without relying on BGV APIs.

---

## 15. Phase 11 - CKKS Circuits

### Owned Areas

- `lintrans`
- `polynomial`
- `minimax`
- `comparison`
- `inverse`
- `mod1`
- `dft`

### Deliverables

- CKKS linear transformations and slot permutations.
- Approximate polynomial evaluation.
- Minimax composite polynomial evaluator.
- Sign, max, and step approximations.
- Inverse approximation.
- Mod1 approximation.
- Homomorphic DFT and inverse DFT.
- Precision-aware circuit configuration.

### Tests

- Linear transformation tolerance tests.
- Polynomial evaluation tolerance tests.
- Minimax evaluator tests.
- Comparison/sign/max/step approximation tests.
- Inverse approximation tests.
- Mod1 tests.
- DFT round-trip tolerance tests.

### Benchmarks

- CKKS linear transform.
- CKKS polynomial evaluation.
- CKKS DFT.
- CKKS inverse and comparison.

### Exit Criteria

- CKKS circuit layer is stable enough for the separate bootstrapping crate to build on it.

---

## 16. Phase 12 - CKKS Bootstrapping

This phase implements centralized CKKS bootstrapping first and establishes the crate structure for future BGV/BFV centralized bootstrapping. BGV and CKKS interactive refresh/bootstrapping are multiparty protocols handled in later multiparty phases.

### Owned Areas

- `phantom-bootstrapping::ckks`
- reserved experimental modules `phantom-bootstrapping::bgv` and `phantom-bootstrapping::bfv`
- optional compatibility re-export at `phantom_fhe::circuits::ckks::bootstrapping`
- Bootstrapping parameters and keys
- Coefficients-to-slots and slots-to-coefficients
- Eval-mod
- Packing and unpacking
- Batch bootstrapping

### Deliverables

- `BootstrapParams` builder and validator.
- Bootstrapping key generation.
- Coefficients-to-slots transform.
- Slots-to-coefficients transform.
- Eval-mod circuit.
- Single-ciphertext bootstrapping.
- Batch bootstrapping.
- Sparse packing/unpacking.
- Arbitrary precision options.
- Conjugate-invariant support.
- Experimental BGV/BFV module stubs without stable public APIs.

### Tests

- Bootstrapping preserves messages within tolerance.
- Bootstrapping refreshes level/noise/precision.
- Batch bootstrapping correctness.
- Sparse packing/unpacking correctness.
- Invalid parameter rejection.
- Conjugate-invariant bootstrapping tests.

### Benchmarks

- Single CKKS bootstrap.
- Batch CKKS bootstrap.
- Coeffs-to-slots and slots-to-coeffs.
- Eval-mod.

### Exit Criteria

- CKKS bootstrapping works end-to-end on documented parameter presets.

---

## 17. Phase 13 - Multiparty Common Layer

### Owned Areas

- Participants
- Sessions
- Transcripts
- Shares
- Aggregation
- Transcript hashing

### Deliverables

- `ParticipantId`.
- Protocol session state types.
- Typed share objects.
- Deterministic transcript encoding and hashing.
- Share aggregation APIs.
- Error handling for missing, duplicate, stale, or malformed shares.

### Tests

- Transcript determinism.
- Share aggregation correctness.
- Missing/duplicate/stale share rejection.
- Serialization round trips for public protocol messages.

### Exit Criteria

- BGV and CKKS multiparty protocols can reuse the common layer.

---

## 18. Phase 14 - BGV Multiparty

### Owned Areas

- `mpbgv::ckg`
- `mpbgv::rkg`
- `mpbgv::gkg`
- Partial decryption
- Re-encryption from shares
- Interactive bootstrapping where supported

### Deliverables

- Collective public key generation.
- Collective relinearization key generation.
- Collective Galois key generation.
- Partial decryption.
- Re-encryption from linear secret-sharing shares.
- Interactive bootstrapping protocol scaffolding and implementation where supported by scheme components.

### Tests

- Collective public key encrypts decryptable ciphertexts.
- Partial decryptions reconstruct the correct plaintext.
- Invalid share detection.
- Re-encryption from shares.
- Interactive bootstrapping correctness where implemented.

### Benchmarks

- Collective key generation.
- Partial decryption aggregation.
- Re-encryption.

### Exit Criteria

- BGV threshold workflows are usable in examples.

---

## 19. Phase 15 - BFV Multiparty

### Owned Areas

- `mpbfv::ckg`
- `mpbfv::rkg`
- `mpbfv::gkg`
- Partial decryption
- Re-encryption from shares
- Interactive bootstrapping where supported

### Deliverables

- Collective public key generation.
- Collective relinearization key generation.
- Collective Galois key generation.
- Partial decryption.
- Re-encryption from linear secret-sharing shares.
- Interactive bootstrapping protocol scaffolding and implementation where supported by scheme components.

### Tests

- Collective public key encrypts decryptable ciphertexts.
- Partial decryptions reconstruct the correct plaintext.
- Signed BFV encoding behavior survives threshold workflows.
- Invalid share detection.
- Re-encryption from shares.
- Interactive bootstrapping correctness where implemented.

### Benchmarks

- BFV collective key generation.
- BFV partial decryption aggregation.
- BFV re-encryption.

### Exit Criteria

- BFV threshold workflows are usable in examples.

---

## 20. Phase 16 - CKKS Multiparty

### Owned Areas

- `mpckks::ckg`
- `mpckks::rkg`
- `mpckks::gkg`
- Partial decryption
- Re-encryption from shares
- Interactive bootstrapping

### Deliverables

- Collective public key generation.
- Collective relinearization key generation.
- Collective Galois key generation.
- Partial decryption.
- Re-encryption from linear secret-sharing shares.
- Interactive CKKS bootstrapping.

### Tests

- Collective public key encrypts decryptable ciphertexts.
- Partial decryptions reconstruct values within tolerance.
- Invalid share detection.
- Re-encryption from shares.
- Interactive bootstrapping correctness.

### Benchmarks

- CKKS collective key generation.
- CKKS partial decryption aggregation.
- CKKS interactive bootstrapping.

### Exit Criteria

- CKKS threshold and interactive bootstrapping workflows are demonstrated end-to-end.

---

## 21. Phase 17 - Serialization and Compatibility

Status: Done at the current scaffold/correctness level.

### Owned Areas

- Canonical binary formats
- Version tags
- Optional `serde` support
- Public key/ciphertext/plaintext serialization
- Public protocol message serialization

### Deliverables

- Deterministic binary encoding for public scheme parameters, plaintexts, and ciphertexts.
- Explicit versioning and domain separators.
- Serialization for RLWE public keys, evaluation-key markers, common circuit plans, and CKKS bootstrapping parameters.
- Public protocol messages already use deterministic transcript/share encodings from Phase 13.
- Secret serialization only behind explicit APIs and feature gates.
- Malformed-input tests for decode rejection.

### Tests

- Round-trip tests for all serializable public types.
- Corrupted input rejection.
- Version mismatch behavior.
- Secret serialization guardrail tests.

### Exit Criteria

- Serialized artifacts are stable enough for examples and future releases.

---

## 22. Phase 18 - Examples, Benches, and Release Hardening

Status: Done at the current scaffold/correctness level.

### Owned Areas

- Examples
- Benchmarks
- Rustdoc
- Parameter presets
- Performance tuning
- Release checklist

### Deliverables

- Examples:
  - `bfv_basic`
  - `bfv_batching`
  - `bfv_rotation`
  - `bgv_basic`
  - `bgv_polynomial`
  - `ckks_basic`
  - `ckks_rescale`
  - `ckks_dft`
  - `ckks_inverse`
  - `ckks_bootstrapping`
  - `mpbgv_basic`
  - `mpckks_basic`
  - `mpckks_interactive_bootstrap`
- Benchmarks:
  - `ring_ntt`
  - `ring_rns`
  - `rlwe_encrypt`
  - `rlwe_keyswitch`
  - `bfv_eval`
  - `bgv_eval`
  - `ckks_eval`
  - `ckks_bootstrapping`
  - `multiparty`
- Parameter preset documentation, now in `docs/user-guide.md#choosing-parameters`.
- Runnable API examples in `phantom-examples`.
- Performance notes for CPU backend, now in `docs/technical-manual.md#performance`.
- Release checklist for alpha, beta, and stable in `docs/internal/release-checklist.md`.

### Tests

- All examples compile and run with documented toy/test presets.
- Doctests pass.
- Full workspace test suite passes.
- Clippy is warning-free.

### Exit Criteria

- Library is ready for an alpha release.

---

## 21. Suggested Milestones

### Alpha 1 - Arithmetic Foundation

- Phases 0-2 complete.
- Ring arithmetic, NTT, RNS, and samplers are usable.

### Alpha 2 - RLWE Foundation

- Phases 3-4 complete.
- RLWE and RGSW foundations compile, test, and benchmark.

### Alpha 3 - Exact Schemes

- Phases 5-6 complete.
- BGV and BFV exact arithmetic work end-to-end.

### Alpha 4 - CKKS

- Phase 7 complete.
- CKKS approximate arithmetic works end-to-end.

### Beta 1 - Circuits

- Phases 8-11 complete.
- BGV, BFV, and CKKS circuits work with documented examples.

### Beta 2 - Bootstrapping

- Phase 12 complete.
- CKKS bootstrapping works with documented presets.
- BGV/BFV centralized bootstrapping module locations exist behind experimental gates if not yet implemented.

### Beta 3 - Multiparty

- Phases 13-16 complete.
- BGV, BFV, and CKKS multiparty workflows work end-to-end.

### Stable 1.0

- Phases 17-18 complete.
- Public APIs, serialization, examples, docs, and benchmarks are release-ready.

---

## 24. Definition of Done for Every Phase

Each phase is complete only when:

1. It compiles under the workspace default feature set.
2. Unit tests pass.
3. Relevant integration tests pass.
4. Public APIs have Rustdoc.
5. Parameter validation exists for public constructors.
6. Errors use typed `Result` values.
7. Secret material is protected where applicable.
8. No third-party source material is incorporated into project files.
9. Benchmarks exist for hot-path operations.
10. Examples or doctests cover user-facing APIs.

---

## 25. Immediate Next Coding Tasks

Current next implementation target: Alpha Hardening Workstream 3 (ring and RNS foundation hardening) - the first workstream that changes cryptographic behavior rather than API/documentation surface. Workstreams 1 (Phase 0 cleanup) and 2 (scaffold boundary and API honesty) are complete - see below.

## 26. Next Release Plan - Alpha Hardening

The phase roadmap is complete at the current scaffold/correctness level. The next release should not add another broad feature layer. It should turn the existing workspace into a clearly bounded alpha: easy to build, honest about toy/scaffold internals, safer to consume, and ready for deeper production cryptography work.

### Release Goal

Ship an alpha-quality repository where:

- public crates compile, test, document, and lint consistently
- examples and smoke benchmarks are runnable from documented commands
- scaffold/toy cryptography boundaries are explicit
- the planned `phantom-fhe` facade crate exists
- contributors can understand security status, dependency policy, and release expectations
- production hardening work is broken into concrete follow-up tracks

### Workstream 1 - Phase 0 Cleanup and Release Infrastructure

Owned areas:

- workspace root
- `crates/phantom-fhe`
- CI and repository policy files

Tasks:

1. [Done] Add the `phantom-fhe` facade crate.
2. [Done] Re-export stable top-level modules from the facade:
   - `ring`
   - `lattice`
   - `schemes`
   - `circuits`
   - `bootstrapping`
   - `multiparty`
   - (also `utils`, since `phantom-utils` error types leak into the public error enums of `phantom-lattice` and `phantom-schemes`)
3. [Done] Decision: `phantom-examples` and `phantom-benches` remain workspace-only packages (`publish = false`). They already exercise each `phantom-*` crate directly; facade-facing example binaries would duplicate that coverage without adding any. The facade instead gets its own smoke test (`crates/phantom-fhe/tests/facade.rs`) confirming the re-exports resolve to working APIs.
4. [Done] Add `SECURITY.md` with current cryptographic status and vulnerability reporting guidance.
5. [Done] Add `CONTRIBUTING.md` with formatting, testing, authorship, and no-copying rules.
6. [Done] Add baseline CI (`.github/workflows/ci.yml`) for:
   - `cargo fmt --all -- --check`
   - `cargo test --workspace --all-targets`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo doc --workspace --no-deps`
   - (plus a `cargo bench -p phantom-benches` smoke job, since that command is also in the documented matrix)
7. [Done] Add dependency policy (`docs/internal/dependency-policy.md`):
   - which dependencies are allowed in core crates
   - which dependencies are dev-only
   - whether Criterion is allowed for benchmarks
   - whether `serde`, `rayon`, `zeroize`, and `proptest` are feature-gated or default dependencies

Exit criteria:

- [Met] A new contributor can clone the repository and run the documented command matrix (`cargo fmt --all -- --check`, `cargo test --workspace --all-targets`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo doc --workspace --no-deps`, `cargo bench -p phantom-benches` all pass locally as of this update).
- [Met] The top-level facade crate compiles and has clear Rustdoc (crate-level docs describe alpha status and module layout).
- [Met] CI status reflects the same checks developers run locally (`.github/workflows/ci.yml` runs the identical command matrix).

### Workstream 2 - Scaffold Boundary and API Honesty

Owned areas:

- README
- crate-level Rustdoc
- examples
- parameter documentation
- feature flags

Tasks:

1. [Done] Mark the current implementation status in all user-facing docs. Reframed from repeated "alpha scaffold / do not use" alarm banners to a single, professional TRL-framed status (`SECURITY.md`, one README status line) plus the precise per-operation account in `docs/technical-manual.md` — see the "Consolidate security messaging" commit. Same underlying facts, stated once rather than repeated as warnings on every page.
2. Separate toy/test presets from future production presets — still deferred. No production preset exists yet to separate from; adding one is explicitly gated on the noise-management/RNS/security-review work in Workstreams 3-7 landing first (see `docs/user-guide.md#choosing-parameters`).
3. Consider a `toy`/`experimental` feature flag for APIs that should not be mistaken for secure production cryptography — still open. Deferred per the new `docs/architecture.md#api-stability` section: worth doing once there's a large-enough stable tier that gating the rest behind a flag is more signal than noise, not before.
4. Hide or rename helpers that are only present to support toy semantics — partially done (rustdoc/user-facing wording swept from "toy" to neutral terms alongside item 1); no visibility changes made, per the API-audit decision in item 6 below.
5. [Done] Add warnings to examples and parameter docs that current presets are not secure — same consolidation as item 1; `docs/user-guide.md#choosing-parameters` and `docs/getting-started.md` both point to `SECURITY.md`.
6. [Done] Audit public APIs and decide: stable alpha API / experimental API / crate-private/internal API. Delivered as a documented tiering in `docs/architecture.md#api-stability` (stable-shape / experimental-placeholder / internal-not-advertised) rather than a mechanical `pub`/`pub(crate)` pass across the ~150 public items found — Workstreams 4-7 are expected to substantially rewrite the experimental tier, so a visibility refactor now would need redoing once real implementations land. No genuine encapsulation gaps were found (the public struct fields that exist are all plain data-transfer types, appropriately public).
7. [Done] Improve error conversions that currently collapse lower-level failures into generic messages. `CircuitsError`/`BootstrappingError`'s `From<UtilsError>`/`From<SchemesError>` impls now wrap the source error via `#[from]`/`#[error(transparent)]` (matching `LatticeError`/`SchemesError`'s existing pattern) instead of discarding it into a generic `&'static str` variant; both error enums dropped their `PartialEq`/`Eq` derives as a result (their new wrapped variants aren't comparable), with the one affected test (`phantom-circuits/tests/phase8_common.rs::invalid_inputs_are_rejected`) switched from `assert_eq!` to `assert!(matches!(...))`. Remaining coarser-grained error handling — call-site `.map_err(|_| SomeVariant("label"))` in circuit/bootstrapping evaluators, which labels *where* a failure happened but still discards the specific lower-layer error — is a smaller follow-up, not yet scheduled as its own item.

Exit criteria:

- [Met] Users cannot reasonably confuse the current status with production-secure FHE (SECURITY.md, technical-manual.md).
- [Met] Public API boundaries are documented (`docs/architecture.md#api-stability`).
- [Met] Examples remain easy to run (`make examples`, `docs/user-guide.md#runnable-examples`) and are clearly scoped to development parameters (`docs/user-guide.md#choosing-parameters`).

Workstream 2 is now effectively complete; items 2 and 3 remain intentionally deferred (see above) rather than outstanding work.

### Workstream 3 - Ring and RNS Foundation Hardening

Owned areas:

- `phantom-ring`
- NTT backend
- modular reduction
- RNS basis operations
- samplers

Tasks:

1. Add property tests for modular arithmetic, polynomial arithmetic, NTT round trips, and RNS reconstruction.
2. Add larger randomized tests for basis extension, rescale, and modulus dropping.
3. Replace placeholder Gaussian-like sampling with a documented, cryptographically appropriate path or keep it explicitly toy-gated.
4. Replace the current O(N²) direct-evaluation NTT (`ntt::cpu::forward_component`/`inverse_component`) with a real Cooley-Tukey-style O(N log N) butterfly network, and measure against schoolbook multiplication and against `Ring::schoolbook_mul` (the O(N²) path everything above `phantom-ring` currently uses for ciphertext multiplication).
5. [Done] Implement real Barrett and Montgomery reduction in `phantom_ring::reduce`. `BarrettReducer` now does precomputed multiply-and-shift with correction (`mu = ⌊2⁶⁴/modulus⌋`); `MontgomeryReducer` implements real REDC with a Newton-Raphson 2-adic inverse, plus `to_montgomery`/`from_montgomery`/`mul_montgomery` for staying in Montgomery form across a chain of operations. Both are currently restricted to moduli `< FAST_REDUCER_MAX_MODULUS` (`2^32`) so every intermediate product stays within `u128` without wide-multiplication tricks — full 64-bit range is follow-up work (needs either wide multiplication or the "drop the lowest partial product" technique). Validated by exhaustive tests (all moduli 3-199, full value range) plus thousands of randomized large-modulus cases (`crates/phantom-ring/tests/phase2.rs`), and a standalone unit test for the Newton-Raphson inverse. Neither reducer is wired into `Ring`'s actual arithmetic yet (`add_mod`/`mul_mod`/`Ring::*` still use widened `u128` directly) — that hot-path swap is a natural next step, not yet scheduled as its own item.
6. Replace `rns::extension::extend_basis`'s `u128`-based CRT round trip with a production RNS-native basis-extension algorithm (e.g. Bajard-Eynard-Hasan-Zucca or Halevi-Polyakov-Shoup style) that doesn't overflow for realistic multi-modulus bases; its own doc comment already flags it as debug/small-parameter-only.
7. Audit allocation patterns in polynomial operations.
8. Add in-place variants where they remove meaningful allocation in hot paths.
9. Extend smoke benchmarks or replace them with Criterion once dependency policy is settled.

Exit criteria:

- Ring operations have stronger randomized coverage.
- The CPU backend has baseline performance data.
- Sampling status is explicit and not silently production-claimed.
- The NTT is a real O(N log N) transform, and Barrett/Montgomery reducers implement their named algorithms.

### Workstream 4 - Production RLWE/RGSW Track

Owned areas:

- `phantom-lattice::rlwe`
- `phantom-lattice::rgsw`

Tasks:

1. Replace toy exact encryption internals with real RLWE encryption semantics — `KeyGenerator::generate_public_key` currently adds no error term (a noiseless RLWE-of-zero), and `Encryptor` performs real RLWE arithmetic but likewise with no error sampled in.
2. Add noise tracking and correctness bounds.
3. Implement production key switching (`keyswitch::key_switch_identity` is currently a literal identity function).
4. Implement production relinearization (`Evaluator::relinearize` is currently a literal identity function, not a real degree reduction).
5. Implement production automorphism/Galois key behavior, replacing `Evaluator::rotate_coefficients`'s raw coefficient rotation with real Galois-automorphism-based slot rotation.
6. Implement production repacking (`repacking::repack_identity` is currently a literal identity function).
7. Improve RGSW ciphertext representation beyond plaintext-backed scaffolding — `RgswCiphertext` currently stores the message polynomial directly rather than an encrypted gadget matrix, and `external_product` is a plain polynomial multiplication by that plaintext message.
8. Implement real gadget decomposition/external product paths suitable for higher layers (decomposition/recomposition themselves are already production-shaped; what's missing is a real encrypted RGSW ciphertext for them to operate on).
9. Add randomized decryptability and homomorphic-operation tests.

Exit criteria:

- RLWE operations are no longer transparent/toy.
- Key switching and relinearization have meaningful cryptographic behavior.
- Higher scheme crates can build production BFV/BGV/CKKS semantics on top.

### Workstream 5 - Production BFV/BGV/CKKS Track

Owned areas:

- `phantom-schemes::bfv`
- `phantom-schemes::bgv`
- `phantom-schemes::ckks`

Tasks:

1. Replace transparent BFV/BGV ciphertext semantics with real scheme behavior — `bgv::Encryptor::encrypt` (which `bfv::Encryptor` also calls through) currently ignores its RNG and key entirely and returns the plaintext polynomial wrapped as a length-1 ciphertext.
2. Implement proper modulus switching and plaintext scaling for BFV/BGV (`ModulusSwitcher::switch_next` currently validates and clones, with no real RNS modulus drop).
3. Rebuild the CKKS ciphertext/plaintext representation on top of `phantom_lattice::rlwe` — today `ckks::Ciphertext`/`Plaintext` store `Complex64` slots directly with no ring/RLWE backing at all, and `Encryptor`/`Decryptor` are identity functions over that representation. Then add real encoding/decoding over the ring representation.
4. Harden CKKS scale management, rescale, level alignment, and precision accounting — the current `Precision` degradation amounts (e.g. `degrade(0.25)`, `degrade(1.0)` throughout `ckks::Evaluator`) are illustrative constants, not derived from real noise analysis.
5. Add noise/error estimates to scheme contexts.
6. Add scheme-specific parameter builders that reject insecure or inconsistent settings.
7. Add cross-operation tests for encryption, addition, multiplication, rotations, rescale/modswitch, and serialization.

Exit criteria:

- Scheme ciphertexts carry real encrypted state.
- Existing examples still run, but over non-transparent scheme behavior where possible.
- CKKS precision metadata reflects real approximation behavior rather than scaffold bookkeeping.

### Workstream 6 - Bootstrapping and Circuits Hardening

Owned areas:

- `phantom-circuits`
- `phantom-bootstrapping`

Tasks:

1. Keep common circuit planning APIs stable while production scheme internals evolve.
2. Connect BGV/BFV/CKKS circuit evaluators to real evaluator semantics.
3. Improve polynomial/minimax approximation testing with known mathematical targets.
4. Turn CKKS bootstrapping from message-preserving scaffold into a real refresh pipeline — the coefficients-to-slots/EvalMod/slots-to-coefficients pipeline *shape* is already correct (`CoeffsToSlots`/`SlotsToCoeffs` genuinely run the DFT transforms), but `Bootstrapper::bootstrap` calls `EvalMod::preserve_message`, an identity function, for the middle stage instead of a real polynomial approximation of modular reduction (`EvalMod::centered_fractional_part`, which does call the real `Mod1Evaluator`, exists but isn't wired into `bootstrap()`).
5. Give `BootstrapKeyGenerator` real key material — `BootstrapKey` currently carries only `{ params, rotation_elements }`, no cryptographic content, consistent with the transparent scheme layer beneath it not yet needing any.
6. Decide whether BGV/BFV bootstrapping remain reserved modules or become explicit future milestones.
7. Add parameter documentation for any bootstrapping presets.

Exit criteria:

- Circuit APIs remain usable across toy and production internals.
- CKKS bootstrapping has a documented path from scaffold to production.
- Exact-scheme bootstrapping status is explicit.

### Workstream 7 - Multiparty and Protocol Security

Owned areas:

- `phantom-multiparty::common`
- `phantom-multiparty::mpbgv`
- `phantom-multiparty::mpbfv`
- `phantom-multiparty::mpckks`

Tasks:

1. Review protocol transcripts and share encodings for replay, stale-share, and domain-separation risks.
2. Add stronger validation around participant sets, thresholds, rounds, and protocol kinds.
3. Replace `common::transcript::stable_hash_256` — currently a small hand-rolled XOR/multiply/rotate mixer with no cryptanalysis behind it — with a vetted cryptographic hash function (e.g. SHA-256 or BLAKE3) before any transcript hash is relied on for collision or preimage resistance.
4. Tie collective key generation, relinearization-key generation, and Galois-key generation (`ckg`/`rkg`/`gkg` across `mpbgv`/`mpbfv`/`mpckks`) to production key material once RLWE is hardened — today all three `aggregate_*` functions ignore collected share content and return placeholder key material (e.g. `CollectiveKeyGen::aggregate_public_key` returns an all-zero public key regardless of shares).
5. Replace share aggregation's current byte-equality check (`ensure_equal_payloads`, used by `PartialDecryptor`/`ReEncryptor`/`InteractiveBootstrap`) with real threshold secret-share reconstruction (e.g. Lagrange interpolation) once ciphertext semantics are production-grade — there is currently no actual secret sharing of a decryption/re-encryption computation happening, only agreement-checking on identical cleartext-equivalent payloads.
6. Document security assumptions for threshold and interactive bootstrapping protocols.
7. Add adversarial tests for malformed shares and protocol confusion.

Exit criteria:

- Multiparty workflows remain deterministic and testable.
- Public protocol messages have documented compatibility and security boundaries.
- Production protocol work has a concrete threat model.

### Workstream 8 - Testing, Serialization, and Compatibility

Owned areas:

- all crates
- serialization modules
- test suites

Tasks:

1. Add golden-file serialization tests for public encodings.
2. Add version-mismatch and domain-mismatch tests for every serialized type.
3. Add fuzz/property tests for decode rejection where practical.
4. Add more randomized tests for scheme and lattice operations.
5. Add compatibility policy for serialization domains and version bumps.
6. Keep secret-bearing types non-serializable by default.

Exit criteria:

- Serialization formats are intentionally versioned and regression-tested.
- Decode rejection is tested beyond simple truncation cases.
- Secret serialization remains an explicit non-default decision.

### Workstream 9 - Performance and Benchmarking

Owned areas:

- `phantom-benches`
- hot paths across ring, lattice, schemes, bootstrapping, and multiparty

Tasks:

1. Keep current smoke benchmarks runnable without extra setup.
2. Decide whether to add Criterion.
3. If Criterion is approved, add benchmark groups for:
   - `ring_ntt`
   - `ring_rns`
   - `rlwe_encrypt`
   - `rlwe_keyswitch`
   - `bfv_eval`
   - `bgv_eval`
   - `ckks_eval`
   - `ckks_bootstrapping`
   - `multiparty`
4. Add benchmark parameters for toy, small, and eventually production-like sizes.
5. Track allocation counts for evaluator hot paths where possible.

Exit criteria:

- Performance regressions are visible before release.
- Benchmark documentation explains which numbers are smoke signals versus meaningful performance baselines.

### Workstream 10 - Alpha Release Checklist

Before tagging the next release:

1. Run:
   - `cargo fmt --all -- --check`
   - `cargo test --workspace --all-targets`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo doc --workspace --no-deps`
   - `cargo bench -p phantom-benches`
2. Run representative examples:
   - `cargo run -p phantom-examples --example bfv_basic`
   - `cargo run -p phantom-examples --example bgv_polynomial`
   - `cargo run -p phantom-examples --example ckks_rescale`
   - `cargo run -p phantom-examples --example ckks_bootstrapping`
   - `cargo run -p phantom-examples --example mpckks_interactive_bootstrap`
3. Confirm README roadmap, implementation plan, and release checklist agree.
4. Confirm all toy/scaffold warnings are present.
5. Write alpha release notes with:
   - implemented crate map
   - known scaffold limitations
   - security status
   - supported examples
   - planned production-hardening tracks

### Recommended Sequencing

1. Finish Phase 0 cleanup first: facade crate, CI, security/contributing docs, dependency policy.
2. Mark scaffold boundaries and feature-gate toy/experimental surfaces.
3. Harden `phantom-ring` with property tests and CPU backend benchmarks.
4. Move into production RLWE/RGSW internals.
5. Rebuild BFV/BGV/CKKS behavior on hardened lattice primitives.
6. Revisit circuits, bootstrapping, and multiparty once ciphertext semantics are real.

Completed implementation phases so far: Phase 1 (`phantom-utils`), Phase 2 (`phantom-ring`), Phase 3 (`phantom-lattice::rlwe`), Phase 4 (`phantom-lattice::rgsw`), Phase 5 (`phantom-schemes::bgv`), Phase 6 (`phantom-schemes::bfv`), Phase 7 (`phantom-schemes::ckks`), Phase 8 (`phantom-circuits::common`), Phase 9 (`phantom-circuits::bgv`), Phase 10 (`phantom-circuits::bfv`), Phase 11 (`phantom-circuits::ckks`), Phase 12 (`phantom-bootstrapping`), Phase 13 (`phantom-multiparty::common`), Phase 14 (`phantom-multiparty::mpbgv`), Phase 15 (`phantom-multiparty::mpbfv`), Phase 16 (`phantom-multiparty::mpckks`), Phase 17 (Serialization and compatibility), and Phase 18 (Examples, benches, and release hardening).
