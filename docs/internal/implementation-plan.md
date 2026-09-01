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

Current next implementation target: Alpha Hardening Workstream 5 (production BFV/BGV/CKKS track) - the next workstream up now that Workstream 4 (production RLWE/RGSW track) is complete. Workstreams 1 (Phase 0 cleanup), 2 (scaffold boundary and API honesty), 3 (ring and RNS foundation hardening, item 5b intentionally deferred, see its own entry), and 4 are done - see below.

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

1. [Done] Added property tests (`crates/phantom-ring/tests/property_tests.rs`, using `proptest` - added as a dev-dependency, exactly what `docs/internal/dependency-policy.md` pre-approved it for) covering all four named areas: modular arithmetic (`add_mod`/`sub_mod`/`neg_mod`/`mul_mod`/`pow_mod`/`inv_mod` - commutativity, associativity, distributivity, additive/multiplicative inverses, and a widened-`u128` reference check, generated across the *full* `u64` modulus range rather than a fixed iteration count), `BarrettReducer`/`MontgomeryReducer` (matching `mul_mod` across their respective full supported ranges), polynomial arithmetic (`Ring::add`/`sub`/`neg`/`mul` - the same ring-axiom properties, generated over arbitrary coefficient vectors), NTT round trips (forward+inverse recovers the original, generatively rather than via a fixed random-seed loop), and RNS reconstruction (`decompose_value`/`reconstruct_residue` round-trip identity, `extend_basis`'s target residues matching direct reduction of the true value, `drop_last_modulus` removing exactly the last component). These complement, not replace, `tests/phase2.rs`'s existing hand-seeded randomized tests - proptest's own RNG and generator composition reach a wider, more systematically-varied input space (with shrinking available if a failure is ever found).
2. [Done] Added larger randomized tests for basis extension and modulus dropping (`crates/phantom-ring/tests/rns_randomized.rs`). `extend_basis`: 40 cases at realistic RNS-CKKS/BGV scale (3-10 source moduli, 1-4 target moduli, drawn from a pool of 20 independently Miller-Rabin-verified ~51/~61-bit primes; source-basis products spanning 161-561 bits, always far beyond `u128`) generated offline in Python (arbitrary-precision integers - not this crate's own logic) and checked against `extend_basis`'s actual output, extending the single hardcoded 8-prime case from item 6 into real breadth across basis shapes and sizes. `drop_last_modulus`: 500 random trials varying both RNS component count (2-8) and polynomial degree (1-32), verifying every remaining component's coefficients are preserved exactly and the count shrinks by exactly one - the prior test only checked one fixed small shape. `rescale` (the scaling-by-approximately-`q_k` half of modulus switching) has no separate primitive to test yet - only `drop_last_modulus`'s truncation exists today, per `docs/technical-manual.md#ring-internals`'s own account, so there was nothing further to add there.
3. [Done, see item 10] Replace placeholder Gaussian-like sampling with a documented, cryptographically appropriate path or keep it explicitly toy-gated.
4. [Done] Replace the O(N²) direct-evaluation NTT with a real radix-2 Cooley-Tukey butterfly network (bit-reverse permute, then the standard iterative in-place stages; the twist/untwist steps around it are unchanged). Forward and inverse share one core function (`radix2_ntt_inplace`), run with `ω`/`ω⁻¹` respectively, by the standard NTT/DFT duality (forward structure + inverse root + `N⁻¹` scaling = inverse transform). Verified: a hand-derived reference case checked before the code was written, an independent direct-DFT comparison, and round-trip/vs-`schoolbook_mul` comparisons across six degrees (4-128) with ten random polynomials each. Measured ~414µs per forward+inverse round trip at `N=1024` (`crates/phantom-benches/benches/ring_ntt.rs`, updated from its previous `N=4` size specifically because that was too small to show the asymptotic difference). Not yet done: `Ring::schoolbook_mul` (still O(N²), still what every higher crate actually uses for multiplication - the new NTT isn't wired into it), lazy/deferred reduction between butterfly stages, Montgomery-form precomputed roots, loop unrolling - all performance follow-ups, not correctness gaps. See `docs/technical-manual.md#ring-internals` for the full account.
4a. [Done] Wire the real NTT into ciphertext multiplication. Added `Ring::mul` (NTT via a per-modulus `NttTable` cached at `Ring::new`, falling back per-component to `schoolbook_mul`'s O(N²) approach for any modulus that doesn't support NTT at this degree - `schoolbook_mul` itself is untouched, kept as the always-correct reference `mul`'s NTT path is tested against). Switched every real call site in `phantom-lattice::rlwe` (`Encryptor`, `Decryptor`, `KeyGenerator::generate_public_key`, `Evaluator::mul`) and `rgsw::external_product` from `schoolbook_mul` to `mul`. Verified by the full workspace test suite passing unchanged (`mul` and `schoolbook_mul` compute identical results) plus dedicated `Ring::mul`-specific tests, including the NTT-unsupported fallback path and unreduced-coefficient safety. `rlwe_encrypt` bench updated from `N=4` to `N=1024` (`~883us` per encryption, 100 iterations combined) to actually exercise the NTT path it now goes through; `rlwe_keyswitch` left at `N=4` since it only benchmarks `key_switch_identity`/`relinearize`, both identity-function placeholders that call no multiplication at all.
4b. [Done] Closed two of item 4's "not yet done" gaps for the NTT hot path specifically (distinct from item 5b, which is the further `[0, 2·modulus)`-lazy-correction technique, still open). `NttTable` now precomputes `psi_powers`/`inv_psi_powers` (`psi^j mod q` for every `j`, via one `O(n)` running-product pass at table-construction time) instead of `forward_component`/`inverse_component` each calling `pow_mod(psi, j, q)` fresh per coefficient (`O(n log n)` total, recomputed on every single multiplication since these components aren't cached across calls the way the table itself is). `NttTable` also now precomputes a `BarrettReducer` for its modulus, and every multiplication in the twist step and the butterfly network (`radix2_ntt_inplace`, `forward_component`, `inverse_component`) routes through it via a `mul_residue` helper with the same `< modulus` defensive guard `Ring::mul_residue` uses, replacing division-based `mul_mod`. Verified by the full existing NTT/`Ring::mul` test suite passing with identical results (this changes performance, not output), plus two new tests cross-checking the precomputed power tables against independent `pow_mod` calls. Measured: the `ring_ntt` forward+inverse round trip at `N=1024` dropped from ~414µs to ~110-130µs (100 iterations combined) - roughly a 3.5-4x speedup - and `rlwe_encrypt` at the same size dropped from ~883µs to ~316µs per encryption, both `crates/phantom-benches/benches/`.
5. [Done] Implement real Barrett and Montgomery reduction in `phantom_ring::reduce`. `BarrettReducer` now does precomputed multiply-and-shift with correction; `MontgomeryReducer` implements real REDC with a Newton-Raphson 2-adic inverse, plus `to_montgomery`/`from_montgomery`/`mul_montgomery` for staying in Montgomery form across a chain of operations. See item 5c for the full-64-bit-range version of `BarrettReducer` described here. Validated by exhaustive tests (all moduli 3-199, full value range) plus thousands of randomized large-modulus cases (`crates/phantom-ring/tests/phase2.rs`), and a standalone unit test for the Newton-Raphson inverse.
5a. [Done] Wire `BarrettReducer` into `Ring`'s actual arithmetic: one reducer is precomputed per modulus at `Ring` construction, and `coeffwise_mul`/`schoolbook_mul`/`scalar_mul_assign` route through a new `mul_residue` helper. That helper checks both operands are already `< modulus` before taking the fast path — `Poly`'s type doesn't enforce that invariant, and `BarrettReducer::reduce`'s precondition is narrower than `mul_mod`'s unconditional correctness, so anything out of range falls back to the widened `u128` path rather than risking a wrong result. Covered by a dedicated regression test constructing deliberately out-of-range coefficients (`ring_multiplication_is_correct_even_for_unreduced_coefficients`). `add_assign`/`sub_assign`/`neg_assign` are unchanged (addition doesn't benefit the way multiplication does). `MontgomeryReducer` is not wired in yet — it needs a hot path that stays in Montgomery domain across a whole chain of operations (e.g. the real NTT in item 4) to be worth its conversion overhead, not a single-multiplication swap.
5b. Add lazy/deferred-correction reducer variants (returning `[0, 2·modulus)` rather than fully reducing) for the tight-loop performance a real NTT still needs beyond what item 4b's full-reduction `BarrettReducer` wiring already captured - the further step of eliding most of the *correction* work itself (e.g. Harvey-style butterflies operating on values kept in `[0, 4·modulus)` across stages), not just replacing division with Barrett's multiply-and-shift.
5c. [Done] Extended `BarrettReducer` past its old `FAST_REDUCER_MAX_MODULUS` (`2^32`) cap to the **full 64-bit modulus range** (`modulus >= 2`) via real wide (128×128→256-bit) multiplication: `mu = ⌊2^128/modulus⌋` is computed exactly through a new minimal internal `BigUint` (`crates/phantom-ring/src/bignum.rs` - moved from `rns/` to the crate root so both `rns::extension::extend_basis` and this can share it; also gained `from_u128`/`to_u128`/`shl_limbs`/`mul` on top of what `extend_basis` needed), and reduction itself uses a dedicated stack-only `mul_wide_128` (four 64x64->128-bit partial products with explicit carry propagation into a fixed `[u64; 4]` accumulator - no heap allocation, since this is `Ring`'s hot multiplication path). Proved (and Monte-Carlo-verified, 200k random cases, before shipping) that `reduce`'s precondition generalizes from `value < modulus^2` to the wider `value < modulus * 2^64` - still short of the full `u128` range, which was an incorrect claim caught and corrected before landing (a small modulus with `value` near `u128::MAX` needs a quotient wider than 64 bits, which this implementation doesn't support). `MontgomeryReducer` was not extended the same way (its `redc` accumulator would need to grow past `u128` too, real follow-up work) but its artificial shared cap was replaced with its own natural, derived bound: `MONTGOMERY_MAX_MODULUS = 2^63`, the exact point past which `redc`'s `t + u*modulus` step stops fitting a `u128` accumulator. `RingError::ModulusTooLargeForReducer` is now Montgomery-specific; added `RingError::ModulusTooSmall` for Barrett's `modulus < 2` rejection. Verified by: exhaustive/randomized tests across the full 64-bit range (not just `<2^32`), a dedicated test against four ~61-bit NTT-friendly primes (the realistic RNS-CKKS/BGV size this was blocking), and `mul_wide_128` cross-checked against an independently-written heap-based `BigUint::mul` (2000 random cases) plus a Python-computed reference product for `u128::MAX * u128::MAX`.
6. [Done] Replaced `rns::extension::extend_basis`'s `u128`-based CRT round trip, which silently overflowed for realistic multi-modulus bases (e.g. eight or more ~60-bit primes exceeds `2^128`), with an exact reconstruction over a new minimal `BigUint` type (`rns/bignum.rs`: base-`2^64` limbs, `add`/`sub`/`mul_u64`/`divmod_u64`/`cmp` - no general bignum/bignum division anywhere). The CRT sum is bounded at `< k · Q` (`k` = source modulus count, `Q` = their product), so reducing it back under `Q` only needs a bounded subtraction loop, not division. This is an exact-arithmetic choice, not the classic RNS-native BEHZ/HPS algorithms, which instead use fast per-modulus floating-point approximation to avoid bignums entirely at the cost of a small, carefully-bounded approximation error; that remains a valid future performance upgrade once there's profiling data showing this path is hot (see item 9). Verified against: the crate's own exhaustive/randomized `BigUint` primitive tests, the pre-existing small-basis test unchanged, and a new large-basis regression test (`extend_basis_is_exact_for_a_realistic_multi_prime_basis_that_overflows_u128`, `phantom-ring/tests/phase2.rs`) using an 8-prime ~489-bit basis checked against values independently computed in Python (arbitrary-precision integers, not this crate's own logic) - exactly the scenario that would have silently overflowed the old `u128` path. This is also what real RNS-based key-switching (Workstream 4) needs underneath it.
7. [Done] Audited allocation patterns in `phantom-ring`'s hot paths (`Poly`, `Ring::mul`/`schoolbook_mul`/`coeffwise_mul`, `ntt::cpu`, `ntt::table`) and `phantom-lattice::rlwe`'s callers. Highest-impact finding: `Ring::mul`'s NTT branch did four heap allocations per NTT-supporting modulus per call (`forward_component` twice - once per operand - plus `inverse_component`'s internal `to_vec()` and `vec![0u64;n]`), plus a further wasted allocation from `self.zero()` immediately discarded and replaced by `inverse_component`'s return value. Lower-priority findings: `NttBackend::forward`/`inverse` clone the input and allocate an output per call, but that trait impl is confirmed (by grep) unused by `Ring::mul` or any `phantom-lattice` code today - purely a smoke-bench/test path, not production-hot; `NttTable::new`'s own construction-time allocations (power tables, primitive-root search) run once per `Ring`, not per multiplication; `phantom-lattice::rlwe::evaluator`'s `add_plain`/`rotate_coefficients` clone the whole ciphertext to mutate one component, inherent to the crate's `&Ciphertext -> Ciphertext` value-semantics API, not easily avoidable without `Rc`/COW - not worth the added complexity here.
8. [Done] Added in-place variants for the item 7 finding that mattered: `ntt::cpu` gained `forward_transform_in_place`/`inverse_transform_in_place` (fully in place - safe because each coefficient's twist/untwist value depends only on that same coefficient's own input, never a value another iteration already overwrote) and `forward_component_into` (writes into a caller-provided buffer when the input must survive). `Ring::mul`'s NTT branch now allocates exactly one scratch buffer per call (reused across every RNS component, not re-allocated per modulus) instead of four-plus-one: `lhs`'s forward transform and the final product both write directly into `out`'s own already-allocated component, and only `rhs`'s transform needs the separate scratch space. `NttBackend::forward`/`inverse` were updated the same way (transform directly into `poly.coeffs_mut()[j]`, no clone) even though that path is cold, since the fix was free once the in-place primitives existed. Verified by the full existing NTT/`Ring::mul` test suite (including the property-based ring-axiom and unreduced-coefficient regression tests) passing with identical results - this changes allocation count, not output. **Honestly measured, not claimed:** a before/after `rlwe_encrypt` smoke-bench comparison (`git stash` on just this change, same machine, back-to-back runs) showed no distinguishable difference - both landed in the same ~43-61ms/100-iterations noise band. The allocation-count reduction is real and verifiable by code inspection; its wall-clock effect at this scale is not visible above smoke-timing's own noise floor without a statistically rigorous benchmark (i.e. exactly what item 9's deferred Criterion adoption would provide) - recorded honestly rather than reported as a measured speedup it isn't.
9. [Done, smoke half] Extended smoke benchmarks: added `ring_extend_basis` (`crates/phantom-benches/benches/`), the one hardened piece of RNS code from items 2 and 6 that had zero performance visibility until now - an 8-source/2-target-modulus basis at `N=1024` (the same source basis size as the `extend_basis` regression test). Measured ~530-720µs per call, 100 iterations combined - meaningfully higher than `ring_ntt`'s ~110-130µs at the same degree, consistent with `extend_basis`'s per-coefficient `BigUint` heap allocations (see item 7/8's allocation audit) being real, uninvestigated cost. Replacing smoke timing with Criterion is deliberately *not* done here - `docs/internal/dependency-policy.md` pre-approves that specifically once Workstream 9 (Performance and Benchmarking) is picked up, not before, so doing it now would jump the sequencing the policy itself set up.
10. [Done] Replaced the placeholder uniform-in-range Gaussian sampler with a real discrete Gaussian, via a cumulative distribution table (CDT) over a support truncated to `±6·sigma` (the true tail beyond that integrates to ~`2e-9`, negligible against any practical sample count) - draw one uniform `u64`, walk the table to find the matching cumulative-probability bucket. Deliberately **not constant-time**: the walk short-circuits at the matching bucket, so execution time depends on the sampled value; a side-channel-hardened deployment needs every entry touched unconditionally or a Knuth-Yao/Ziggurat construction instead - noted explicitly rather than silently assumed away, per this item's own instruction to decide deliberately. The public API changed from an integer uniform-range `bound: u64` to the actual standard deviation `sigma: f64` (`sample_discrete_gaussian`'s own signature, and `SecretDistribution::Gaussian { sigma }` in `phantom-lattice::rlwe::keygen` - its only real call site). Verified by: the table's cumulative sum landing at exactly `1.0` across several `sigma` values (forced past floating-point rounding so sampling always terminates), samples staying within the truncated support, and an independent statistical check (200,000 samples, empirical mean/stddev within a sample-count-derived tolerance of the target `0`/`sigma`) - `crates/phantom-ring/src/sampling/gaussian.rs`. Not yet wired into any scheme's actual encryption error (`phantom-lattice::rlwe::Encryptor` still samples no error term - Workstream 4 item 1); reachable today only via `SecretDistribution::Gaussian` as an alternative secret-key distribution.

Exit criteria:

- [Met] Ring operations have stronger randomized coverage: property tests (item 1) covering modular/polynomial/NTT/RNS properties across the full `u64` modulus range, plus 40 independently-computed large-scale RNS basis-extension cases and 500 randomized modulus-dropping trials (item 2).
- [Met] The CPU backend has baseline performance data: `ring_ntt`, `ring_rns`, `ring_extend_basis`, `rlwe_encrypt` smoke benchmarks with recorded numbers (item 9, smoke half - Criterion adoption remains deliberately deferred to Workstream 9 per `dependency-policy.md`).
- [Met] Sampling status is explicit and not silently production-claimed: `sample_discrete_gaussian` is now a real CDT-based discrete Gaussian (items 3/10), explicitly documented as not constant-time and not yet wired into any scheme's encryption noise.
- [Met] The NTT is a real O(N log N) transform, and Barrett/Montgomery reducers implement their named algorithms.
- [Met] Barrett reduction is wired into `Ring`'s actual arithmetic, not a standalone unused type (item 5a).

Workstream 3 is now effectively complete; item 5b (true Harvey-style `[0, 2·modulus)`-lazy-correction NTT butterflies, as opposed to item 4b's full-reduction-but-faster-reducer wiring) remains intentionally deferred - it is real further optimization, not a correctness gap or an unmet exit criterion, and its bound-tracking across multiple butterfly stages is meaningfully higher-risk to get subtly wrong than anything else in this workstream.

**Post-hoc fix (found while starting Workstream 4 item 3):** `phantom_ring::sampling::sample_ternary`/`sample_discrete_gaussian` sampled independently per `(RNS component, coefficient)` pair instead of drawing one true small value per coefficient and reducing it identically into every component - invisible on every single-modulus ring this crate's tests happened to use (including this workstream's own item 1/2 test coverage above), but a real CRT-coherence break the moment a ring has more than one modulus, which is the entire premise of RNS and exactly what hybrid key-switching needs. Fixed, with a dedicated regression test (`ternary_and_gaussian_samples_are_crt_coherent_across_rns_components`, `phantom-ring/tests/phase2.rs`) confirmed - by literally reverting the fix and re-running it - to fail against the old code and pass against the new. `sample_uniform`'s own per-component independence is unaffected and correct (CRT is a bijection, so independent uniform draws per modulus are exactly how you sample a value uniform over the product range) - only the two "true small value" samplers needed the fix. Every existing single-modulus test's fixed-seed output is unchanged (identical RNG call count and order), so nothing downstream needed updating.

### Workstream 4 - Production RLWE/RGSW Track

Owned areas:

- `phantom-lattice::rlwe`
- `phantom-lattice::rgsw`

Tasks:

1. [Done] Replaced toy exact encryption internals with real RLWE encryption semantics. `KeyGenerator::generate_public_key` now samples a real error term into `b = -(a*s + e)`; `Encryptor::encrypt` samples a real error into the secret-key path (`c_0 = pt - a*s + e`) and two real errors plus the public key's own baked-in one into the public-key path (`c_0 = pt + b*u + e_1`, `c_1 = a*u + e_2`). Both use `phantom_lattice::security::STANDARD_ERROR_STD_DEV` (σ≈3.2, from item 10). `phantom_lattice::rlwe::Decryptor` was never given a rounding/mod-t step, so at this raw layer decryption now honestly returns "plaintext plus small noise," not the plaintext exactly - grep-confirmed that no other crate depends on this layer's exact-decrypt behavior (`phantom-schemes::bgv`/`bfv` bypass `rlwe::Encryptor`/`Decryptor` entirely with their own transparent scaffold, and `ckks` doesn't touch `rlwe` at all), so this was safe to change without touching any scheme crate - only `phantom-lattice`'s own tests needed updating. Rewrote `tests/phase3_rlwe.rs` and `tests/phase4_rgsw.rs` accordingly: replaced exact-equality assertions with a centered-residue noise-bound check (`assert_noise_bounded`, checked against item 2's bounds below), and replaced the old degree=4/modulus=17 toy ring (which has no room for real σ=3.2 noise at all - its own ~6σ tail alone can reach 20, larger than the whole modulus) with realistically-sized NTT-friendly rings chosen with real headroom over even the worst-case post-multiplication noise bound, not just fresh-encryption noise.
2. [Done, worst-case half] Added `phantom_lattice::noise`: sound (not tight) worst-case noise-growth bounds - `ring_product_bound` (the standard triangle-inequality bound for a negacyclic ring product, `degree * bound_a * bound_b`), `fresh_secret_key_noise_bound`/`fresh_public_key_noise_bound` (derived from the RLWE decryption-noise algebra for each encryption path), and `mul_noise_bound` (derived the same way for a raw ciphertext-ciphertext product). Explicitly scoped as the sound foundation, not the tight probabilistic bound a full noise-tracking system would have (real noise growth is typically far smaller than these bounds thanks to random sign cancellation across a ring product's terms, `sqrt(degree)` rather than `degree`) - tightening that remains real future work, not attempted here.
3. [Done, general primitive] Implemented real RNS hybrid key-switching (`phantom_lattice::rlwe::{generate_key_switch_key, key_switch}`) - gadget-decompose the input ciphertext's `c1` *per RNS modulus* (`L` digits for an `L`-modulus working basis `Q`, not the many more a classical power-of-base decomposition would need), lift each digit into an extended basis `QP = Q ∪ P` (via Workstream 3 item 6's `extend_basis`, from the single-modulus source basis `{q_j}` - confirming the plan's own prediction that item 6 would feed into this), dot-product against key-switching-key rows generated in `QP`, then "mod down" back to `Q` (new `phantom_ring::rns::rescale::mod_down`, derived and independently Python-verified alongside a new `phantom_ring::rns::extension::crt_basis_constant` this needed too - see their own commit). Each key-switching-key row encrypts `P · (Q/q_j) · s_old`, not just `(Q/q_j) · s_old` - omitting that factor of `P` was an actual bug caught by hand-deriving and numerically verifying the whole algorithm in Python (200+ randomized trials) *before* writing any Rust; see `keyswitch.rs`'s own module doc comment for the full derivation. Verified in Rust by 5+ independent randomized trials (`tests/key_switch.rs`) on a genuinely multi-modulus `Q` (3 moduli, with a comparably-sized 2-modulus `P`) - deliberately not a single-modulus basis, which would never exercise what makes this RNS key-switching rather than a textbook one. Scoped as the *general* primitive: `generate_key_switch_key` takes `s_old` already lifted into `QP` by the caller (a new `rebase_ternary_secret` helper does this for ternary secrets directly; a non-ternary `s_old` like relinearization's `s^2` needs a different, genuine CRT-based centered lift, deliberately left for item 4 to build rather than folded in here) and requires `s_new` to be ternary. Item 4 (relinearization) and item 5 (Galois rotation) can now build on this rather than needing their own key-switching machinery.

**Also surfaced and fixed a real, separate bug**: key-switching was the first thing in this codebase to genuinely need more than one RNS modulus at once, which is what exposed that `phantom_ring::sampling::sample_ternary`/`sample_discrete_gaussian` sampled independently per RNS component instead of once per coefficient - see the dedicated commit fixing it, between Workstream 3's closure and this item.
4. [Done] Implemented production relinearization. Turned out **not** to need the centered CRT lift this item's own earlier note predicted: verified numerically first (Python, 100 randomized trials with non-ternary values) that for *any* representative `T` of `s²`'s true value congruent mod `Q` - in particular the raw `[0, Q)` value `extend_basis` already produces, no centering needed - `P · (Q/q_j) · T ≡ P · (Q/q_j) · s² (mod QP)`, because `P · (Q/q_j) · Q` is itself an exact multiple of `QP`. So `s²`'s `QP`-basis representative for `generate_key_switch_key`'s `s_old` is just `extend_basis(ring.mul(s, s), q_basis, qp_basis)` directly. Added `KeyGenerator::generate_hybrid_relinearization_key(sk, p_moduli, rng)` (real key generation) and wired `Evaluator::relinearize` to use it via `key_switch` when given one - treating a degree-2 ciphertext's `c2` component as the `c1` half of a throwaway `(0, c2)` ciphertext, key-switching that from `s²` to `s`, and folding the result into `c0`/`c1`. `RelinearizationKey` changed from a unit-struct placeholder to a type holding `Option<KeySwitchKey>` (`RelinearizationKey::placeholder()` preserves the old identity behavior exactly; `::from_key_switch_key` is the real one) specifically so every existing caller across `phantom-schemes` (BGV, CKKS) and `phantom-multiparty` (which all only ever construct the placeholder, since none of them have a concept of the auxiliary `P` moduli a real key needs - genuinely Workstream 5 scope, not reopened here) keeps compiling and behaving identically with zero changes beyond `RelinearizationKey` → `RelinearizationKey::placeholder()` at each construction site. Verified end to end in Rust (`tests/phase3_rlwe.rs::real_relinearization_reduces_degree_and_preserves_the_product`): multiply, relinearize with a real key, decrypt, check against the true product within a noise bound, and confirm `relinearized.degree() == 1`. Updated the `rlwe_keyswitch` benchmark to measure this real path (~8µs per relinearization at `N=8`) instead of the old placeholder no-op it used to time.
5. [Done] Implemented production Galois-automorphism-based rotation. Added `phantom_ring::Ring::apply_automorphism(poly, k)`: for `R = Z[X]/(X^N+1)`, applies `σ_k: X -> X^k` (valid for any `k` coprime to `2N`) independently per RNS component - coefficient `i` moves to position `m = (i*k) mod 2N` if `m < N`, or to `m - N` negated if `m >= N` (since `X^N ≡ -1`). Hand-derived, checked against direct polynomial substitution `p(X^k) mod (X^N+1)` in Python first, then re-verified in Rust (`phantom-ring/tests/automorphism.rs`) against that same substitution plus two algebraic properties any genuine ring automorphism must satisfy across random trials: `σ_k(a*b) == σ_k(a)*σ_k(b)` (all 8 valid elements for `2N=16`) and `σ_k1(σ_k2(p)) == σ_{k1*k2 mod 2N}(p)`. `GaloisKey` got the same two-state redesign `RelinearizationKey` got in item 4 (`GaloisKey::new` - unchanged, the identity-preserving placeholder every existing caller across `phantom-schemes`/`phantom-multiparty` still gets; `GaloisKey::from_key_switch_key` - real, an RNS hybrid key-switching key from `σ_element(s)` to `s`, produced by new `KeyGenerator::generate_hybrid_galois_key`). Unlike relinearization's `s²`, `σ_element(s)`'s coefficients are just `s`'s own ternary values permuted and sign-flipped (proven algebraically: multiplication by an element coprime to `2N` is a bijection on `Z/2N` that commutes with the `x -> x+N` shift, so it induces a bijection on the `N` folded positions with no accumulation), so it stays ternary and reuses item 3's `rebase_ternary_secret` directly rather than needing a CRT lift. New `Evaluator::apply_galois_automorphism(ct, key)` applies `σ_element` to both ciphertext components (any ring automorphism preserves the encryption relation: `c0+c1*s=mu+e` becomes `σ(c0)+σ(c1)*σ(s)=σ(mu)+σ(e)`), then key-switches the result from `σ(s)` back to `s` via `key_switch` - same placeholder-returns-`ct.clone()` behavior as `relinearize` when given a placeholder key. `Evaluator::rotate_coefficients` (raw coefficient rotation, no key involved) is untouched - `phantom-schemes::bgv::Evaluator` still calls it directly, and it has no key parameter to redesign around. Also deleted `phantom_lattice::rlwe::AutomorphismKey` (`automorphism.rs`): grep-confirmed dead code, referenced only by its own module, superseded by `GaloisKey` actually doing the job. Verified end to end (`tests/phase3_rlwe.rs::real_galois_automorphism_matches_plaintext_sigma_and_preserves_decryptability`): encrypt, apply a real Galois key, decrypt, check against `σ_element` applied directly to the plaintext within a noise bound.
6. [Done] Implemented production coefficient repacking (`phantom_lattice::rlwe::{repacking::repack, Evaluator::repack}`), replacing `repacking::repack_identity` (deleted - grep-confirmed it had zero callers anywhere, same as `AutomorphismKey` before it). Standard monomial-shift-and-sum technique: given several ciphertexts each encrypting a scalar message at coefficient 0 under the *same* secret key, multiplying `ct_i` by the public monomial `X^i` is linear and stays valid under the same secret (no key-switching needed, unlike items 4/5 - this is closer in kind to `add_plain`), turning `c0 + c1*s = m + e` into `X^i*c0 + X^i*c1*s = X^i*m + X^i*e`; summing over every `i` lands each input's message at its own coefficient of one output ciphertext. Rejects empty input and rejects more ciphertexts than the ring's degree (packing that many would alias positions via the ring's negacyclic wraparound, `X^N = -1`, rather than erroring - checked numerically in Python before implementing, alongside the core algorithm itself on a small concrete example). Verified end to end (`tests/phase3_rlwe.rs::repack_combines_scalar_ciphertexts_into_one_coefficient_packed_ciphertext`): encrypt several scalar messages independently, repack, decrypt, check against the coefficient-packed plaintext within a noise bound (`N * fresh_secret_key_noise_bound()`, the same worst-case triangle-inequality style item 4/5's own key-switching margin uses); plus a rejection test for both error paths.
7. [Done] Replaced the plaintext-backed `RgswCiphertext` scaffold with a real encrypted gadget matrix - the standard GSW/RGSW construction. `RgswCiphertext::encrypt` builds two blocks of `levels` real RLWE ciphertexts: `rows()[0][i] = RLWE_s(B^i * message)`, `rows()[1][i] = RLWE_s(B^i * message * s)` (`B = 2^base_log`), each a fresh RLWE-of-zero (via `Encryptor::with_secret_key`, so real sampled noise) with the gadget-scaled message added into `c0`. No downstream call sites existed anywhere in the workspace (grep-confirmed), so the old plaintext-backed API (`message()`, `from_message()`) was removed outright rather than kept alongside the real one - keeping a field that stores the plaintext directly on a type meant to represent an *encrypted* ciphertext would defeat the point, not just be redundant.
8. [Done] Implemented the real external product: `external_product(RGSW(m), ct)` gadget-decomposes `ct`'s `c0`/`c1` via the existing `GadgetDecomposition::decompose` (already production-shaped per this item's own note - now actually consumed) and computes `sum_i c0_i * rows()[0][i] + sum_i c1_i * rows()[1][i]`. Hand-derived before implementing (see `external_product.rs`'s doc comment for the full derivation): this recovers `RLWE_s(m * mu)` with noise `m*e_ct + sum_i c0_i*e_i + sum_i c1_i*e'_i` (`e_ct` = the input ciphertext's own noise, `e_i`/`e'_i` = each RGSW row's fresh noise) - added `phantom_lattice::noise::external_product_noise_bound` for the corresponding worst-case bound, same technique as items 1/2. Verified against `schoolbook_mul(pt, multiplier)` via the same centered-residue noise-bound comparison `tests/phase3_rlwe.rs` established, at a realistically-sized ring (the old degree=4/modulus=97 ring is kept only for the noise-free structural tests - parameter validation, gadget decompose/recompose - which don't involve encryption at all).
9. [Done] Added `crates/phantom-lattice/tests/randomized.rs`: 300-trial randomized coverage (`ChaCha20Rng`, matching `phantom-ring/tests/rns_randomized.rs`'s established style - hundreds of trials inside one `#[test]`, not one `#[test]` per case) for every real operation this workstream built - secret-key and public-key encrypt/decrypt round trips, add/sub, multiplication, real relinearization (item 4), real Galois automorphism (item 5), repack (item 6), and RGSW external product (item 8) - each checked against an independently computed reference (direct ring arithmetic, `schoolbook_mul`, or `apply_automorphism` applied to the plaintext directly) within the appropriate noise bound from `phantom_lattice::noise`, complementing the fixed-seed handful-of-cases coverage `phase3_rlwe.rs`/`phase4_rgsw.rs` already had. Key material (secret key, relinearization key, Galois key, RGSW key) is generated once per test and reused across trials - only plaintext content and encryption randomness vary per trial, matching realistic usage rather than paying key-generation cost 300 times over. All 8 new tests passed on first attempt.
10. [Done] Added `phantom_lattice::security`, grounding standard deviation, noise bound, and secret-distribution choices in literature-standard values: `STANDARD_ERROR_STD_DEV = 3.2` and `ERROR_TAIL_CUT_STD_DEVS = 6.0` (the homomorphicencryption.org security standard and the BFV/BGV/CKKS papers converge on σ≈3.2 with a 6σ tail cut - the same tail cut `phantom_ring::sampling::sample_discrete_gaussian` already uses internally, now named and justified at the crate level too), `fresh_error_bound()` (`ceil(sigma * tail_cut)`), and `recommended_secret_distribution()` (ternary). This is what item 1's real RLWE noise is actually grounded in, not an ad hoc number. Workstream 2 item 2 (separating toy from production presets) can now mean something - there's a documented value to ground a "production preset" in - though the presets themselves haven't been split yet (still Workstream 2's own deferred item, not reopened here).

Exit criteria:

- [Met] RLWE operations are no longer transparent/toy: encryption and key generation sample real noise (item 1), key switching, relinearization, Galois rotation, and repacking are all real (items 3, 4, 5, 6), and RGSW encryption/external product are a real gadget-matrix construction rather than plaintext-backed (items 7, 8).
- [Met] Key switching, relinearization, and Galois rotation have meaningful cryptographic behavior: real RNS hybrid key-switching (item 3) with relinearization (item 4) and Galois rotation (item 5) both built on it, verified end to end.
- Higher scheme crates can build production BFV/BGV/CKKS semantics on top. Not yet met - BGV/BFV/CKKS still only construct the identity-preserving placeholder keys (no concept of the auxiliary `P` moduli real key-switching needs), which is genuinely Workstream 5 scope to change, not reopened here.
- [Met] A parameter set's standard deviation/bound/distribution choices are traceable to a documented security rationale, not just a number that happens to work in tests: `phantom_lattice::security` (item 10).

Workstream 4 is now complete except for the one exit criterion that is explicitly Workstream 5's own job to satisfy (higher scheme crates consuming these real primitives) - every item (1-10) is done, `phantom-lattice::rlwe`/`rgsw` now have real noise, real RNS hybrid key-switching, real relinearization, real Galois rotation, real repacking, and a real RGSW gadget construction, all verified end to end including 300-trial randomized coverage.

### Workstream 5 - Production BFV/BGV/CKKS Track

Owned areas:

- `phantom-schemes::bfv`
- `phantom-schemes::bgv`
- `phantom-schemes::ckks`

Tasks:

1. [Done, BGV+BFV core] Replaced transparent BGV/BFV ciphertext semantics with real scheme behavior, in a backward-compatible dual-mode design (`with_secret_key`/`with_public_key` stay the existing transparent no-op; new `with_secret_key_real`/`with_public_key_real` do genuine encryption) so every existing caller across `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/`phantom-examples` keeps compiling and behaving identically. Real BGV needs noise scaled by the plaintext modulus `t` (`c0 = m + t*e - a*s`, `c1 = a` for secret-key; `c0 = m + b*u + t*e0`, `c1 = a*u + t*e1` for public-key - the public key's own noise must also be `t`-scaled, new `BgvKeyGenerator::generate_keypair_real`, or it survives decryption's final `mod t` reduction and corrupts the result), so it can't reuse the generic `phantom_lattice::rlwe::Encryptor`'s raw-noise formula directly - implemented natively in `phantom-schemes::bgv` on `phantom_ring`'s `Ring`/sampling primitives instead. `decode_u64` and `Decryptor::decrypt` needed zero changes (already do exactly the centered-mod-`t` reduction and degree-agnostic `sum_i c_i*s^i` decode real BGV needs), and neither did `Evaluator::add`/`sub`/`neg`/`add_plain`/`mul`/`mul_plain` (pure ring arithmetic, provably preserves "noise is a multiple of `t`" regardless of which mode produced the ciphertext - verified both algebraically and with 50-80 randomized trials in `tests/phase5_bgv.rs`, at a realistically-sized ring the existing toy `[257, 769]`/`t=17` preset has no room for). Relinearization stays the existing no-op deliberately - real BGV relinearization needs the key-switching key's own noise to *also* be `t`-scaled (or it corrupts the mod-`t` invariant after relinearizing, unlike raw multiplication, whose noise is entirely the inputs' own already-`t`-scaled noise), which is out of scope here.

   Real BFV (genuinely separate math from BGV, confirmed while investigating: the pre-existing "BFV" scheme was actually just BGV's exact coefficient-mod-`t` scheme relabeled - identical encode/decode/multiply, no Δ-scaling anywhere) scales the *message* by `Delta = floor(Q/t)` instead of scaling noise (`c0 = Delta*m + e - a*s`, `c1 = a` for secret-key; `c0 = Delta*m + b*u + e0`, `c1 = a*u + e1` for public-key, both with *raw*, unscaled noise). Unlike BGV, a standard generic RLWE public key works unchanged for BFV's real path - no special key-generation needed, `BfvKeyGenerator::generate_keypair` is reused as-is for both transparent and real. `Delta` doesn't fit in a `u64` for a multi-modulus ring, so applying it needed a new generic RNS primitive, `phantom_ring::rns::extension::floor_divide_residues(basis, divisor)` (computes `floor(product(basis.moduli())/divisor) mod q_j` per modulus - genuinely a floor division, unlike the existing `crt_basis_constant`'s always-exact one), verified against Python-computed values (`tests/floor_divide.rs`). Decoding needs a matching real path too, new `BatchEncoder::decode_u64_real`/`decode_i64_real` (BFV's standard round-and-rescale-by-`t/q` step, `decode_bfv_residue`) - `Decryptor::decrypt` itself needed no change, same as BGV. Verified end to end in `tests/phase6_bfv.rs`: secret-key round trip, public-key round trip, and ciphertext-ciphertext add/sub/neg, each across 50 randomized trials, all passing on the first attempt after the core derivation was verified in Python.

   [Done] Real BFV multiplication (`Evaluator::mul_real`), the piece deliberately deferred when the above landed - turned out to need a genuinely bigger primitive than expected. A raw ciphertext-ciphertext tensor product's true coefficient magnitude can reach roughly `degree * (Q/2)^2` - far beyond what `Q` alone can represent without wraparound (`Ring::mul`'s ordinary mod-`Q` output loses exactly the information the rescale step needs, confirmed by first deriving this wrong and catching it before writing any Rust) - so both ciphertexts are extended into an auxiliary `Q ∪ P` basis (`P` sized comparably to `Q` itself, via `extend_basis`) where the tensor product is computed without wraparound, then rescaled back down. That rescale needed genuine bignum/bignum division with correct rounding - `Q` doesn't fit in a `u64` for a multi-modulus ring - which `phantom_ring::bignum::BigUint` didn't have (by design; its own doc comment explicitly called this out as unneeded until now). Added `BigUint::divmod` (binary long division, chosen for straightforward correctness over a faster multi-limb-digit algorithm - not hot-path-critical, called once per coefficient) with its own dedicated tests: an independently Python-computed multi-limb case, a 200-trial algebraic property check (`quotient*divisor+remainder == self`), and a cross-check against the existing `divmod_u64` for single-limb divisors. Factored `extend_basis`'s CRT-reconstruction loop into a shared `reconstruct_true_values` helper (behavior-preserving - all of `extend_basis`'s own existing tests still pass unchanged) so the new `phantom_ring::rns::rescale::rescale_and_round(poly, q_basis, p_basis, t)` could reuse it: reconstructs each coefficient's true value, centers it into `(-QP/2, QP/2]`, computes `round(|centered| * t / Q)` via the new `divmod` with round-half-up, and reduces the signed result back into `q_basis`'s own moduli. Verified numerically in three independent passes before implementing: true unbounded-integer arithmetic (no modular reduction at all), an RNS-mechanized simulation using actual CRT reconstruction from residues, and both cross-checked against real BFV encrypt/multiply/decrypt round trips (30 trials each) - then `rescale_and_round` itself got both a fixed independently-computed-case test and a 200-trial randomized property test in Rust (`tests/rescale_and_round.rs`) before `Evaluator::mul_real` was wired up. `mul_real` produces a degree-2 (unrelinearized) result, verified end to end against a `schoolbook_mul` oracle across 30 randomized trials (`tests/phase6_bfv.rs`), passing on the first attempt.

   [Done] `Evaluator::add_plain_real` (BFV): adding a real ciphertext's raw plaintext operand directly (`add_plain`'s existing behavior) is wrong once `c0` holds `Delta*m1 + noise` rather than `m1` - `add_plain_real` scales the plaintext operand by `Delta` first (reusing `Encryptor`'s own `scale_by_delta`, made `pub(crate)` for this), so `c0 + Delta*m2` correctly combines to `Delta*(m1+m2) + noise`. `mul_plain` needed **no** such counterpart - an assumption in this plan's own earlier text, corrected once actually checked: multiplying by a small, unscaled plaintext doesn't have addition's problem (`(c0+c1*s)*m2 = Delta*m1*m2 + noise*m2` is already the right form), verified numerically alongside `add_plain_real` and end to end in Rust (`tests/phase6_bfv.rs::real_add_plain_and_mul_plain_are_exact`, 30 randomized trials, both `add_plain_real` and unmodified `mul_plain` against real ciphertexts).

   [Done] BFV relinearization (`Evaluator::relinearize_real`, `BfvKeyGenerator::generate_hybrid_relinearization_key`): since a real BFV ciphertext is structurally a plain RLWE ciphertext with no `Delta`-specific shape, this is a direct, unmodified pass-through to `phantom_lattice::rlwe`'s existing real key-switching machinery from Workstream 4 - no new derivation needed, since BFV has no `t`-scaled-noise requirement for the key-switching key's own noise to satisfy (unlike BGV, see below). `BgvKeyGenerator::generate_raw_hybrid_relinearization_key` exposes the underlying `phantom_lattice::rlwe::KeyGenerator` pass-through this reuses (named "raw" and documented as unsafe for BGV's own real ciphertexts, to avoid the footgun of a same-named method silently meaning different things on the two types). Verified end to end (`tests/phase6_bfv.rs::real_relinearization_reduces_degree_and_preserves_the_product`, 30 randomized trials, passing on the first attempt).

   [Done] `Evaluator::relinearize_real`/`BgvKeyGenerator::generate_relinearization_key_real` (BGV): genuinely harder than BFV's, and NOT solved by the obvious fix. Naively `t`-scaling the RNS hybrid technique's key-switching noise (the same approach that worked for BFV) was verified numerically to be *insufficient* before implementing anything: the technique's `mod_down` step computes `floor(X/P)` on an accumulator (`acc_b`, `acc_a`) that only becomes congruent to the wanted value mod `t` *after* combining via multiplication by the secret `s_new` - which the evaluator performing key-switching never has access to, by the whole design of key-switching. `floor` doesn't distribute over that sum, so the rounding error it introduces is small in magnitude but not generally a multiple of `t` - simulating the full pipeline showed a post-relinearization residual like `[21, 12, -21, -23]` (mod 17: `[4, 12, 13, 11]`, not `[0,0,0,0]`), confirming the corruption is real and not just imprecision. New `BgvRelinearizationKey` (`phantom-schemes::bgv::relinearization`) sidesteps the problem with classical (power-of-base) gadget decomposition instead of the RNS hybrid technique - reusing `phantom_lattice::rgsw::{GadgetDecomposition, GadgetDecompositionParams}` (already built for RGSW's external product, needing no new decomposition logic) - which involves no auxiliary modulus or division/rounding step at all (`c1 = sum_i B^i * c1_i` is an exact integer identity), so `t`-scaled fresh key-switching noise stays an exact multiple of `t` with nothing to corrupt it. The tradeoff is more gadget levels than RNS hybrid needs (`~log_B(Q)` rather than one per RNS modulus) and a real constraint on the base `B`: an initial `B = 2^20` attempt failed outright (not approximately - a large digit multiplied against even a tiny noise difference between two otherwise-close values can itself overflow `Q` under ring convolution), resolved by switching to a small base (`B = 16` and `B = 4` both verified exact across 50 Python trials). Verified end to end in Rust (`tests/phase5_bgv.rs::real_relinearization_reduces_degree_and_preserves_the_product_exactly`, base `2^8`/7 levels, 30 randomized trials, checking **exact** equality with the true product - not a noise bound, the actual point of the exercise), passing on the first Rust attempt after the Python groundwork.

   **Deliberately scoped out, tracked as follow-up**: wiring `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/`phantom-examples` to any real path (their toy parameters have no noise headroom, and some may need their own noise-growth analysis for repeated multiplication without real relinearization).
2. [Done, BGV core] Implemented real RNS modulus switching for BGV, in the same backward-compatible dual-mode design item 1 established (`ModulusSwitcher::switch_next` stays the existing clone-only scaffold; new `switch_next_real` does the genuine operation). New `phantom_ring::rns::rescale::modulus_switch_down(poly, q_basis, t)` drops `q_basis`'s last modulus `q_L`, producing a value congruent to the original mod the plaintext modulus `t` (preserving the message) and as close as possible to `value / q_L` (shrinking noise proportionally) - genuinely different from both existing RNS primitives it sits alongside: `drop_last_modulus` (pure truncation, no rescale at all) and `mod_down` (exact floor division, no congruence requirement). Hand-derived via a CRT-combined "correction" term (`correction ≡ -X (mod q_L)` for exact divisibility, `correction ≡ X*(q_L-1) (mod t)` for congruence, uniquely determined mod `q_L*t` since they're coprime) and verified numerically (Python, 200 randomized trials, both against a true-value construction and independently via the exact residue-only construction implemented) before writing any Rust - see `tests/modulus_switch.rs` for the Rust-level regression coverage (6 independently Python-computed cases plus a 200-trial CRT-reconstruction property check). Since switching drops an RNS component, the result needs matching smaller-ring parameters and a matching smaller-ring secret key to decrypt - new `ModulusSwitcher::next_params`/`switch_secret_key` (the latter just `drop_last_modulus` on the secret key's own value, since a key isn't rescaled the way a ciphertext is) produce both, exposed through `Evaluator::modulus_switch_next_real`/`next_modulus_switch_params`/`switch_secret_key`. Verified end to end (`tests/phase5_bgv.rs::real_modulus_switch_reduces_ring_and_preserves_plaintext`): encrypt at a 2-modulus ring, switch down to 1 modulus, decrypt with the reduced params/key, and confirm the exact same plaintext values recover, across 30 randomized trials. **Not yet done**: BFV's own modulus switching/plaintext scaling (needs its own Δ-scaling-aware treatment, tracked alongside item 1's BFV gap) and wiring the real path into `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/`phantom-examples`, same follow-up scope item 1 already flagged.
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
5a. Add noise flooding/smudging on top of that reconstruction: each participant's share needs extra calibrated noise added specifically to statistically hide their exact contribution from the other parties, not just correct secret-sharing arithmetic — a standard technique from the threshold-decryption literature, combining the ciphertext's existing fresh-encryption noise with an explicit smudging term. Depends on Workstream 4 item 2 (real noise tracking) to know what that fresh noise actually is.
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
