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
- Parameter preset documentation in `docs/parameter-presets.md`.
- Runnable API examples in `phantom-examples`.
- Performance notes for CPU backend in `docs/performance-notes.md`.
- Release checklist for alpha, beta, and stable in `docs/release-checklist.md`.

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

Current next implementation target: production hardening and Phase 0 cleanup.

1. Add the `phantom-fhe` facade crate.
2. Add `SECURITY.md`, `CONTRIBUTING.md`, baseline CI, and dependency policy.
3. Replace smoke benchmarks with Criterion if dependency policy allows it.
4. Continue production cryptography hardening: real noise management, optimized NTT/RNS, secure parameter sets, and protocol security review.
5. Prepare alpha release notes once Phase 0 cleanup is complete.

Completed implementation phases so far: Phase 1 (`phantom-utils`), Phase 2 (`phantom-ring`), Phase 3 (`phantom-lattice::rlwe`), Phase 4 (`phantom-lattice::rgsw`), Phase 5 (`phantom-schemes::bgv`), Phase 6 (`phantom-schemes::bfv`), Phase 7 (`phantom-schemes::ckks`), Phase 8 (`phantom-circuits::common`), Phase 9 (`phantom-circuits::bgv`), Phase 10 (`phantom-circuits::bfv`), Phase 11 (`phantom-circuits::ckks`), Phase 12 (`phantom-bootstrapping`), Phase 13 (`phantom-multiparty::common`), Phase 14 (`phantom-multiparty::mpbgv`), Phase 15 (`phantom-multiparty::mpbfv`), Phase 16 (`phantom-multiparty::mpckks`), Phase 17 (Serialization and compatibility), and Phase 18 (Examples, benches, and release hardening).
