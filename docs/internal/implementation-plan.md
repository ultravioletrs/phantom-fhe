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

Current status: Alpha Hardening Workstream 11 (CKKS real bootstrapping: modulus raise) is **done**. It landed a real, tested `Evaluator::raise_level_real`, a widened real-domain `EvalMod::reduce_mod_q_real_wide`, a genuinely complex-valued `EvalMod::reduce_mod_q_real_complex_wide`, a from-scratch, paper-verified redesign of `CoeffsToSlots::apply_real`/`SlotsToCoeffs::apply_real` matching real CKKS bootstrapping's own CoeffToSlot/SlotToCoeff construction (Cheon-Han-Kim-Kim-Song, EUROCRYPT 2018), and - closing the workstream - a genuine real end-to-end verification (`raise_level_real` through the public `Bootstrapper::bootstrap_real_wide`, recovering a real message from a real raise, not an engineered wraparound). What looked like a further encoding-precision or architectural gap turned out to be neither: it was an incorrect `raise_modulus` value in the test itself (must be `q0/Delta`, not the raw `q0`) plus a stale, pre-redesign doubling-domain bound in a doc comment that never got updated after item 7's own `CoeffsToSlots` redesign made it inapplicable. See Workstream 11's own entry (item 8) for the full root-cause trace. Workstreams 1 (Phase 0 cleanup), 2 (scaffold boundary and API honesty), 3 (ring and RNS foundation hardening, item 5b intentionally deferred, see its own entry), 4 (production RLWE/RGSW track), 5 (production BFV/BGV/CKKS track), 6, and 11 are done - see below. Workstream 6's own item 1 (keeping circuit planning APIs stable) is an ongoing invariant, not a one-time task, and stays in force going forward the same way analogous "stay stable" items do in earlier workstreams. Workstream 7 (multiparty and protocol security) is in progress: item 3 (real transcript hash), item 4a (a standalone, tested Pedersen VSS distributed-key-generation primitive, `phantom-multiparty::vss`), item 4b (real collective public-key generation wired for BGV, `mpbgv::CollectiveKeyGen`), item 4c (real collective Galois/rotation-key generation wired for BGV, `mpbgv::GaloisKeyGen`), item 4d (real collective relinearization-key generation wired for BGV via a genuine two-round protocol, `mpbgv::RelinearizationKeyGen`), item 5b (real collaborative key-switching/PCKS wired for BGV, `mpbgv::ReEncryptor` - additive n-of-n by design, not a step toward Lagrange/Shamir reconstruction, see that item's own text), and item 5a (PCKS's smudging noise replaced with a rigorously derived, cited bound, `phantom_lattice::security::smudging_std_dev`, plus a new large-sigma `phantom_ring::sampling::sample_smudging_gaussian` the existing table-based sampler couldn't handle at that scale) are done; mirroring CKG/GKG/RKG/PCKS to `mpbfv`/`mpckks`, the rest of item 5 (`PartialDecryptor`, `InteractiveBootstrap`), 6, 7, and the newly-tracked item 8 (anti-replay protection against repeated `create_share` calls) remain open.

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
8. [Done] Implemented the real external product: `external_product(RGSW(m), ct)` gadget-decomposes `ct`'s `c0`/`c1` via the existing `GadgetDecomposition::decompose` (already production-shaped per this item's own note - now actually consumed) and computes `sum_i c0_i * rows()[0][i] + sum_i c1_i * rows()[1][i]`. Hand-derived before implementing (see `external_product.rs`'s doc comment for the full derivation): this recovers `RLWE_s(m * mu)` with noise `m*e_ct + sum_i c0_i*e_i + sum_i c1_i*e'_i` (`e_ct` = the input ciphertext's own noise, `e_i`/`e'_i` = each RGSW row's fresh noise) - added `phantom_lattice::noise::external_product_noise_bound` for the corresponding worst-case bound, same technique as items 1/2. Verified against `schoolbook_mul(pt, multiplier)` via the same centered-residue noise-bound comparison `tests/phase3_rlwe.rs` established, at a realistically-sized ring (the old degree=4/modulus=97 ring is kept only for the noise-free structural tests - parameter validation, gadget decompose/recompose - which don't involve encryption at all). This verification, like BGV's own relinearization test, only ever used a single-modulus ring - `GadgetDecomposition` had a latent multi-modulus soundness gap not caught until Workstream 5 item 7's own investigation, fixed there (`phantom-lattice/tests/rgsw_multi_modulus.rs` now covers the multi-modulus case directly).
9. [Done] Added `crates/phantom-lattice/tests/randomized.rs`: 300-trial randomized coverage (`ChaCha20Rng`, matching `phantom-ring/tests/rns_randomized.rs`'s established style - hundreds of trials inside one `#[test]`, not one `#[test]` per case) for every real operation this workstream built - secret-key and public-key encrypt/decrypt round trips, add/sub, multiplication, real relinearization (item 4), real Galois automorphism (item 5), repack (item 6), and RGSW external product (item 8) - each checked against an independently computed reference (direct ring arithmetic, `schoolbook_mul`, or `apply_automorphism` applied to the plaintext directly) within the appropriate noise bound from `phantom_lattice::noise`, complementing the fixed-seed handful-of-cases coverage `phase3_rlwe.rs`/`phase4_rgsw.rs` already had. Key material (secret key, relinearization key, Galois key, RGSW key) is generated once per test and reused across trials - only plaintext content and encryption randomness vary per trial, matching realistic usage rather than paying key-generation cost 300 times over. All 8 new tests passed on first attempt.
10. [Done] Added `phantom_lattice::security`, grounding standard deviation, noise bound, and secret-distribution choices in literature-standard values: `STANDARD_ERROR_STD_DEV = 3.2` and `ERROR_TAIL_CUT_STD_DEVS = 6.0` (the homomorphicencryption.org security standard and the BFV/BGV/CKKS papers converge on σ≈3.2 with a 6σ tail cut - the same tail cut `phantom_ring::sampling::sample_discrete_gaussian` already uses internally, now named and justified at the crate level too), `fresh_error_bound()` (`ceil(sigma * tail_cut)`), and `recommended_secret_distribution()` (ternary). This is what item 1's real RLWE noise is actually grounded in, not an ad hoc number. Workstream 2 item 2 (separating toy from production presets) can now mean something - there's a documented value to ground a "production preset" in - though the presets themselves haven't been split yet (still Workstream 2's own deferred item, not reopened here).
11. Adaptive RNS digit grouping for `generate_key_switch_key`/`key_switch` - currently always one gadget-decomposition row per `Q`-modulus, regardless of how many `P` moduli exist; the standard technique groups `p_moduli.len()` `Q`-moduli into each digit block instead (row count `ceil((Q_moduli+P_moduli)/P_moduli)` rather than `Q_moduli`), cutting key-switching-key size and per-switch computation roughly in proportion to `p_moduli.len()`. Not a correctness gap (today's fixed one-row-per-modulus design is sound, just not the most compact point in the design space) - a performance/key-size item, not yet started.

Exit criteria:

- [Met] RLWE operations are no longer transparent/toy: encryption and key generation sample real noise (item 1), key switching, relinearization, Galois rotation, and repacking are all real (items 3, 4, 5, 6), and RGSW encryption/external product are a real gadget-matrix construction rather than plaintext-backed (items 7, 8).
- [Met] Key switching, relinearization, and Galois rotation have meaningful cryptographic behavior: real RNS hybrid key-switching (item 3) with relinearization (item 4) and Galois rotation (item 5) both built on it, verified end to end.
- [Met] Higher scheme crates can build production BFV/BGV/CKKS semantics on top - met by Workstream 5, which built BGV/BFV/CKKS's own real encrypted-state paths (including real relinearization for all three) directly on these primitives.
- [Met] A parameter set's standard deviation/bound/distribution choices are traceable to a documented security rationale, not just a number that happens to work in tests: `phantom_lattice::security` (item 10).

Workstream 4 is now complete except for item 11 above (a follow-up performance/key-size item found later, not blocking completion) - every other item (1-10) is done and both exit criteria batches are met: `phantom-lattice::rlwe`/`rgsw` have real noise, real RNS hybrid key-switching, real relinearization, real Galois rotation, real repacking, and a real RGSW gadget construction, all verified end to end including 300-trial randomized coverage, with Workstream 5 confirming scheme crates can build on top of them.

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

   [Done] `Evaluator::relinearize_real`/`BgvKeyGenerator::generate_relinearization_key_real` (BGV): genuinely harder than BFV's, and NOT solved by the obvious fix. Naively `t`-scaling the RNS hybrid technique's key-switching noise (the same approach that worked for BFV) was verified numerically to be *insufficient* before implementing anything: the technique's `mod_down` step computes `floor(X/P)` on an accumulator (`acc_b`, `acc_a`) that only becomes congruent to the wanted value mod `t` *after* combining via multiplication by the secret `s_new` - which the evaluator performing key-switching never has access to, by the whole design of key-switching. `floor` doesn't distribute over that sum, so the rounding error it introduces is small in magnitude but not generally a multiple of `t` - simulating the full pipeline showed a post-relinearization residual like `[21, 12, -21, -23]` (mod 17: `[4, 12, 13, 11]`, not `[0,0,0,0]`), confirming the corruption is real and not just imprecision. New `BgvRelinearizationKey` (`phantom-schemes::bgv::relinearization`) sidesteps the problem with classical (power-of-base) gadget decomposition instead of the RNS hybrid technique - reusing `phantom_lattice::rgsw::{GadgetDecomposition, GadgetDecompositionParams}` (already built for RGSW's external product, needing no new decomposition logic) - which involves no auxiliary modulus or division/rounding step at all (`c1 = sum_i B^i * c1_i` is an exact integer identity), so `t`-scaled fresh key-switching noise stays an exact multiple of `t` with nothing to corrupt it. The tradeoff is more gadget levels than RNS hybrid needs (`~log_B(Q)` rather than one per RNS modulus) and a real constraint on the base `B`: an initial `B = 2^20` attempt failed outright (not approximately - a large digit multiplied against even a tiny noise difference between two otherwise-close values can itself overflow `Q` under ring convolution), resolved by switching to a small base (`B = 16` and `B = 4` both verified exact across 50 Python trials). Verified end to end in Rust (`tests/phase5_bgv.rs::real_relinearization_reduces_degree_and_preserves_the_product_exactly`, base `2^8`/7 levels, 30 randomized trials, checking **exact** equality with the true product - not a noise bound, the actual point of the exercise), passing on the first Rust attempt after the Python groundwork. **Gap found and fixed later (Workstream 5 item 7):** this verification only ever used a single-modulus ring - chaining this relinearization with real modulus switching (`Evaluator::modulus_switch_next_real`) on a multi-modulus ring produced incorrect results, root-caused to a `GadgetDecomposition` soundness gap and fixed there (see item 7's own entry for the full writeup and root cause).

   **Deliberately scoped out, tracked as follow-up**: wiring `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/`phantom-examples` to any real path (their toy parameters have no noise headroom, and some may need their own noise-growth analysis for repeated multiplication without real relinearization).
2. [Done, BGV core] Implemented real RNS modulus switching for BGV, in the same backward-compatible dual-mode design item 1 established (`ModulusSwitcher::switch_next` stays the existing clone-only scaffold; new `switch_next_real` does the genuine operation). New `phantom_ring::rns::rescale::modulus_switch_down(poly, q_basis, t)` drops `q_basis`'s last modulus `q_L`, producing a value congruent to the original mod the plaintext modulus `t` (preserving the message) and as close as possible to `value / q_L` (shrinking noise proportionally) - genuinely different from both existing RNS primitives it sits alongside: `drop_last_modulus` (pure truncation, no rescale at all) and `mod_down` (exact floor division, no congruence requirement). Hand-derived via a CRT-combined "correction" term (`correction ≡ -X (mod q_L)` for exact divisibility, `correction ≡ X*(q_L-1) (mod t)` for congruence, uniquely determined mod `q_L*t` since they're coprime) and verified numerically (Python, 200 randomized trials, both against a true-value construction and independently via the exact residue-only construction implemented) before writing any Rust - see `tests/modulus_switch.rs` for the Rust-level regression coverage (6 independently Python-computed cases plus a 200-trial CRT-reconstruction property check). Since switching drops an RNS component, the result needs matching smaller-ring parameters and a matching smaller-ring secret key to decrypt - new `ModulusSwitcher::next_params`/`switch_secret_key` (the latter just `drop_last_modulus` on the secret key's own value, since a key isn't rescaled the way a ciphertext is) produce both, exposed through `Evaluator::modulus_switch_next_real`/`next_modulus_switch_params`/`switch_secret_key`. Verified end to end (`tests/phase5_bgv.rs::real_modulus_switch_reduces_ring_and_preserves_plaintext`): encrypt at a 2-modulus ring, switch down to 1 modulus, decrypt with the reduced params/key, and confirm the exact same plaintext values recover, across 30 randomized trials. **Not yet done**: BFV's own modulus switching/plaintext scaling (needs its own Δ-scaling-aware treatment, tracked alongside item 1's BFV gap) and wiring the real path into `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/`phantom-examples`, same follow-up scope item 1 already flagged.
   [Partial] `phantom-examples` now has two dedicated real-path workflows, `bgv_real_basic`/`bfv_real_basic` (new example binaries plus `tests/examples_run.rs` coverage), demonstrating encrypt → homomorphic add → homomorphic multiply → real relinearization → decrypt end to end for an external consumer, at the same realistically-sized parameters `phantom-schemes`'s own test suites use - proof the whole session's real BGV/BFV work is actually usable, not just internally testable. Deliberately additive, not a migration: the *existing* examples (`bfv_basic`, `bgv_basic`, `bfv_batching`, `bfv_rotation`, `bgv_polynomial`) still use the transparent path unchanged, since fully migrating them has real blockers beyond a parameter bump - `bfv_rotation` needs real Galois-rotation wiring at the scheme layer (`phantom_lattice::rlwe::Evaluator::apply_galois_automorphism` exists from Workstream 4, but `bgv`/`bfv::Evaluator::rotate_slots` still calls the raw-coefficient `rotate_coefficients` placeholder, with no scheme-layer real counterpart built yet); `bgv_polynomial` needs verification that `phantom_circuits::bgv::PolynomialEvaluator`'s unbounded-degree-growth-without-relinearization pattern stays correct under real noise (not yet checked); and the multiparty examples (`mpbgv_basic`, `mpckks_basic`, `mpckks_interactive_bootstrap`) are blocked on multiparty key aggregation itself still being placeholder (`CollectiveKeyGen::aggregate_public_key` returns an all-zero public key regardless of share content), a Workstream-5-adjacent gap this doesn't touch. `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty` themselves remain entirely on the transparent path.

3. [Done] Rebuilt the CKKS ciphertext/plaintext representation on top of `phantom_lattice::rlwe` — `ckks::Ciphertext`/`Plaintext` used to store `Complex64` slots directly with no ring/RLWE backing at all, and `Encryptor`/`Decryptor` were identity functions over that representation. Added real encoding/decoding, encryption/decryption, and arithmetic over the ring representation, in three stages.

   [Done, encoding half] Real canonical-embedding encode/decode (`Encoder::encode_complex_real`/`decode_complex_real`), the foundational first piece - everything else in this item (real encryption, real arithmetic, rescale) needs a real `Poly`-backed plaintext to operate on, which this produces. `Plaintext` gained an `Option<Poly>` field via the same backward-compatible dual-mode design used throughout Workstream 5 (`Plaintext::new` unchanged, still `None`, so every existing caller - `phantom-circuits`, `phantom-bootstrapping`, `phantom-multiparty`, `phantom-examples`, every other CKKS example - keeps compiling and behaving identically; `Plaintext::new_real` constructible by the encoder or by decryption, see below). For `R = Z[X]/(X^N+1)`, the canonical embedding evaluates a polynomial at the `N` odd powers of `zeta = e^{i*pi/N}` (a primitive `2N`-th root of unity); for real-coefficient polynomials only `N/2` of those `N` evaluation points are independent (the rest are complex conjugates), which is exactly why CKKS packs `N/2` complex slots. Encoding fills the other half with conjugates, scales by the plaintext's `Delta`, and inverts the embedding via a closed-form `U^{-1} = (1/N) * conj(U)^T` (`U` the embedding matrix) - verified numerically (Python) *both* that this inverse identity holds and that the full encode-with-rounding/decode round trip recovers slots to within the expected `~0.5/Delta` error, before writing any Rust. Decoding needed a new `phantom_ring` primitive, `rns::extension::reconstruct_centered_values(poly, basis)` (CRT-reconstructs each coefficient's true signed value, centered into `(-Q/2, Q/2]`, as an `i128`) - built on the same `reconstruct_true_values` internals `extend_basis`/`rescale_and_round` already share, plus a new `BigUint::checked_to_u128` (non-panicking alternative to the existing `debug_assert!`-guarded `to_u128`, since here the modulus product's size is caller-controlled rather than something a fixed call site can guarantee fits in advance). Verified end to end in Rust: `reconstruct_centered_values` itself (`phantom-ring/tests/reconstruct_centered.rs`: an independently Python-computed multi-modulus case plus a 200-trial round-trip property check) and the full CKKS encode/decode pipeline (`phantom-schemes/tests/ckks_real_encoding.rs`: a hand-picked case, 200 randomized trials, partial-slot encoding, and rejection of both conjugate-invariant params and decoding a transparent plaintext) - all passing on the first Rust attempt after the Python groundwork. Conjugate-invariant CKKS (`N` real slots via a different ring structure) isn't supported by the real path yet, rejected explicitly rather than silently wrong; neither is an NTT/FFT fast path (`O(N^2)` evaluation, matching this crate's established "correctness first" convention elsewhere).

   [Done, ciphertext/encryption/arithmetic half] `Ciphertext` gained an `Option<phantom_lattice::rlwe::Ciphertext>` field the same way `Plaintext` did (`Ciphertext::new` unchanged, still `None`; `Ciphertext::new_real` real-path-only) - unlike `Plaintext`'s `slots()` (always meaningful, since a plaintext isn't secret), a real `Ciphertext`'s `slots()` is deliberately empty, since carrying the cleartext message in a "real" (encrypted) ciphertext object would defeat the point of encrypting it. `Encryptor::encrypt_real`/`Decryptor::decrypt_real` are new (unlike BGV/BFV, whose "transparent" ciphertext already secretly wrapped a real RLWE ciphertext under the hood so `decrypt` could just always do real work - CKKS's old scaffold genuinely stored slots in the clear, so it needed a real path added alongside, not revealed underneath). Real CKKS encryption is structurally BFV's real path *minus* the `Delta`-scaling step (already baked into the plaintext by the encoder): `c0 = m + e - a*s`, `c1 = a` for secret-key; the public-key variant needs no special key scaling either, the same as BFV's. `Decryptor::decrypt_real` and `Evaluator`'s own real-path methods derive their working ring from the ciphertext's *own* level via new `CkksParams::at_level` rather than assuming the context's full-level ring, since `rescale_next_real` (below) can drop RNS components - a passed-in full-level secret key is truncated to match automatically. `Evaluator::{add,sub,neg,add_plain}_real` and `mul_real` (raw tensor product, no relinearization) are direct, unmodified pass-throughs to `phantom_lattice::rlwe::Evaluator` - a real CKKS ciphertext needs no BFV-style extended-basis tensor-and-rescale procedure at multiplication time, since CKKS's mod-`Q` tensor product is already exactly the value the *next*, separate rescale step needs (unlike BFV, where the rescale is fused into multiplication itself). `Evaluator::relinearize_real` reuses `phantom_lattice::rlwe`'s real hybrid key-switching unmodified too (new `CkksKeyGenerator::generate_hybrid_relinearization_key` pass-through), the same reasoning BFV's own relinearization documents. `Evaluator::rescale_next_real` drops the ciphertext's last RNS component via the existing `phantom_ring::rns::rescale::mod_down` primitive (`P` = that one modulus) and divides the tracked `Scale` by that modulus's own value - unlike BGV's rescale (`modulus_switch_down`, which needs an exact congruence-preserving correction term to protect a plaintext-modulus invariant), CKKS has no such invariant, so a plain floor division suffices; verified numerically (Python, 200 randomized trials, both directly against the floor-division identity and via a full encrypt/rescale/decrypt/decode round trip - an early version of the check used floating-point division to floor a large integer and silently lost precision, giving a spurious huge error, caught by re-deriving with exact integer `//` division) before implementing. Verified end to end in Rust (`phantom-schemes/tests/ckks_real_arithmetic.rs`, 8 tests): secret- and public-key round trips, add/sub/neg/add_plain, raw multiplication without relinearization, relinearization reducing degree while preserving the product, a full multiply→relinearize→rescale pipeline confirming the scale returns close to `default_scale` and the product still decodes correctly, and rejection of level-zero rescale and of transparent ciphertexts passed to real-path methods.

   [Partial] `phantom-examples` now has a dedicated real-path workflow, `ckks_real_basic` (new example binary plus `tests/examples_run.rs` coverage, alongside `bgv_real_basic`/`bfv_real_basic`), demonstrating encrypt → homomorphic add → homomorphic multiply → real relinearization → real rescale → decrypt → decode end to end for an external consumer, at realistically-sized parameters (a two-modulus ring, the second modulus chosen close to `2^scale_bits` so the rescale step has something meaningful to drop). Deliberately additive, not a migration, the same as item 2's own note: the *existing* CKKS examples (`ckks_basic`, `ckks_rescale`, `ckks_dft`, `ckks_inverse`, `ckks_bootstrapping`) still use the transparent path unchanged, since `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty` themselves remain entirely on the transparent path (same blockers item 2 already documented - `phantom_bootstrapping::ckks`'s own pipeline in particular is not just unmigrated but itself still only message-preserving, not a production refresh pipeline, a separate Workstream 6 gap).

   [Done, real rotation] Added `Evaluator::rotate_real`/`conjugate_real`, found to need a real fix to the encoding itself first while scoping Workstream 6 items 4/5's "rotation-based `CoeffsToSlots`/`SlotsToCoeffs` needs a `rotate_real` this crate doesn't have yet" gap. The standard CKKS technique rotates slots via a single ring automorphism `X -> X^(5^shift mod 2N)` - but `encode_complex_real`/`decode_complex_real`'s *original* encoding assigned slot `j` to the *sequential* embedding exponent `2j+1`, not `5^j`, and brute-force search (Python, `N` in `{8,16,32,64,128}`) found that under sequential indexing no automorphism supports incremental single-step rotation at all - only the identity and one order-2, whole-vector-reversing element stay within the "real, non-conjugated" half of embedding coordinates; every other automorphism mixes conjugates into the result. Confirmed directly against this crate's own `Ring::apply_automorphism`/`Encoder` (a scratch test, deleted before committing), not just the abstract group theory. Fixed by re-deriving the encoder around `5^j`-power slot indexing instead: `(Z/2N)*` factors as `<5> x {+-1}` for `N` a power of two, `N >= 8` (verified numerically before relying on it), so multiplying every exponent by `5^s` maps slot `j`'s exponent to slot `(j+s) mod (N/2)`'s, for every slot at once, with no conjugate mixing - exactly what rotation needs. The closed-form inverse `U^{-1} = (1/N) * conj(U)^T` the encoder relies on still holds for this exponent set (the orthogonality argument only needs the `N` exponents odd and pairwise distinct, not specifically sequential - reverified numerically for the new set, alongside the round trip and the rotation property itself, before implementing). New `CkksParams::rotation_element(shift)`/`conjugation_element()` compute the matching automorphism elements; new `Evaluator::rotate_real`/`conjugate_real` (mirroring `relinearize_real`'s shape - a key from `CkksKeyGenerator::generate_hybrid_galois_key`, direct pass-through to `phantom_lattice::rlwe::Evaluator::apply_galois_automorphism`) apply them to a real ciphertext. No existing test hardcoded specific encoded coefficient values (only round-trip decoded values), so every pre-existing real-path test kept passing unchanged - confirming the encoding change is a genuine internal-convention swap, not a behavior change external callers could observe. Verified end to end: every rotation amount for an 8-slot ring recovers the correctly-rotated slots, conjugation recovers correctly-conjugated slots, and a degree-2 ciphertext is rejected (`ckks_real_arithmetic.rs`, 3 new tests).

   Not yet done: an NTT/FFT fast path for encode/decode (still `O(N^2)`), conjugate-invariant real packing, wiring the real path into `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty` (`phantom-examples` now has one dedicated workflow, see above, but the consumer crates themselves are untouched), and level-alignment/rescale-chaining helpers beyond one rescale at a time.
4. [Done] Hardened CKKS scale management, rescale, level alignment, and precision accounting — the `Precision` degradation amounts (`degrade(0.25)`, `degrade(1.0)` throughout `ckks::Evaluator`) were illustrative constants, not derived from real noise analysis; every one is now a formula in new `ckks::noise`, derived the same triangle-inequality way `phantom_lattice::noise` already derives BGV/BFV/RGSW's own bounds.

   A CKKS ciphertext's decryption noise (a ring element) affects the *decoded* slot value only after evaluating at the canonical embedding's roots of unity and dividing by the scale `Delta`; since every root of unity has magnitude `1`, the triangle inequality gives `|decoded_error| <= (degree/Delta) * coefficient_noise_bound` - the same "sum `degree` unit-magnitude terms" expansion `ring_product_bound` already uses, applied to the embedding evaluation instead. `precision_bits_from_noise`/`noise_bound_from_precision` convert between a coefficient-domain noise bound and bits of slot precision via this identity, letting every formula work in `phantom_lattice::noise`'s own domain (coefficient-domain bounds) while `Evaluator` only ever sees bits.

   `add_degrade_bits` (used by `add`/`sub`/`add_plain` and their real-path counterparts alike - the formula doesn't care whether the second operand is a noisy ciphertext or a near-noiseless plaintext) sums the two operands' implied noise bounds; for two equal-precision, equal-scale operands this comes out to *exactly* 1.0 bit, independent of degree or scale - verified numerically before implementing. `mul_degrade_bits` (used by `mul`/`mul_plain` and their real-path counterparts) mirrors `mul_noise_bound`'s shape (`pt_a*e_b + pt_b*e_a + e_a*e_b`) computed in `f64` over the encoded plaintext bound `Delta*message_bound`; in the realistic noise-much-smaller-than-signal regime it reduces to approximately `log2(2*degree*message_bound)` bits, independent of absolute scale. The transparent scaffold's own `mul`/`mul_plain` read the real `message_bound` straight from `Complex64` slots (the scaffold's whole point); the real path (which can't, since the message is actually encrypted) assumes a documented `ASSUMED_REAL_MESSAGE_BOUND = 1.0`, the standard CKKS convention of normalizing inputs to roughly unit magnitude before encoding.

   `rescale_degrade_bits` (used by `rescale_next`/`rescale_next_real`) models dividing by a modulus close to the current scale as `noise_after = noise_bound/dropped + 1.0` - the `+1` matching `mod_down`'s own documented off-by-at-most-one floor-division rounding; close to zero when the dropped amount matches the current scale (the standard convention every rescale here already follows - rescale is designed to trade ciphertext size for noise, not spend precision), much larger when badly mismatched. `align_degrade_bits` (used by `align_levels`, which - unlike a real rescale chain - doesn't change the ciphertext's own tracked `Scale`, both inputs assumed already at compatible scale despite differing level) chains `rescale_degrade_bits` with `scale_after == scale_before` once per level dropped, replacing the previous flat "1 bit per level" with a per-level cost that shrinks as the ring's precision headroom grows (monotonically increasing total, diminishing marginal cost, verified numerically). `rotate_slots`/`conjugate` now degrade by exactly `0.0` bits rather than the previous `0.25`: a Galois automorphism is a pure coefficient permutation with sign flips, which changes no coefficient's magnitude at all - the key-switch a real implementation would need to restore the original secret key does add noise, but is left unmodeled rather than guessed at, since `phantom_lattice::rlwe`'s own hybrid key-switching doesn't have a formally-derived noise bound yet either (the same gap `SECURITY.md` already documents for the RLWE layer). `mul`/`mul_real` similarly uses the raw-multiplication formula regardless of whether a relinearization key is given, for the same reason - a documented, not silently ignored, gap.

   A genuine internal-consistency bug surfaced while wiring this up and verifying end to end: `Encryptor::encrypt` (transparent) previously passed `plaintext.precision()` (`log2(scale)`, pure encode-rounding, no RLWE noise at all) straight through unchanged, so a "fresh" ciphertext's implied noise bound came out to a physically meaningless `1/degree` - far smaller than any real noise term, which made even a well-matched rescale's small constant rounding artifact look enormous by comparison (`align_degrade_bits`'s own test unexpectedly returning several bits for a realistically-scaled ring, traced back to this rather than a formula bug). Fixed by adding new `fresh_precision_bits` (using `phantom_lattice::noise::fresh_public_key_noise_bound`, the larger/sound choice since the transparent `Encryptor` doesn't currently distinguish which mode it was constructed with) and degrading `encrypt`'s output to it; `encrypt_real` gets the more precise mode-specific bound (`fresh_secret_key_noise_bound`/`fresh_public_key_noise_bound`) directly, since it *does* know its own mode.

   Verified end to end: 9 new `ckks::noise` unit tests (round-trip conversion, each formula's own derived-value sanity check, bound-soundness properties) plus 6 new `phantom-schemes/tests/ckks_precision_accounting.rs` integration tests exercising the formulas through `Evaluator` itself (add costing ~1 bit, mul costing more for larger-magnitude slots, rescale-after-multiply recovering most of the precision the squared scale would otherwise suggest was lost, align_levels costing less than the old flat model, rotate/conjugate no longer degrading at all, and the toy preset's fresh precision gracefully clamping to `0.0` instead of going negative) - alongside the full existing suite, with one existing test (`phase7_ckks.rs::add_mul_and_rescale_track_scale_level_and_precision`) moved from the toy preset to a new realistically-scaled one, since the toy preset's scale genuinely has no headroom left for a meaningful precision comparison once real fresh-noise accounting applies (consistent with every other "toy preset has no headroom for real noise" note elsewhere in this document).
5. [Done] Added noise/error estimates to scheme contexts. BGV/BFV's real ciphertexts have no per-ciphertext noise field at all (unlike CKKS's `Precision`, item 4), so this is standalone, parameter-driven estimate functions - new `bgv::noise`/`bfv::noise` modules, plus a small `noise_budget_bits` addition to `phantom_lattice::noise` they both build on, and thin `BgvContext`/`BfvContext` convenience wrappers (`noise_budget_bits`, `fresh_secret_key_noise_budget_bits`, `fresh_public_key_noise_budget_bits`). `CkksContext::fresh_precision_bits` was added too, mostly for API symmetry - CKKS already has a real per-ciphertext estimate via `Precision`.

   Every function tracks the same quantity for its scheme: `e` in BGV's `c0+c1*s = m + t*e` (unscaled by `t`) or BFV's `c0+c1*s = Delta*m + e` (already unscaled) - `fresh_secret_key_noise_bound`/`fresh_public_key_noise_bound` are thin re-exports of `phantom_lattice::noise`'s own generic RLWE bounds in both schemes (fresh noise sampling is identical to plain RLWE; only what wraps around it afterward differs per scheme). `bgv::noise::mul_noise_bound` is a new derivation (`(m1+t*e1)*(m2+t*e2) = m1*m2 + t*(m1*e2+m2*e1+t*e1*e2)`, genuinely different in shape from `phantom_lattice::noise::mul_noise_bound` because of that extra `t` factor) and `bgv::noise::relinearize_noise_bound` adapts `external_product_noise_bound`'s own "digit times fresh row noise, summed over levels" reasoning to BGV's classical-gadget-decomposition relinearization (a single gadget block, so half `external_product_noise_bound`'s factor) - both verified numerically (Python, 300 and 200 randomized trials respectively, direct negacyclic-convolution simulation against the derived bound) before implementing.

   `bfv::noise::mul_noise_bound` surfaced a genuine, non-obvious bug while verifying: the natural-looking approach (`Delta*t/Q ≈ 1` cancels `Delta` out of the ratio, so reuse `phantom_lattice::noise::mul_noise_bound` directly) is *unsound* - `Delta = floor(Q/t)`, not `Q/t` exactly, and the flooring gap introduces an *additional* noise contribution proportional to the message magnitude itself, not just the input noise, which the generic formula's shape doesn't capture at all (a first verification attempt reusing it directly failed by several orders of magnitude against a real `rescale_and_round` simulation). Bounding each term of the exact rescale identity gives a sound closed form instead, `degree*(t+noise_bound)^2 + 1`, verified numerically (Python, 9000 randomized trials across three seeds) before implementing - a clear instance of the same "verify before implementing" discipline catching a wrong-but-plausible shortcut, this time in a derivation rather than an implementation.

   `noise_budget_bits` (both schemes) converts an absolute noise bound into bits of margin against decryption's actual correctness threshold (BGV: `|m+t*e| < q/2`; BFV: `|e| < Delta/2`) via a new shared `phantom_lattice::noise::noise_budget_bits(threshold_bits, noise_bits)` - kept in `log2` space throughout rather than ever materializing `q`/`Delta`/the noise bound as literal numbers, since a realistic multi-modulus ring's modulus product routinely exceeds what `u64`/`f64` can represent exactly (the same reason `ckks::noise::precision_bits_from_noise` - this same identity, specialized to CKKS's canonical-embedding setting, predating this shared extraction - already worked this way).

   Deliberately not modeled: relinearization/key-switching's own noise contribution for BFV (and CKKS), since `phantom_lattice::rlwe`'s generic RNS hybrid key-switching doesn't have a formally-derived noise bound of its own yet either - the same gap `SECURITY.md` already documents, not solved here (BGV's own relinearization sidesteps this because it uses a different technique - classical gadget decomposition - that *does* have a derived bound now, per above).

   Verified end to end: `bgv::noise`/`bfv::noise` each have unit tests (hand-worked cases matching the Python derivations, monotonicity checks, budget-never-negative checks) alongside `phantom_lattice::noise::noise_budget_bits`'s own; a new `phantom-schemes/tests/noise_estimates.rs` (4 tests) cross-checks the estimates against *actual* real encrypt/multiply/relinearize pipelines at realistically-sized parameters - confirming a positive predicted budget genuinely corresponds to a still-decryptable ciphertext, not just that the formulas are internally consistent - plus `BgvContext`/`BfvContext`'s convenience methods matching their underlying free functions.
6. [Done] Added parameter-builder validation that rejects both inconsistent and insecure settings, with two different default strictness levels for the two categories - new `phantom-schemes::security` (crate-private, exercised only through the builders) plus a new `phantom_lattice::security::max_secure_total_modulus_bits_128` table.

   **Inconsistent settings** (things that break correctness regardless of parameter size) are rejected unconditionally by `BgvParamsBuilder`/`BfvParamsBuilder` (delegates to BGV's own builder)/`CkksParamsBuilder::build`: duplicate ciphertext moduli (breaks the pairwise-coprime assumption every CRT-based RNS primitive in `phantom_ring::rns` relies on) and, for BGV/BFV, a plaintext modulus not coprime to every ciphertext modulus (breaks `inv_mod` wherever BGV/BFV need it - modulus switching's CRT correction, BFV's `Delta = floor(Q/t)` scaling). Verified safe to enable unconditionally by auditing every parameter combination actually constructed anywhere in this workspace (direct `::new` calls and every builder call site, across all six crates) before adding either check - none violate either condition, so this is a pure bug-catcher with zero behavior change for any existing caller.

   **Insecure settings** are opt-in only, via each builder's new `.require_128_bit_security()`: `phantom_lattice::security::max_secure_total_modulus_bits_128(degree)` reproduces the homomorphicencryption.org security standard's own published table (indexed by ring degree, in bits - the same table production FHE libraries' own parameter defaults use, e.g. Microsoft SEAL's `hestdparms.h`), returning `None` for a degree the table doesn't cover (below its smallest entry, `1024`, or above its largest, `32768`) rather than guessing. This is deliberately *not* a default `build()` check: every development/test preset this crate's own test suite uses (ring degree `8`-`64`) is far below the table's smallest covered degree, so an unconditional check would reject essentially every existing caller across `phantom-schemes`/`phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/`phantom-examples` - consistent with `SECURITY.md`'s own description of those presets as "small development sizes chosen for fast iteration, not production security margins," not a defect to silently paper over by weakening the check. A caller that opts in gets a hard error for both a table-covered degree whose total modulus bits exceed the limit *and* a degree the table doesn't cover at all, since "no published guidance available" isn't the same as "known secure."

   Verified end to end: unit tests for each of the three new `phantom-schemes::security` functions (hand-worked accept/reject cases) and `phantom_lattice::security::max_secure_total_modulus_bits_128`'s own (table values, monotonicity), plus a new `phantom-schemes/tests/param_builder_validation.rs` (10 tests) covering all three builders' consistency checks, the opt-in security check accepting/rejecting both table-covered and uncovered degrees, and explicit backward-compatibility confirmation that every existing toy preset still builds successfully without the opt-in flag - alongside the full existing suite (every crate, not just `phantom-schemes`) under make check.
7. [Done] Added cross-operation tests for encryption, addition, multiplication, rotations, rescale/modswitch, and serialization (`phantom-schemes/tests/cross_operations.rs`, 6 tests) - each chains several operations into one pipeline and checks the final decrypted value, unlike every other test file in this crate, which exercises one operation at a time. This is deliberately about *composition*: a bug that only shows up when operations are chained wouldn't necessarily show up in any single per-operation test, and this item's own work found two such bugs.

   **Found and fixed**: CKKS serialization (`crate::serialization`) never handled the real path at all - `encode_ckks_plaintext`/`encode_ckks_ciphertext` only ever wrote `slots`/`scale`/`level`/`precision`(`/degree`), silently discarding a real `Plaintext`/`Ciphertext`'s actual content (its `poly`, since a real one's `slots()` is deliberately empty - see items 3/4's own notes) rather than erroring. Every existing BGV/BFV serialization test happened not to catch the CKKS-specific version of this gap, since BGV/BFV ciphertexts have always had a single representation shape (no dual transparent/real split at the type level - see item 3's own note on why CKKS needed one and BGV/BFV didn't). Fixed with new `encode_ckks_plaintext_real`/`decode_ckks_plaintext_real`/`encode_ckks_ciphertext_real`/`decode_ckks_ciphertext_real` (new domain tags, so the existing transparent wire format is completely unchanged) that explicitly reject a plaintext/ciphertext with no real representation rather than silently encoding nothing meaningful. Verified end to end via `cross_operations.rs::ckks_real_pipeline_encrypt_add_multiply_relinearize_rescale_and_serialize`, which serializes and deserializes mid-pipeline and confirms the final decoded value is still correct.

   **Found, root-caused, and fixed**: chaining BGV's real relinearization (`Evaluator::relinearize_real`, item 1's classical gadget decomposition) with real modulus switching (`Evaluator::modulus_switch_next_real`, item 2) on a ring with more than one auxiliary modulus produced an incorrect plaintext - `relinearize_real`'s own output decrypted correctly on its own (matches `real_relinearization_reduces_degree_and_preserves_the_product_exactly`'s own single-modulus verification), and switching a *fresh* (non-relinearized) ciphertext was independently correct too, but the two combined were not.

   A later, much more targeted investigation (instrumenting every stage of a minimal encrypt→multiply→relinearize→switch pipeline with independent `i128`/CRT reconstruction rather than only comparing final decoded output) found the actual root cause: **not** a BGV-specific interaction bug, and **not** in `modulus_switch_down` (its own arithmetic was re-verified exact, again, against an independent CRT reconstruction). It was a soundness gap in the *shared* `phantom_lattice::rgsw::GadgetDecomposition` primitive itself, present whenever it's used on a ring with more than one RNS modulus - which, before this investigation, had simply never happened anywhere in this workspace (`phantom-lattice`'s own `GadgetDecomposition`/RGSW tests, `phase4_rgsw.rs` and `randomized.rs`, and BGV's single-modulus relinearization test all used a one-modulus ring). `GadgetDecomposition::decompose` extracted each digit via `(coeff >> shift) & mask` applied *independently to every RNS component's own residue* - for a coefficient with true value `x`, it bit-sliced `x mod q_0` and `x mod q_1` *separately*, producing a digit polynomial whose two RNS components were base-`B` digits of two unrelated numbers (the two residues), not of one common small value. `recompose` was still correct *per modulus* (`sum_i digit_i[j]*B^i ≡ c[j] (mod q_j)` holds independently for each `j` - a straightforward consequence of digit extraction being an exact base-`B` expansion of that one residue), which is exactly why the first RNS modulus's own component - all `BatchEncoder::decode_u64` ever reads - still decoded correctly right after relinearizing. But the digit polynomial carried no CRT-consistent value once more than one modulus was involved, so the ciphertext's *other* RNS components ended up holding noise uncorrelated with the first modulus's - invisible to `decode_u64` until `modulus_switch_down` explicitly CRT-reconstructed *across all components* to rescale, at which point the incoherent extra components corrupted the result. Confirmed directly: reconstructing `relinearize_real`'s own output across its full RNS basis (`phantom_ring::rns::extension::reconstruct_centered_values`, the same primitive `modulus_switch_down` itself uses internally) gave a noise value many orders of magnitude past what `bgv::noise::relinearize_noise_bound` predicted, while the first modulus's own component alone matched that bound closely.

   **Fixed** with a CRT-coherent redesign of `GadgetDecomposition` itself - shared `phantom-lattice` infrastructure, so this also fixes the same latent gap in RGSW's `external_product` (never triggered before, since no caller anywhere used it on a multi-modulus ring either). Each RNS modulus is now its own gadget "level": for modulus `q_j`, the coefficient's *own* `q_j`-residue (an ordinary small-ish integer, no CRT ambiguity) is base-`B` decomposed as before, but the resulting digit is embedded *consistently* across every output RNS component (`digit mod q_i` for every `i`) rather than bit-sliced from each component's own, unrelated residue - genuinely a small, well-defined integer now, not two different numbers wearing the same digit's clothes. Recomposing (or, for key material, baking the equivalent scaling into fresh rows) needs the standard CRT reconstruction identity `sum_j G_j * (x mod q_j) ≡ x (mod Q)`, where `G_j` is the new `phantom_ring::rns::extension::crt_lift_constant` (`(Q/q_j) * ((Q/q_j)^{-1} mod q_j)`, reduced into every target modulus) - so a ring with `n` moduli now decomposes into `n * levels` digits/rows instead of just `levels`, each block `j` additionally scaled by `crt_lift_constant(.., j, ..)` (`BgvRelinearizationKey::generate`, `RgswCiphertext::encrypt`). For a genuinely single-modulus ring `G_0 == 1` always, so this is *exactly* the previous construction with zero behavior change - confirmed by every existing single-modulus BGV/RGSW test passing unchanged.

   Verified end to end: the derivation itself first (Python, before touching Rust) - 100 randomized trials of the full decompose→key-material→recombine identity across 2-4 moduli and varying bases (an earlier attempt using only `crt_basis_constant`'s raw `M_j`, missing the `(Q/q_j)^{-1} mod q_j` inverse factor, failed outright until corrected - caught by this same Python-first verification, not shipped), plus 200 trials of the plain decompose/recompose round trip including the single-modulus case. Then in Rust: new `phantom-ring` tests for `crt_lift_constant` (hand-worked values plus the CRT identity itself, directly); a new `phantom-lattice/tests/rgsw_multi_modulus.rs` (2 tests) proving RGSW's own external product now works on a multi-modulus ring, which no existing test had ever exercised; and, most directly, a new `cross_operations.rs::bgv_real_pipeline_encrypt_add_multiply_relinearize_switch_and_serialize` reproducing the exact originally-broken chain (encrypt→add→multiply→relinearize→switch→serialize) and confirming it now decrypts correctly - alongside the full existing suite (every crate) under `make check`, unchanged.

   (Design informed by comparing against how a production RNS-BGV/CKKS library structures its own gadget decomposition - RNS-level digit blocks each scaled by a CRT lifting factor, plus a base-`2^w` sub-split within each block - before finalizing this derivation, not reinvented from scratch blind.)

   The other four cross-operation pipelines all passed on the first attempt: BFV (encrypt→add→multiply→relinearize→serialize, real tensor-and-rescale multiplication plus RNS hybrid relinearization chained together for the first time in a single test), CKKS (encrypt→add→multiply→relinearize→rescale→serialize, the fullest real CKKS pipeline exercised anywhere in the test suite), and one transparent-scaffold pipeline each for BGV and CKKS (encrypt→add→multiply(or just add)→rotate→serialize) - rotation is covered only via the transparent scaffold, since real rotation isn't wired up for any scheme yet (`SECURITY.md`: BGV/BFV still only call the raw-coefficient `rotate_coefficients` placeholder; CKKS's real path has no rotation method at all), so exercising it on a real ciphertext would test something not proven correct there rather than validate real behavior.

Workstream 5 is now complete (items 1-7 all done) - BGV, BFV, and CKKS each have a real encrypted-state path (encryption, homomorphic add/multiply, relinearization) alongside their unchanged transparent scaffolds, all three have real noise/error estimates and parameter-builder validation, and cross-operation testing exercises them chained together, including the one gap this workstream's own item 7 found and has since fixed (BGV real relinearization chained with real modulus switching on a multi-modulus ring, and RGSW's external product on the same - see item 7's own entry and `SECURITY.md`) - every real-path combination tested is now verified correct. Wiring any real path into `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty` remains out of scope here (each item's own entry notes this as deliberately deferred), which is why the exit criteria below are met at the scheme layer specifically, not end to end through every consumer crate.

Exit criteria:

- Scheme ciphertexts carry real encrypted state. Met (BGV/BFV/CKKS all have a real path now).
- Existing examples still run, but over non-transparent scheme behavior where possible. Partially met: `phantom-examples` has a dedicated real-path workflow per scheme (`bgv_real_basic`, `bfv_real_basic`, `ckks_real_basic`), additive rather than migrating the existing toy-preset examples (their toy parameters have no real-noise headroom) - full migration remains future work.
- CKKS precision metadata reflects real approximation behavior rather than scaffold bookkeeping. Met (item 4's `ckks::noise`).

### Workstream 6 - Bootstrapping and Circuits Hardening

Owned areas:

- `phantom-circuits`
- `phantom-bootstrapping`

Tasks:

1. Keep common circuit planning APIs stable while production scheme internals evolve.
2. [Done] Connect BGV/BFV/CKKS circuit evaluators to real evaluator semantics. Scoping this properly - before writing any circuit code - surfaced that the three schemes are in genuinely different starting positions, not a single "port the evaluators" task. All three now have real `PolynomialEvaluator`/`LinearTransformEvaluator` evaluators; BGV/BFV's `LinearTransformEvaluator::apply_real` is scoped to row-local (block-diagonal) transforms rather than the fully general case (see below) - a deliberate, documented scope limit, not an oversight.

   **BGV: done end to end. BFV: not started, though it should need the identical technique.** `phantom-circuits::{bgv,bfv}::{PolynomialEvaluator,LinearTransformEvaluator}` treat each of a ciphertext's `degree` raw coefficients as an independent SIMD "slot," evaluating a scalar polynomial (or applying a matrix) to each one separately - correct for the transparent scaffold, where the coefficients *are* the plaintext values directly. But real BGV/BFV ciphertext multiplication (`Evaluator::mul`/`mul_real`) is negacyclic *ring* multiplication (convolution across every coefficient jointly, established repeatedly throughout Workstream 5 - e.g. `[2,3,4,0]*[5,6,1,0] = [10,10,6,10]`, not elementwise) - confirmed the hard way here too, by writing a Horner-method test expecting elementwise squaring and getting a real (if initially alarming) negacyclic convolution result instead, matching the identity exactly once corrected. This means the "each raw coefficient is an independent slot" model these evaluators assume had **no real-ciphertext equivalent** without CRT-based plaintext batching (the standard technique, needing `t ≡ 1 (mod 2N)` and an NTT-based encode/decode substantially different from `BatchEncoder`'s raw coefficient packing) and real rotation first.

   Batching: `phantom_ring::ntt` gained public `negacyclic_forward`/`negacyclic_inverse` wrappers around the crate's own already-verified negacyclic-NTT machinery (previously `pub(crate)`-only, used only internally by `Ring::mul`'s NTT path) - `negacyclic_forward` evaluates a polynomial's coefficients at the odd powers of an `NttTable`'s own `2N`-th root `psi` (`buf[j] -> m(psi^(2j+1)) mod modulus`), verified directly against an independent `O(N^2)` evaluation before relying on it (the pre-existing NTT tests only checked round-trip consistency and multiplication equivalence, neither of which pins down this specific claim). `X^N+1`'s `N` roots in `Z_t` are exactly those odd powers when `t` is prime and NTT-friendly at this degree, so this is a genuine CRT isomorphism `R_t = Z_t[X]/(X^N+1) ≅ Z_t^N` - exact, no rounding, unlike CKKS's own floating-point canonical embedding. New `bgv::BatchEncoder::encode_batched`/`decode_batched` use it, laid out as `2` rows of `N/2` slots (row `0`, slot `j`, at embedding exponent `5^j mod 2N`; row `1`, slot `j`, at `-5^j mod 2N`) - the same `5`-power indexing `ckks::Encoder`'s own module doc comment derives and reuses the exact reasoning for (`(Z/2N)* = <5> x {+-1}`), chosen here for the identical payoff: `X -> X^(5^shift mod 2N)` rotates both rows together, `X -> X^(-1)` swaps them - though unlike CKKS, row `1` isn't forced to be any function of row `0` (no conjugate-symmetry constraint applies to a finite field), so this genuinely packs `N` independent slots, not `N/2`. Verified numerically (Python, `(N,t)` in `{(8,97),(8,193),(16,257)}`) before implementing. Verified end to end in Rust (`phantom-schemes/tests/phase5_bgv.rs`) - and conveniently, the existing toy/real-path plaintext modulus `t=17` at `REAL_DEGREE=8` already happens to be NTT-friendly (`17-1=16` is exactly `2*8`), so no new parameters were needed: an exact round trip; the actual payoff, checked against a *real* (encrypted) ciphertext-ciphertext multiplication (encode two batches, encrypt, `mul`, decrypt, `decode_batched` - confirming the result is the *elementwise* product mod `t`, not the convolution the transparent per-coefficient model would wrongly assume); and rejection of a non-NTT-friendly plaintext modulus.

   Rotation: real BGV rotation via Galois automorphism turned out to need the *same* fix relinearization already had - the generic `phantom_lattice::rlwe` hybrid key-switching samples raw (non-`t`-scaled) noise, which would corrupt BGV's exact mod-`t` decode invariant. Rather than duplicate `BgvRelinearizationKey`'s own classical-gadget-decomposition machinery, reused it directly: neither `BgvRelinearizationKey::generate` nor its `key_switch` is actually specific to `s_old == s^2` - both are generic key-switching from whatever secret to `s_new`. New `BgvKeyGenerator::generate_rotation_key_real(sk, element, decomposition_params, rng)` just computes `s_old = σ_element(s)` (the automorphism-permuted secret) and calls `generate()` unmodified. New `bgv::Evaluator::rotate_real` applies `σ_element` to both ciphertext components and key-switches the result back onto `s`, mirroring `apply_galois_automorphism`'s structure through BGV's own `t`-scaled `key_switch`. New `BgvParams::rotation_element(shift)`/`row_swap_element()` compute the matching automorphism elements. Verified end to end (`phantom-schemes/tests/phase5_bgv.rs`) - exact, not just noise-bounded, the same reason relinearization is exact: row rotation for every shift amount, row swap, and rejection of a degree-2 ciphertext.

   With batching and rotation both real, built the two `phantom-circuits` evaluators on BGV's real path. `PolynomialEvaluator::evaluate_real`: Horner's method, genuinely simpler than CKKS's own `evaluate_encrypted` since BGV's mod-`t` arithmetic is exact throughout with no scale or level to track - just `mul`/`relinearize_real`/`add_plain` in a loop, one relinearization key reused at every step (unlike CKKS's per-level keys, since BGV multiplication doesn't change which ring subsequent operations need). The first draft had a real bug its own test caught immediately: the loop folded the second-highest coefficient's `add_plain` into the first iteration instead of applying it right after the leading multiply and before the loop starts, so a linear polynomial `4 + 6x` came out as `6x^2 + 4` - fixed by matching CKKS's own `evaluate_encrypted` structure exactly. Verified end to end (`phantom-circuits/tests/bgv_real_polynomial.rs`): a genuine quadratic, a linear polynomial (zero-relinearization-calls edge case), and rejection of a degree-0 polynomial.

   `LinearTransformEvaluator::apply_real` needed its own real design work, not just a port: the scheme-independent `DiagonalMatrix` type (already used by the transparent scaffold's `apply_diagonal`, though only by reconstructing a dense matrix and summing directly - never actually rotation-driven) assumes slots form one flat cyclic group of size `n`, true for CKKS's own `rotate_real` but not BGV's two-independent-rows-of-`N/2` structure - confirmed numerically (Python) that naively feeding a full-`N`-slot transform through `DiagonalMatrix`'s own offset formula and driving it with `rotate_real` computes the *wrong* diagonals for any offset crossing the row boundary, silently reading from the other row. Rather than build the full general case (row-local diagonals for the two "straight" blocks *and* row-swap-then-rotate for the two "cross" blocks - real additional design work, deferred), scoped `apply_real` down to **row-local** (block-diagonal in the two rows) transforms only: a new BGV-specific `row_local_diagonals` helper computes diagonals directly against the row structure (`values[row] = M[row][row_base + (local_row+k) mod half]`), rejecting any transform with a cross-row entry outright rather than silently computing something wrong. Verified numerically (Python) before implementing, then end to end in Rust (`phantom-circuits/tests/bgv_real_linear_transform.rs`): a dense block-diagonal matrix exercising every row-local rotation offset, a row-local permutation checked against `rotate_real` directly, and rejection of both a cross-row entry and a missing rotation key.

   Still not done for BGV: the full (non-row-local) `LinearTransformEvaluator::apply_real` case.

   **BFV: done end to end too, tracking BGV closely** (same plaintext ring `Z_t[X]/(X^N+1)`, same `t ≡ 1 (mod 2N)` NTT-friendliness requirement). `BfvParams`/`BatchEncoder`/`Evaluator`/`BfvKeyGenerator` already wrap BGV's own internally, so most of batching was a thin pass-through: `rotation_element`/`row_swap_element` and `encode_batched`/`decode_batched` delegate straight to `bgv`'s. `decode_batched_real` needed real work, not just delegation: a real BFV ciphertext decrypts to a `Delta`-scaled raw value needing `decode_bfv_residue`'s own centering/rounding step first (the one `decode_u64_real` already uses), before the batched slots can be recovered - re-embeds the descaled per-coefficient values as a fresh mod-`t` plaintext and reuses `bgv::BatchEncoder::decode_batched`'s NTT decode unchanged (safe since `decode_bfv_residue`'s output is always `< t`, inside the "positive half" `bgv`'s own residue interpretation expects).

   Rotation turned out genuinely *simpler* than BGV's: BFV's real relinearization already reuses `phantom_lattice::rlwe`'s generic hybrid key-switching unmodified (no `t`-scaled-noise invariant to protect, unlike BGV), so rotation does too - new `bgv::BgvKeyGenerator::generate_raw_hybrid_galois_key` (a raw, unscaled pass-through, living on BGV's key generator for the same "that's where the underlying `phantom_lattice::rlwe::KeyGenerator` lives" reason `generate_raw_hybrid_relinearization_key` already does) backs `BfvKeyGenerator::generate_hybrid_galois_key`, and `bfv::Evaluator::rotate_real` is a direct, unmodified pass-through to `apply_galois_automorphism` - the same shape `relinearize_real` already has.

   Both circuit evaluators ported too: `PolynomialEvaluator::evaluate_real` mirrors BGV's Horner's method exactly (same structure, `mul_real`/`relinearize_real`/`add_plain_real` instead of BGV's `mul`/`relinearize_real`/`add_plain`, needing real BFV's own `p_moduli` for `mul_real`'s extended-basis tensor procedure). `LinearTransformEvaluator::apply_real` reuses BGV's own `row_local_diagonals` helper directly (made `pub(crate)`) rather than re-deriving it, since the row-local slot structure and its derivation are identical for BFV. All new tests (`phantom-circuits/tests/bfv_real_polynomial.rs`, `bfv_real_linear_transform.rs`, plus new `phantom-schemes/tests/phase6_bfv.rs` cases) passed on the first attempt, confirming the BGV groundwork really does transfer directly. Still not done: the full (non-row-local) `apply_real` case, same as BGV.

   This closes Workstream 6 item 2 for BGV and BFV both, at the row-local-transform scope described above. CKKS's own side of item 2 was already done (see below).

   **CKKS: the ring arithmetic already *is* SIMD (canonical embedding), but multi-level circuits exposed a real gap.** Unlike BGV/BFV, CKKS's real ring multiplication genuinely does correspond to elementwise slot multiplication (the whole point of the canonical embedding - already confirmed by Workstream 5's own cross-operation pipeline test, `mul_real` producing the elementwise product). A single multiply-relinearize-rescale step was verified correct here too before building anything further. But extending that into a genuine multi-step (Horner-method) circuit exposed two real, previously-undiscovered gaps:
   - No way to bring one real ciphertext's *level* down to match another's without also changing its *scale* the way `rescale_next_real` always does - needed to keep the original input `x` in sync with an accumulator that drops a level on every step. **Fixed**: new `Evaluator::drop_level_real`, a plain `phantom_ring::rns::rescale::drop_last_modulus` applied to each ciphertext component (the same primitive `bgv::ModulusSwitcher::switch_secret_key` already uses for secret keys), leaving scale and the represented value both exactly unchanged - valid whenever the ciphertext's own noise already fits the smaller remaining modulus product (documented as a precondition, not checked). Verified end to end (`ckks_real_arithmetic.rs`, 2 new tests): level drops by one, scale is byte-for-byte unchanged, the decrypted value is still correct, and it correctly rejects level zero and a transparent ciphertext.
   - **Found and fixed**: `Scale::compatible`'s `1e-9` relative tolerance (used by every real-path `add_real`/`mul_real`/`add_plain_real` scale-match check) was tight enough to reject two ciphertexts legitimately at "the same" scale after a real rescale - a dropped modulus is only ever *close to* `2^scale_bits` (it must be odd, per `Modulus::new`, so it can never equal an even power of two exactly), so scale drifts by a small absolute amount on every rescale; that drift compounds across a multi-step circuit and could exceed the old tolerance even though nothing was actually wrong. Reproduced directly with a two-step Horner chain. Fixed two things together, since the investigation surfaced both: `Scale::compatible` now compares `log2(scale)` against a documented absolute-bits tolerance (`1e-6` bits - about 250x the worst empirically-observed single-rescale drift, still six orders of magnitude below a genuine mismatch, which differs by at least a full bit) instead of a relative tolerance on the raw value; and `mul`/`mul_real`'s scale-compatibility check (inherited from a shared `check_binary` helper also used by `add`/`sub`) was removed outright, since real CKKS multiplication never required matching operand scales in the first place - the result's scale is simply the product of the inputs either way, only *addition* needs aligned scales, and requiring it for multiplication too was blocking exactly the kind of Horner-style chain (`x^3` as `x^2 * x`, the two operands at deliberately different scales) this item's own investigation was trying to build. Verified end to end: two new `ckks_real_arithmetic.rs` tests reproduce the original blocked scenario directly (a real multiply between mismatched-scale operands, and a real `add_plain_real` against a scale that drifted through one real rescale) and confirm both now succeed and decrypt correctly, alongside the full existing suite.

   With both gaps fixed, built the first actual `phantom-circuits` evaluator on CKKS's real path: `PolynomialEvaluator::evaluate_encrypted` (deliberately not named `evaluate_real` - that name was already taken by the transparent-scaffold "real-valued, as opposed to complex-valued, coefficients" method above it, an unrelated sense of "real" this item's own scoping had already flagged as a naming clash worth avoiding). Horner's method against a real ciphertext, needing two more pieces beyond `drop_level_real`/`Scale::compatible`, both found while actually building the evaluator rather than while scoping it:
   - **New**: `ckks::Evaluator::mul_plain_real` (ciphertext × plaintext, no relinearization needed) - the real path had `add_plain_real` but no plaintext-multiply counterpart, needed for Horner's method's leading `c_d * x` term. Implemented the same way BGV/BFV's own real `mul_plain` already do - wrap the plaintext as a degree-`0` (single-component) ciphertext and reuse `phantom_lattice::rlwe::Evaluator::mul`'s generic degree handling, rather than a bespoke scaling loop.
   - **Found and fixed**: a real relinearization key from `CkksKeyGenerator::generate_hybrid_relinearization_key` is *not* usable to relinearize a ciphertext below the level it was generated at - `phantom_lattice::rlwe::key_switch` rejects it (the key-switching key's row count is fixed to the *original* ring's modulus count at generation time, which no longer matches a lower-level ciphertext's smaller one). Invisible until now because every prior real-path test relinearized immediately after multiplying, always at the ciphertext's own top level - a genuine multi-step circuit relinearizes at *every* level along the way. New `CkksKeyGenerator::generate_hybrid_relinearization_key_at_level(sk, level, p_moduli, rng)` builds a fresh key generator entirely within `params.at_level(level)`'s own smaller ring, truncating the secret key first via repeated `drop_last_modulus` (the same technique `Decryptor::decrypt_real` already uses to bring a full-level secret key down to a ciphertext's own level) - a caller now generates one such key per level a circuit will relinearize at.

   Verified end to end: `phantom-schemes`'s own `mul_plain_real` correctness (`ckks_real_arithmetic.rs`, folded into the existing add/sub/neg/add_plain test) plus three new `phantom-circuits/tests/ckks_real_polynomial.rs` tests - a genuine cubic (`2 - x + 3x^2 - 0.5x^3`, not a trivial monomial, exercising every `add_plain_real` step with a different coefficient) evaluated on a real encrypted ciphertext end to end (encrypt → `evaluate_encrypted` → decrypt → decode, matching the true polynomial value within `1e-2`), a linear polynomial (exercising the zero-relinearization-calls edge case), and rejection of a degree-0 polynomial and of too few remaining levels. BGV/BFV remain blocked on the CRT-batching prerequisite above, untouched by this - CKKS alone now has a real multi-level circuit evaluator, the concrete thing item 2's own exit criteria were waiting on.
3. [Done] Improve polynomial/minimax approximation testing with known mathematical targets. Every existing test for these evaluators (`phase11_ckks.rs`) checked either exact arithmetic on arbitrary coefficients (`PolynomialEvaluator`/`MinimaxEvaluator`, no relationship to any real target function) or a loose sanity bound (`ComparisonEvaluator::sign`, `< -0.99`/`> 0.99`) - neither validated that these are good *approximations* of anything. New `phantom-circuits/tests/ckks_approximation_targets.rs` (8 tests) instead checks each evaluator against its exact closed-form target with a derived (not guessed) error bound:

   - `ComparisonEvaluator::sign`/`step` are literally `tanh(alpha*x)`/`0.5*(tanh(alpha*x)+1)`, so `|sign(x) - tanh(alpha*x)| < 2*e^{-2*alpha*|x|}` follows directly from `1 - tanh(z) = 2/(e^{2z}+1)` for `z > 0`; `max` is `0.5*(l+r+sqrt((l-r)^2+epsilon))`, whose error against exact `max(l,r)` is maximized at `l == r` and equals exactly `0.5*sqrt(epsilon)` there (monotonically decreasing as `|l-r|` grows) - both bounds verified against 200000 random trials in Python before being encoded as Rust assertions, and hold with the ratio of actual-to-bound error approaching (but never exceeding) `1` in the worst case, confirming they're tight, not loose.
   - `InverseEvaluator::reciprocal` and `Mod1Evaluator::centered_fractional_part` are already exact outside their clamp/rounding edge cases, so their tests check bit-for-bit agreement (to float precision) with literal `1/z` and `x - round(x)`, plus the clamp/edge-case branches explicitly (values inside `min_abs`, `x` at a `0.5` boundary, negative inputs).
   - `MinimaxEvaluator`/`CompositePolynomial` gained the flagship case this item was really about: a genuine composite-polynomial approximation of `sign(x)`, using the standard CKKS bootstrapping technique of iterating `f(x) = 1.5*x - 0.5*x^3` (six `CompositePolynomial` stages of the same cubic) - `x = 1`/`x = -1` are attracting fixed points (`f'(+-1) = 0`) and `x = 0` is repelling (`f'(0) = 1.5`), so the iterates converge to `sign(x)` for any `x` bounded away from zero. Verified in Python first (a fine deterministic grid over `|x| in [0.3, 1.0]`, 6 iterations bringing the worst-case error to `~2.7e-5`) before writing the Rust test, which asserts every point on that grid is within `1e-4` of the true sign - a real mathematical target with a real, non-arbitrary polynomial composition, replacing the old test's meaningless `(1+2x)^2`.

   One incidental fix needed along the way: every test in this file uses a much larger ring degree (`128` instead of the existing tests' `8`) purely to get enough slots (`64`) to hold the wide grids these bounds need to be checked over - the evaluators themselves are unaffected (still pure transparent-scaffold `Complex64` arithmetic, no real ring/NTT cost from the larger degree in this context).
4. [Done] Turn CKKS bootstrapping's EvalMod stage from an identity into genuine modular reduction. Real CKKS bootstrapping's EvalMod removes an unknown multiple of the ciphertext's own lowest modulus `q0` that modulus-raising introduces: after `CoeffsToSlots::apply`, each slot holds (approximately) `m_j + q0*I_j` for the true message `m_j` (`|m_j| << q0/2`) and some bounded integer `I_j`; the standard technique approximates centered-mod-`q0` reduction with a low-degree polynomial, but the operation it approximates is exactly `q0 * centered_fractional_part(x / q0)`. The pre-existing `EvalMod::centered_fractional_part` only ever computed the *unscaled* `x - round(x)` (correct for its own direct callers, whose inputs are already bounded by one) - calling it directly on `CoeffsToSlots::apply`'s output, whose magnitude has no relationship to `1`, would have silently corrupted any message outside `(-0.5, 0.5)`. New `EvalMod::reduce_mod_q` is the scaled version, verified numerically (Python, 20000 randomized trials, `|m| < 0.4*q`, both real-scalar and independent real/imaginary-part cases) before implementing, and now wired into `Bootstrapper::bootstrap` in place of `preserve_message`. New `BootstrapParams::raise_modulus` (builder-settable, `DEFAULT_RAISE_MODULUS = 1e6`) carries the assumed `q0`. Verified end to end: a new `phase12_ckks_bootstrapping.rs` test constructs an `input` engineered so that `coeffs_to_slots(input)` genuinely lands on `message + raise_modulus*(nonzero, per-slot integer)`, and confirms `bootstrap()` still recovers the true message, alongside the full pre-existing suite (still passing, including the identity-stage `preserve_message`/`centered_fractional_part` exposure test, now explicitly documented as *not* what `bootstrap()` itself calls).

   **Extended to a real, homomorphically-evaluable version**: new `EvalMod::reduce_mod_q_real(input, relin_keys)` replaces the transparent `round()` with a degree-9 odd polynomial approximating `sin(2*pi*y)` over the domain `reduce_mod_q_real`'s own doc comment derives (`y in [-1.03, 1.03]`, `I_max=1`, `msg_bound=0.03`), evaluated via `PolynomialEvaluator::evaluate_encrypted`. The coefficients are fit by Chebyshev-Gauss-Lobatto node interpolation, not a direct monomial-basis least-squares fit - the latter was tried first and found numerically unstable at this degree (nonzero even coefficients where odd-function symmetry demands exactly zero), a classic ill-conditioning failure the Chebyshev basis avoids. Verified numerically (Python, 20000 randomized trials across several `q`) before implementing: about `3%` relative error against the message bound, essentially converged by degree 9 - the price of a polynomial standing in for `f64::round()`, not a bug.

   Building the real evaluator surfaced one further real bug, found via a real (encrypted) test failing only for large-magnitude input: `PolynomialEvaluator::evaluate_encrypted`'s Horner loop reuses the same never-rescaled operand for every multiplication, so each step's noise growth scales with `Delta*|operand|` while a rescale only removes a factor of about `Delta` - for `|operand| ~ 1` these roughly cancel, but for `|operand|` on the order of `q` the ratio grows multiplicatively every step, compounding exponentially over the polynomial's degree and overwhelming the modulus long before the approximation's own error would matter. Root-caused via targeted decode comparisons (small-magnitude slots decoded correctly, large-magnitude slots came back as noise) and manual noise-growth analysis, not by expanding the modulus chain (doubling headroom did not fix it, ruling out a simple insufficient-room explanation). Fixed by pre-scaling `input` by `1/q` before `evaluate_encrypted` runs the polynomial's own (unscaled) base coefficients on the resulting small, `O(1)`-magnitude value, then scaling the result back up by `q/(2*pi)` afterward - keeping the repeatedly-multiplied Horner operand bounded throughout instead of running the approximation directly against a raw, large-magnitude ciphertext. Verified end to end (`phase12_ckks_bootstrapping.rs`): a real, encrypted ciphertext holding `message + raise_modulus*I` (`raise_modulus=100`, `|I| <= 1`) recovers the true message within the `~3%` bound derived above.
5. [Done] Give `BootstrapKeyGenerator` real key material. `BootstrapKey` previously carried only `{ params, rotation_elements }`, no cryptographic content. New `CkksKeyGenerator::generate_hybrid_galois_key` (`phantom-schemes`) fills a real-key-generation gap found while scoping this: `CkksKeyGenerator` already had `generate_hybrid_relinearization_key` for real relinearization keys, but nothing exposed the lattice layer's own already-real, already-tested `phantom_lattice::rlwe::KeyGenerator::generate_hybrid_galois_key` (RNS hybrid key-switching key from `σ_element(s)` to `s`) - a direct, unmodified pass-through, the same reasoning `generate_hybrid_relinearization_key` documents for its own. New `BootstrapKeyGenerator::generate_real(secret, rotation_elements, p_moduli, rng)` uses it to build a `BootstrapKey` carrying one real `GaloisKey` per requested rotation element; new `BootstrapKey::galois_keys()` exposes them. The pre-existing transparent `BootstrapKeyGenerator::generate` (no secret key needed) is unchanged and still used where no single secret key is available - `phantom-multiparty`'s threshold `InteractiveBootstrap::aggregate_refreshed` in particular, which has no such key by design.

   Verified end to end: a new `phantom-schemes/tests/ckks_real_arithmetic.rs` test drives the real Galois key directly at the RLWE layer (`apply_galois_automorphism`, since a real CKKS ciphertext is structurally a plain RLWE ciphertext and `ckks::Ciphertext`/`Plaintext`'s real constructors are `pub(crate)`) and confirms the rotated-then-decrypted result matches the plaintext's own automorphism-applied polynomial within the expected noise bound, generalizing `phantom-lattice`'s own single-modulus noise-bound check across every RNS limb; a new `phantom-bootstrapping/tests/phase12_ckks_bootstrapping.rs` test confirms `generate_real` produces one real (non-placeholder) `GaloisKey` per requested element in order, and that the pre-existing marker path is unaffected.

   Still partial, not the exit criterion in full: `BootstrapKey::galois_keys()` is real key material but currently unconsumed - `Bootstrapper::bootstrap`'s `CoeffsToSlots`/`SlotsToCoeffs`/`EvalMod` stages still operate on transparent slots directly via `DftEvaluator`, not by homomorphically rotating a real ciphertext, so nothing in the pipeline reads these keys yet (the same "real but not yet wired into a construction" state `RgswCiphertext` was in before any bootstrapping construction consumed it). The blocker this paragraph originally flagged - no `ckks::Evaluator::rotate_real`/Galois-automorphism wrapper existing yet - is now resolved (Workstream 5 item 3's own new "real rotation" entry: `rotate_real`/`conjugate_real` now exist and are verified, and needed a real fix to the encoder's own embedding convention along the way, not just a new method), and so is the general homomorphic linear-transform plumbing a real `CoeffsToSlots`/`SlotsToCoeffs` would need: new `phantom-circuits::ckks::LinearTransformEvaluator::apply_real` implements the standard rotate-multiply-accumulate diagonal method against *any* dense linear map, reusing the scheme-independent `DiagonalMatrix`/`BabyStepGiantStepPlan` planning types this crate already had (previously unconsumed by any real evaluator - only the transparent `apply`/`apply_diagonal` used them, and only by reconstructing a dense matrix and summing directly, never actually executing a rotation schedule) - see that method's own doc comment for the algorithm and why it's the direct `O(n)`-rotation version, not the BSGS-optimized `O(sqrt n)` schedule `DiagonalMatrix::bsgs_plan` can already produce. Verified end to end (`phantom-circuits/tests/ckks_real_linear_transform.rs`, 4 tests): a dense random matrix (exercising every rotation offset), a pure permutation (checked to match `rotate_real` directly), and rejection of a missing Galois key and of a mismatched slot count.

   **Resolved and built**: `CoeffsToSlots`/`SlotsToCoeffs` now have real (encrypted) evaluators too. Revisiting the "domain mismatch" flagged above: `phantom-bootstrapping`'s own scaffold treats `CoeffsToSlots`/`SlotsToCoeffs` as a *square* transform over however many "slots" the input ciphertext has (`DftEvaluator::transform` is generic-length, matching an arbitrary-size input, not the textbook's dimension-*reducing* `N`-coefficients-to-`N/2`-slots embedding matrix) - so the real, faithful counterpart genuinely is `LinearTransformEvaluator::apply_real` applied to the dense forward/inverse DFT matrix at `n = ckks_params().slot_count()` (a real ciphertext's own fixed slot count, unlike the transparent scaffold's arbitrary-length input), not a different, dimension-changing primitive. New `CoeffsToSlots::apply_real`/`SlotsToCoeffs::apply_real` build that matrix and diagonalize+apply it. Wiring this up (not just designing it) surfaced two further real bugs: `LinearTransformEvaluator::apply_real` never rescaled (each diagonal's `mul_plain_real` multiplies scale by `default_scale`, so composing two calls - forward then inverse - compounds scale past the ciphertext modulus and silently wraps around mod `Q` into near-zero garbage; caught directly via a failing round-trip test, isolated to the composition by verifying the forward and inverse transforms independently first), fixed by rescaling once inside `apply_real` itself (matching `evaluate_encrypted`'s own "handles its own rescaling" convention, fixing every caller, not just bootstrapping); and no level-aware Galois key generator existed (the same problem `generate_hybrid_relinearization_key_at_level` fixed for relinearization keys, invisible until something chained two `apply_real` calls across a rescale) - fixed by new `CkksKeyGenerator::generate_hybrid_galois_key_at_level`. Verified end to end (`phantom-bootstrapping/tests/phase12_ckks_bootstrapping.rs`): a real ciphertext round-tripped through `apply_real` forward then inverse recovers the original values within real-noise tolerance.

   **Resolved and wired**: new `Bootstrapper::bootstrap_real(input, c2s_galois_keys, eval_mod_relin_keys, s2c_galois_keys)` composes `CoeffsToSlots::apply_real` / `EvalMod::reduce_mod_q_real` / `SlotsToCoeffs::apply_real` on an actual encrypted ciphertext, now that item 4's own `reduce_mod_q_real` closes the last missing piece. Each of the three stages needs key material generated at its own level (each `apply_real` call consumes a level via its own internal rescale, and `reduce_mod_q_real` consumes several more on top of that), so `bootstrap_real` takes the three key sets as explicit parameters rather than folding level-selection into `BootstrapKey` itself - `BootstrapKey::galois_keys()` (a single top-level set) doesn't fit a multi-level chained pipeline, the same reason `CkksKeyGenerator::generate_hybrid_galois_key_at_level` exists at all. Unlike `Bootstrapper::bootstrap`'s transparent path, `bootstrap_real` does not relabel its output to `target_level`/`default_scale` - a real ciphertext's level and scale describe its actual RNS representation, not a claim `Ciphertext::new` can overwrite without doing the work, so `bootstrap_real`'s output simply carries whatever level and scale the three real stages leave it at.

   Still not the exit criterion in full: `bootstrap_real` is the digit-extraction half of bootstrapping (coefficients-to-slots, eval-mod, slots-to-coefficients), not the whole circuit - real bootstrapping first raises a nearly-exhausted ciphertext's modulus back up to a full top-level chain before this pipeline can run on it, and that modulus-raise step remains separate and not yet built (the same gap `Bootstrapper::bootstrap`'s own doc comment already flagged for the transparent path); `bootstrap_real`'s own tests construct `input` already at the raised level this pipeline expects, the same way `reduce_mod_q_real`'s own tests do. Verified end to end (`phase12_ckks_bootstrapping.rs`): a real, encrypted ciphertext engineered so a real `CoeffsToSlots::apply_real` exposes `message + raise_modulus*I` recovers the true message through all three real stages chained together, at a modulus chain sized for the total rescales the full chain needs (one more than `reduce_mod_q_real`'s own fixture budgets, for `CoeffsToSlots`'s and `SlotsToCoeffs`'s own rescales).
6. [Done] Decide whether BGV/BFV bootstrapping remain reserved modules or become explicit future milestones. **Decision: stay reserved-but-unimplemented placeholders, not scheduled as an explicit milestone yet.** Real BGV/BFV bootstrapping (Halevi-Shoup/Gentry-Halevi-Smart-style digit extraction) is a substantially larger undertaking than CKKS bootstrapping - a low-degree polynomial "digit extraction" evaluation per prime-power factor of the plaintext modulus, thin/thick-bootstrapping variants, and its own noise/parameter analysis - and this repository doesn't have either of BGV/BFV's own real-path prerequisites yet: real per-slot SIMD circuit evaluators (item 2's own CRT-batching blocker) or even item 4/5's level of "genuine but still transparent-slot" bootstrapping progress CKKS now has. Scheduling BGV/BFV bootstrapping as a milestone ahead of those would invert the actual dependency order. Revisit once BGV/BFV's own CRT-batching SIMD prerequisite lands and a real (non-scaffold) evaluator exists for them (item 2's own blocker) - at that point, whether to build digit-extraction bootstrapping becomes a real scheduling decision rather than a premature one. `bgv`/`bfv::{BootstrapParams, BootstrapKey, Evaluator}` stay exactly as they are (unit-struct markers, `Evaluator::bootstrap_unimplemented` always erroring) - no code change, just the explicit decision this item asked for.
7. [Done] Add parameter documentation for any bootstrapping presets. The one dedicated "preset" type in this crate, `BootstrapParamsLiteral`, turned out to be dead code - defined but never converted into a usable `BootstrapParams` anywhere, and stale relative to item 4's own later `raise_modulus` addition (missing that field entirely). Fixed both: added `raise_modulus` to the literal and a new `BootstrapParamsLiteral::build(self, ckks_params) -> Result<BootstrapParams>` that runs the exact same validation `BootstrapParams::new` always does (an invalid literal, e.g. `target_level` above the target `CkksParams::initial_level`, is still rejected, not silently accepted), making the type actually usable for the first time. Documented every field precisely against what actually consumes it, correcting one likely misconception along the way: `sparse_slot_count` is *not* read by `Bootstrapper::bootstrap` itself (it operates on whatever slot count its input has, checked against the full `slot_count`) - it's purely `Packer`/`Unpacker`'s own per-ciphertext slot allotment for interleaving `batch_size` independent ciphertexts into one packed ciphertext. Deliberately did not invent named constant presets (e.g. a hardcoded "128-bit standard" `BootstrapParamsLiteral`): `target_level`/`sparse_slot_count` are only meaningful relative to a specific `CkksParams` (`initial_level()`/`slot_count()`), and this repository has no analogous named CKKS/BGV/BFV parameter presets to anchor one to yet - inventing one here would be speculative, not documentation. Verified end to end (`phase12_ckks_bootstrapping.rs`): a literal converts to `BootstrapParams` with every field matching, and an out-of-range one is still rejected.

Exit criteria:

- Circuit APIs remain usable across toy and production internals.
- CKKS bootstrapping has a documented path from scaffold to production.
- Exact-scheme bootstrapping status is explicit.

### Workstream 7 - Multiparty and Protocol Security

Owned areas:

- `phantom-multiparty::common`
- `phantom-multiparty::vss`
- `phantom-multiparty::mpbgv`
- `phantom-multiparty::mpbfv`
- `phantom-multiparty::mpckks`

Tasks:

1. Review protocol transcripts and share encodings for replay, stale-share, and domain-separation risks.
2. Add stronger validation around participant sets, thresholds, rounds, and protocol kinds.
3. [Done] Replace `common::transcript::stable_hash_256` — was a small hand-rolled XOR/multiply/rotate mixer with no cryptanalysis behind it — with SHA-256 (`sha2`, `default-features = false`, added to the workspace and to `phantom-multiparty` per the dependency policy's own process). `TranscriptHash`'s own shape (`[u8; 32]`) needed no change; `Transcript::hash`'s determinism test continues to pass unchanged (it only checks equal inputs produce equal hashes, not any specific byte pattern). `SECURITY.md`, `docs/technical-manual.md`, and `docs/internal/dependency-policy.md` updated alongside.
4. Tie collective key generation, relinearization-key generation, and Galois-key generation (`ckg`/`rkg`/`gkg` across `mpbgv`/`mpbfv`/`mpckks`) to production key material once RLWE is hardened — today all three `aggregate_*` functions ignore collected share content and return placeholder key material (e.g. `CollectiveKeyGen::aggregate_public_key` returns an all-zero public key regardless of shares). **Not yet started** - item 4a below builds the primitive this will be wired on top of, but the wiring itself (into `ckg`/`rkg`/`gkg` across all three schemes) is separate, future work.
4a. [Done, Stage 1 of item 4/5] Built the real cryptographic primitive collective key generation and threshold decryption/re-encryption will be wired on top of: `phantom-multiparty::vss`, a standalone, scheme-agnostic Pedersen verifiable-secret-sharing (VSS) distributed-key-generation (DKG) module (see its own module doc comment, `crates/phantom-multiparty/src/vss/mod.rs`, for the full scheme). Driven by an explicit security requirement (confirmed with the user across two rounds of clarifying questions): whoever operates the infrastructure aggregating multiparty protocol messages must never see the collective secret, not even momentarily, and the protocol must detect a participant sending inconsistent shares to different peers - ruling out both a dealer-based Shamir split (someone briefly holds the full secret) and non-verifiable secret sharing (no way to catch a lying dealer). Each dealer locally samples a degree-`(t-1)` vector-valued polynomial (constant term = their own small centered-integer secret, embedded as a Ristretto255 scalar - RLWE secret coefficients are always small enough, ternary or discrete-Gaussian bounded to roughly `±32`, to embed directly as a scalar and Shamir-share per ring coefficient rather than needing to prove any RLWE RNS modulus prime, which `Modulus::new` doesn't check), publishes a compact Pedersen *vector* commitment (one group element per polynomial degree, not one per coordinate - `vss::VectorPolynomial::commit`'s own doc comment proves the one-blinding-scalar-per-degree construction is still perfectly hiding), and sends each participant their own evaluation. Recipients verify each share against the public commitment before accepting it (`vss::VssShare::verify`), accumulate verified shares from every dealer without ever assembling the full secret (`vss::ShareAccumulator`), and `>= threshold` participants' own final combined shares reconstruct the collective secret via standard Lagrange interpolation (`vss::reconstruct_secret`) - subset-independence (any two different qualifying subsets reconstruct identically) verified both in Python and as a dedicated Rust test, a property nothing in this crate's existing `threshold`/`ShareAggregator` machinery had ever exercised before. New dependency `curve25519-dalek` (Ristretto255), `phantom-multiparty` only - see `docs/internal/dependency-policy.md`'s own entry for exact feature set and a real, non-obvious `digest`-version incompatibility with this workspace's `sha2` avoided by using `from_uniform_bytes` instead of `hash_from_bytes`. Verified numerically in Python before implementing (a toy subgroup-based simulation, and a real-field embedding/centering check using the actual Ristretto255 group order) per this repository's own established practice; 9 Rust integration tests (`crates/phantom-multiparty/tests/vss_dkg.rs`) plus in-module unit tests cover single- and multi-dealer round trips, subset independence, VSS tamper detection (both commitment and share tampering, and cross-dealer confusion), malformed-input rejection, combine-time verification, and a randomized property test. **Explicitly not done in this stage**: wiring this into `ckg`/`rkg`/`gkg`/`partial_decrypt`/`reencryption`/`interactive_bootstrap` for any of `mpbgv`/`mpbfv`/`mpckks` (items 4/5 above remain open for that); the bridge from an RLWE `Poly`'s own RNS representation to/from the small centered integers this module operates on (`phantom_ring::rns::extension::reconstruct_centered_values` exists for one direction, the reverse embed-into-RNS direction needs its own new helper, not built here); noise flooding/smudging (item 5a).
4b. [Done, BGV slice of item 4] Wired real collective public-key generation for BGV: `mpbgv::CollectiveKeyGen::create_share`/`aggregate_public_key` now compute a genuine `t`-scaled BGV public key `(sum_i b_i, a)` for the collective secret `s = sum_i s_i`, matching `bgv::keygen::BgvKeyGenerator::generate_keypair_real`'s own `b = t*e_pk - a*s` construction (required so a key's own noise doesn't survive decryption's final `mod t` reduction). `RKG`/`GKG` and BFV/CKKS's own mirrors remain open, future work.

   **A design correction found while implementing, worth recording since it revises item 4a's own framing**: CKG's collective *public key* does not need Shamir/VSS reconstruction at all - each participant's own `local_secret_share` must be their ordinary, independently-generated small RLWE secret (the same shape a normal single-party `SecretKey` has), not a Shamir *share* of anything. A raw Shamir share, evaluated at a nonzero point, is a large, uniformly-random-looking field element - embedding one as an RLWE secret and computing `a*s_i` with it does not correspond to any meaningful cryptographic operation, and the collective public key that results is not decryptable by any consistent secret. Simple per-party independence already gives item 4a's own security requirement (no one, including the aggregating infrastructure, ever sees the collective secret) for the public-key step specifically - summing public `b_i` values never requires seeing any `s_i`. `phantom_multiparty::vss` (item 4a) remains genuinely necessary, but for a *different* purpose than originally scoped in item 4a's own text: giving participants a verifiable, recoverable backup of each other's own secret contributions (composable with CKG, not required by it) - which is exactly what item 5's own threshold-decryption need actually is. `mpbgv::ckg`'s own doc comment and `tests/phase14_mpbgv.rs`'s `collective_public_key_generation_via_dkg_produces_a_genuinely_decryptable_key` (which runs a full VSS round alongside real CKG to demonstrate the two compose, and reconstructs the collective secret via `vss::reconstruct_secret` purely as an independent, test-only correctness check) document this precisely.

   **A second, separate bug found and fixed along the way**: `common::shares::ShareAggregator::aggregate()` truncates to exactly `threshold` shares (by ascending `ParticipantId`) - correct for genuine Shamir-style (t-of-n) protocols, where any qualifying subset reconstructs the same value, but silently wrong for CKG's own *additive* (n-of-n) construction, where omitting even one contributing participant's share produces a public key for a *different* collective secret than the one every contributor actually agreed to. Confirmed directly: a 3-participant, threshold-2 test produced a public key matching only 2 of the 3 dealers' secrets, decrypting to garbage against the true 3-party sum. Fixed by adding `ShareAggregator::all_shares()` (returns every collected share once `threshold` is met, no truncation) alongside the existing `aggregate()`, and switching `CollectiveKeyGen::aggregate_public_key` to use it - both methods' own doc comments now state precisely which construction each is for.

   Also found and fixed while building this item's own test: `mpbgv`'s existing toy test fixture (`degree=8`, moduli `[257, 769]`) was never noise-safe for BGV's *real* path - confirmed directly, even a single-party `generate_keypair_real` round trip against it fails the majority of the time across randomized seeds (43/50 in one run), since nothing in `mpbgv` exercised the real path before this item (every other `mpbgv` test uses the transparent scaffold, which ignores noise budgets entirely). The new real-CKG test reuses `phantom-schemes/tests/phase5_bgv.rs`'s own `real_params()`-equivalent large-modulus fixture instead of deriving a new one.

4c. [Done, mpbgv slice] Wired real collective Galois (rotation) key generation for BGV, `mpbgv::GaloisKeyGen` - matching this workstream's own priority ordering (real Galois keys matter to an actual deployment's own aggregation/grouping computation step more than mirroring CKG/PCKS to BFV/CKKS would). **Found during research, not assumed**: this workspace has two real Galois-key constructions, and only one is safe for BGV. `phantom_lattice::rlwe::KeyGenerator::generate_hybrid_galois_key` (RNS-hybrid, extended `QP` ring, raw noise - what BFV and CKKS bootstrapping use) is *not* safe for BGV: its `mod_down` rounding doesn't distribute over `t`-scaled noise, corrupting BGV's exact `mod t` decode (already documented directly in `bgv::relinearization`'s own module doc comment - a residual noise pattern like `[21, 12, -21, -23]`, not `≡ 0 mod t` in 3 of 4 coefficients). Real BGV instead uses `phantom_schemes::bgv::BgvRelinearizationKey` (classical gadget decomposition over the plain `Q` basis, exact integer arithmetic, `t`-scaled noise) for both relinearization and rotation. This changed `GaloisKeyGen::aggregate_keys`'s own return type from `Vec<phantom_lattice::rlwe::GaloisKey>` (structurally committed to the *other*, BGV-unsafe type) to `Result<BgvRelinearizationKey>` - a real, necessary breaking change, the same kind items 4b/5b already made.

    Construction: `BgvRelinearizationKey::generate`'s own single-party row formula (`moduli.len() * levels` rows, row `(j,i)`: `b_{j,i} = scale_by_base_power_and_lift(s_old, base_log, i, lift_j) + t*e_{j,i} - a_{j,i}*s_new`) is the identical `t`-scaled additive equation item 4b already established, tiled per row: since ring automorphisms are linear over addition (`sigma(sum_p(s_p)) = sum_p(sigma(s_p))`, verified directly), each participant contributes `b_{j,i}^{(p)} = scale_by_base_power_and_lift(sigma(s_p), base_log, i, lift_j) + t*e_{j,i}^{(p)} - a_{j,i}*s_p` per row, with one common `a_{j,i}` per row (`derive_common_ring_element`, a distinct purpose label per row so none collide). Made `scale_by_base_power_and_lift` `pub` (was a private helper inside `bgv::relinearization`) and added `BgvRelinearizationKey::from_rows` (a new, additive constructor alongside the existing `generate`) so collective key generation can reuse both rather than duplicating gadget-weighting logic a third time.

    Scoped to one rotation `element` per `GaloisKeyGen` session (was a placeholder `elements: Vec<usize>` plural shape) - matching `CollectiveKeyGen`/`ReEncryptor`'s own "one clear thing per session" design; a caller needing several rotation amounts runs several sessions.

    **A real bug found and fixed while testing, worth recording precisely**: the first implementation summed *both* `a_{j,i}` and `b_{j,i}` across participants in `aggregate_keys` - but `a_{j,i}` is a shared constant every participant derives identically (`derive_common_ring_element`, not a per-participant additive contribution), so summing it across `n` participants gave `n*a` instead of `a`, silently corrupting every row. Isolated by comparing a single-party (`n=1`) run (passed - the summing code path never actually adds anything with only one share) against `n=2` (failed), then printing each participant's own per-row `a` (identical, correctly derived) and `b` (correctly summed - verified by hand against `b_1+b_2 mod q`) directly, which made the `a`-summing mistake visible immediately. Fixed: `aggregate_keys` now keeps one copy of `a_{j,i}` (from whichever share is read first) and *verifies* every other share's own copy matches exactly (a mismatch means a malformed or malicious share) rather than summing it.

    Verified end to end (`phase14_mpbgv.rs::collective_galois_key_generation_via_real_dkg_rotates_a_genuine_ciphertext`): the same participants collectively generate both a real public key and a real rotation key, encrypt and rotate a genuine batched ciphertext, and decrypt correctly under the (test-only) reconstructed collective secret - robust across several independent seeds. Mirroring to `mpbfv`/`mpckks` not attempted.

4d. [Done, mpbgv slice] Wired real collective relinearization-key generation for BGV, `mpbgv::RelinearizationKeyGen`. **Structurally different from items 4b/4c/5b, found during scoping, not assumed**: those three are all linear in each participant's own secret `s_p`, so each participant computes their own additive contribution alone. Relinearization needs the collective secret's *square* - `s^2 = (sum_p s_p)^2 = sum_p sum_q s_p*s_q` - which has cross terms `s_p*s_q` for `p != q` that no single participant can form from their own secret alone. This needs a genuine two-round protocol rather than a one-round tiling of item 4b's own equation the way item 4c was.

    Construction (derived and numerically verified in Python before any Rust - 3000 trials across `n_parties` in `[1,2,3,5,8,12]`, sized to a modulus large enough to avoid toy-noise exhaustion, which surfaced once at `n_parties=12` against an undersized toy modulus and disappeared with a larger one, confirming genuine noise growth rather than an algebra error): reuses the collective public key `(cpk_b, cpk_a)` (item 4b's own output) as a tool. Per gadget row `i` - same `(modulus_index, level)` indexing item 4c already uses: **round 1**, each party locally samples fresh ephemeral ternary `u_i^(p)` and computes `h0_i^(p) = cpk_b*u_i^(p) + t*e0_i^(p) + scale_i(s_p)`, `h1_i^(p) = cpk_a*u_i^(p) + t*e1_i^(p)` (`scale_i` is item 4c's own `scale_by_base_power_and_lift`); summing every party's row publicly gives `(H0_i, H1_i)`, a fresh encryption of `scale_i(s)` under the collective key that nobody decrypts. **Round 2**, each party uses that public aggregate: fresh ephemeral ternary `v_i^(p)`, `h0'_i^(p) = s_p*H0_i + cpk_b*v_i^(p) + t*e2_i^(p)`, `h1'_i^(p) = s_p*H1_i + cpk_a*v_i^(p) + t*e3_i^(p)`; summing every party's row gives the real relinearization-key row, decrypting under the collective secret to `scale_i(s^2) + t*(noise)`, via the collective public key's own identity `cpk_b + cpk_a*s = t*e_pk` and `s*scale_i(s) = scale_i(s^2)`.

    `common::shares::Share`/`ShareAggregator`/`SessionState` already support multi-round protocols directly (`Share::new` stamps the session's current round, `ShareAggregator` rejects a share from the wrong round, `SessionState::advance_round` exists for exactly this) - no new session/round infrastructure needed. `RelinearizationKeyGen::new` takes the collective public key as an explicit input (unlike items 4b/4c/5b's own constructors), since both rounds encrypt under it. Neither round sums a shared constant the way item 4c's per-row `a` was - every summed quantity in both rounds is a genuine per-participant contribution - so that bug class doesn't apply here, though row-count/shape agreement across shares is still checked the same way.

    Verified end to end (`phase14_mpbgv.rs::collective_relinearization_key_generation_via_real_dkg_relinearizes_a_genuine_product`): the same participants collectively generate a real public key and, via both rounds, a real relinearization key, multiply a genuine batched ciphertext by itself (raw, unrelinearized), relinearize with the collectively-generated key, and confirm the decrypted result matches the raw (pre-relinearization) product exactly under the (test-only) reconstructed collective secret. Mirroring to `mpbfv`/`mpckks` not attempted.

5. Replace share aggregation's current byte-equality check (`ensure_equal_payloads`, used by `PartialDecryptor`/`ReEncryptor`/`InteractiveBootstrap`) with real threshold secret-share reconstruction (e.g. Lagrange interpolation) once ciphertext semantics are production-grade — there is currently no actual secret sharing of a decryption/re-encryption computation happening, only agreement-checking on identical cleartext-equivalent payloads. `PartialDecryptor`/`mpbfv`/`mpckks::InteractiveBootstrap` remain open (still transparent placeholders); `mpbgv::ReEncryptor` is done, see item 5b — but not via Lagrange reconstruction, see that item's own text for why.

5b. [Done, mpbgv slice] Wired real collaborative key-switching (PCKS) for `mpbgv::ReEncryptor` — the mechanism a real multiparty deployment uses for result delivery toward a recipient who never participates in DKG at all: each participant contributes a share computed from their own already-known local secret (the same `s_i` `CollectiveKeyGen` already uses) and the *recipient's* public key; combining every contributing participant's share (`ShareAggregator::all_shares`, the same additive n-of-n construction item 4b already established, matching this deployment's own stated default and explicitly *not* Lagrange/Shamir reconstruction — see below) produces a ciphertext under the recipient's own key, decryptable only by them, without any party (including whoever combines shares) ever seeing the plaintext, the collective secret, or the recipient's own secret. Construction: `h0_i = u_i*b_r + t*e0_i + s_i*c1`, `h1_i = u_i*a_r + t*e1_i` (`u_i` fresh ternary per participant per call — the source of the output ciphertext's own randomization, not a reused public value), combined as `ct_out0 = c0 + sum_i(h0_i)`, `ct_out1 = sum_i(h1_i)`. Verified algebraically that every noise term beyond the original `c0+c1*s` is `t`-scaled (vanishes under decryption's own `mod t`), then numerically (Python, 120 randomized trials across 1-12 participants, plus confirming the platform's own intermediate view doesn't trivially reveal the plaintext) before any Rust — see `mpbgv::reencryption`'s own doc comment for the full derivation.

    **Why this isn't Lagrange/Shamir reconstruction, correcting this item's own original framing**: item 5's text above assumed genuine (t,n) threshold reconstruction was the target, matching `vss::reconstruct_secret` (item 4a). Discussed directly with the user before implementing: additive n-of-n is the right default here, not a stepping stone toward it — every party who helped generate the collective key also contributes to every re-encryption, which is strictly stronger against colluding-provider secret recovery than any t-of-n variant (fewer colluding providers can reconstruct under n-of-n, since none short of everyone can). `phantom_multiparty::vss` remains genuinely useful for a *different*, not-yet-attempted purpose (giving participants a verifiable backup of each other's own secrets, for whatever future fault-tolerance work is wanted), but PCKS's own correctness doesn't depend on it, mirroring item 4b's own finding for CKG exactly.

    Verified end to end (`phase14_mpbgv.rs::reencryption_via_pcks_delivers_the_result_to_a_genuinely_separate_recipient`): a real collective keypair (via `CollectiveKeyGen`), a real encryption under it, a real PCKS round toward a wholly separate, non-DKG recipient keypair, decrypting correctly under the recipient's own secret — robust across several independent seeds. Its smudging noise was a fixed, uncalibrated placeholder (`10x STANDARD_ERROR_STD_DEV`) at the time this item shipped — see item 5a, which replaced it with a rigorously derived bound.

5a. [Done] Replaced `mpbgv::reencryption`'s fixed, uncalibrated smudging-noise constant with a rigorously derived one. Each PCKS share `h0_i = u_i*b_r + t*e0_i + s_i*c1` is, from the view of anyone who can decrypt an *individual* share (e.g. a combiner colluding with the recipient), a fresh RLWE-style encryption of `s_i*c1` under the recipient's own public key — the smudging noise `e0_i`/`e1_i` is what stops the residual from leaking `s_i` itself once `c1` (public) is factored out, and an arbitrary multiplier gives no actual guarantee of that. Added `phantom_lattice::security::smudging_std_dev(signal_noise_bound, statistical_security_bits) = signal_noise_bound * 2^(statistical_security_bits / 2)`, the noise-flooding relationship (`sigma_smudge^2 = 2^lambda * sigma_ct^2`) Mouchet, Troncoso-Pastoriza, Bossuat & Hubaux, *"Multiparty Homomorphic Encryption from Ring-Learning-with-Errors"* ([eprint 2020/304](https://eprint.iacr.org/2020/304)), Section IV-E/Appendix A, derive for exactly this purpose in a collective key-switching protocol — a public, peer-reviewed paper, cited directly (distinct from this repository's own practice of never naming a competing *reference implementation*). Also added a recommended default, `RECOMMENDED_STATISTICAL_SECURITY_BITS = 40` — a standard statistical-security target deliberately smaller than this codebase's own 128-bit *computational* target (`max_secure_total_modulus_bits_128`), since the formula's exponential noise growth makes matching 128 bits impractical for any usable noise budget, and statistical indistinguishability doesn't need to match RLWE's own hardness margin.

    `ReEncryptor::new` now takes an explicit `statistical_security_bits: u32`, and `create_share` takes an explicit `ciphertext_noise_bound: u64` — the caller's own worst-case bound on the *specific* ciphertext being switched (via `phantom_schemes::bgv::noise`'s existing composable bound functions), since `ReEncryptor` has no way to know a ciphertext's operation history itself.

    **A real infrastructure gap found while implementing, not anticipated in scoping**: `phantom_ring::sampling::sample_discrete_gaussian`'s cumulative-distribution-table sampler allocates a table of width `O(sigma)` — fine at ordinary encryption-noise scale (`sigma ~= 3.2`) but a 34GB allocation (confirmed directly, a real `SIGABRT`) at smudging scale (`sigma` in the hundreds of millions at the recommended 40-bit target). Added `phantom_ring::sampling::sample_smudging_gaussian`, a Box-Muller-based sampler with no table (`O(1)` per coefficient) for exactly this regime, alongside the existing table-based sampler (unchanged, still used everywhere else). Verified via the same empirical mean/stddev statistical check the existing sampler's own test uses, at smudging scale.

    Verified the existing `real_ckg_params()` fixture (modulus ~1e15, degree 8, t=17) still has enough noise budget for this at the recommended 40-bit target before implementing: `bgv::noise::fresh_public_key_noise_bound(8) = 340`, giving `sigma_smudge ≈ 3.57e8`, worst-case combined bound across 3 participants ≈ `2^32.6`, against a ≈44.7-bit budget — about 12 bits (≈4000x) to spare. `reencryption_via_pcks_delivers_the_result_to_a_genuinely_separate_recipient` continues to pass unchanged at that fixture with the new, correctly-sized noise.

    **A separate finding, documented but not fixed here**: the wider threshold-FHE literature also warns that *retrying* a share-generation protocol (a participant producing a second share for the same session/public randomness) leaks key material via accumulated linear algebra, independent of how large any single call's smudging noise is. `mpbgv`'s protocols don't currently guard against a participant's `create_share` being invoked twice for the same session — out of scope for this item (a separate, larger piece of stateful anti-replay tracking), flagged in `SECURITY.md` and tracked below as item 8.
6. Document security assumptions for threshold and interactive bootstrapping protocols.
7. Add adversarial tests for malformed shares and protocol confusion.
8. Guard against a participant's `create_share`/`create_share_round1`/`create_share_round2` being invoked more than once for the same session across `mpbgv`'s protocols (CKG/GKG/RKG/PCKS) — repeated shares for the same public randomness and secret-key contribution leak key material via accumulated linear algebra, regardless of per-call smudging noise (see item 5a's own "separate finding"). Needs stateful anti-replay tracking (e.g. per-session, per-participant "already contributed" bookkeeping) this crate doesn't currently have. Not started.

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

### Workstream 11 - CKKS Real Bootstrapping: Modulus Raise

Owned areas:

- `phantom-ring::rns`
- `phantom-schemes::ckks`
- `phantom-bootstrapping::ckks`

Context: Workstream 6 items 4/5 built `EvalMod::reduce_mod_q_real` and `Bootstrapper::bootstrap_real`, the real digit-extraction half of CKKS bootstrapping (coefficients-to-slots, eval-mod, slots-to-coefficients) - but real bootstrapping's own first step, raising a nearly-exhausted ciphertext's modulus back up to a full top-level chain, was explicitly out of scope there and remained unbuilt. Without it, `bootstrap_real` could only be exercised on a ciphertext an *existing* test manually constructed already at the raised level - not on the output of a real multi-level computation that had actually run out of budget.

Tasks:

1. [Done] Add an RNS basis-extension primitive suited to modulus-raise, distinct from the existing `phantom_ring::rns::extension::extend_basis`. `extend_basis` reconstructs each coefficient's true value as a *non-negative* residue in `[0, Q_source)` before re-reducing into the target basis - correct for its own existing callers, but wrong for modulus-raise, which needs the *centered* (signed, small-magnitude) representative embedded into the bigger basis instead (embedding the non-negative reconstruction would introduce an offset on the order of `Q_source` into every coefficient, not the small bounded wraparound real bootstrapping's `EvalMod` is built to remove). New `phantom_ring::rns::extension::extend_basis_centered` reuses `reconstruct_centered_values` (already built for CKKS's own real decoding) for the reconstruction half, the same way `extend_basis`/`rescale_and_round` already share `reconstruct_true_values`, and the same `rem_euclid`-based signed-to-residue embedding `phantom_schemes::ckks::encoder`'s own `embed_signed_coeffs` uses for the other half. Verified end to end (`phantom-ring/tests/extend_basis_centered.rs`, 3 tests): a hand-picked negative-value case confirming it differs from `extend_basis`'s own non-negative convention as expected, a 200-trial round-trip property check, and rejection of a component-count mismatch.
2. [Done] Derive, numerically before implementing, the actual bound on the wraparound integer a raised ciphertext's `<s, ct>` introduces, as a function of ring dimension and secret-key distribution (not a freely-chosen constant the way `BootstrapParams::raise_modulus` was treated before this item). Derivation: a level-zero ciphertext `(c0, c1)` decrypts as `c0 + c1*s ≡ Δm + e (mod q0)`; negacyclic convolution bounds `c1*s`'s raw (unreduced) coefficients by `||c1||_inf * ||s||_1 <= (q0/2)*h` (`h` = the ternary secret's Hamming weight), so the raw integer value of `c0 + c1*s` is bounded by `(q0/2)*(1+h)`, giving `|I| <= (h+2)/2` for the wraparound integer `Δm + e + q0*I` a raised (bigger-basis, no-longer-reduced-mod-q0) decryption reveals. Verified numerically (Python, 400 randomized trials across several Hamming weights) before implementing: never exceeded, worst observed ratio to the bound `~0.67`. This is what makes `EvalMod`'s existing tight domain requirement (`|I| <= 1`, from Workstream 6 item 4) unsatisfiable for any real secret in the worst case (`(h+2)/2 <= 1` needs `h <= 0`) - a genuine, previously-undocumented gap this derivation surfaced, not assumed away.
3. [Done] Wire a real modulus-raise operation into `phantom-schemes::ckks::Evaluator` (`raise_level_real(ciphertext, target_level)`), raising a real, level-zero ciphertext's basis via `extend_basis_centered` on each of its `c0`/`c1` components, without changing the encrypted value's centered representation. Verified end to end (`phantom-schemes/tests/ckks_real_arithmetic.rs`, 2 tests): a real ciphertext encrypted directly at level zero, raised to the top level, decrypts (via the *full*, untruncated secret key, working entirely outside CKKS's own encode/decode layer via `reconstruct_centered_values` directly) to exactly `e + q0*I` for an `I` matching item 2's own derived bound - and rejection of a ciphertext above level zero.

   **Deliberately not connected to `Bootstrapper::bootstrap_real`**: item 2's own finding means chaining a real raise directly into the existing narrow-domain `EvalMod::reduce_mod_q_real` would silently produce wrong output for any realistic secret (this ring's own ternary secret already has `h` large enough that the derived bound exceeds the polynomial's domain by a wide margin) - wiring that up now, without first widening `EvalMod`'s domain to match a real secret's Hamming weight (more Chebyshev terms, or an iterated-doubling reconstruction from a narrow base case - both flagged, neither attempted, in `Evaluator::raise_level_real`'s own doc comment), would either need an insecure near-zero-Hamming-weight secret to "work" or fail outright. Landing a primitive that only demonstrably works for insecure parameters would misrepresent its own real security-relevant scope, so `raise_level_real` stays a standalone, honestly-scoped `Evaluator` method for now rather than being force-connected to `bootstrap_real`.
4. [Done] Update `BootstrapParams::raise_modulus`'s own documentation to reflect a real, derived relationship rather than an arbitrary constant - `Evaluator::raise_level_real`'s own doc comment now states plainly that `raise_modulus` should be the ciphertext's own real `q0` (the level-zero modulus `raise_level_real` raises from), not a freely-chosen value, and documents the `(h+2)/2` bound directly. No change to `BootstrapParams`'s own default/validation: the derived bound is a statement about what `EvalMod`'s domain needs to satisfy, not a constraint `BootstrapParams` itself could check without knowing the caller's own secret Hamming weight (which it doesn't carry).
5. [Done, partial] Widen `EvalMod`'s domain to match a realistic secret's Hamming weight, attempting the concrete remainder item 3 flagged. New `EvalMod::reduce_mod_q_real_wide(input, relin_keys, doublings)` generalizes `reduce_mod_q_real` (which now just calls it with `doublings=0`) via the standard angle-doubling reconstruction: rather than fitting one polynomial across a wide domain (impractical - a low-degree fit can't track `sin`'s own oscillation across many periods), it evaluates a much more accurate degree-`17` `sin`/`cos` pair (`SIN_APPROX_BASE_COEFFICIENTS`/new `COS_APPROX_BASE_COEFFICIENTS`, both re-fit via the same Chebyshev-Gauss-Lobatto method, replacing the original degree-`9` fit) on a rescaled-down input, then reconstructs the wide-domain result via `doublings` applications of the exact trigonometric double-angle identity. Verified numerically (Python) before implementing: the *doubled* result's own relative error stays close to `0.6%` uniformly for `doublings` up to at least `5` (`I` bounds up to `32`), a real improvement over the original fit's `~3%` at `doublings=0` alone (needed specifically because doubling *amplifies* the base fit's own error each step). New `Bootstrapper::bootstrap_real_wide` generalizes `bootstrap_real` the same way. Verified end to end against an **engineered** slot-domain wraparound (`phase12_ckks_bootstrapping.rs`, `doublings=2`, `|I|` up to `4`, beyond `reduce_mod_q_real`'s own `|I| <= 1`).

   Building this surfaced one further real bug, found the same way item 4's own noise-growth bug was: a real, encrypted test failing partway through a long doubling chain. Each doubling step's `mul_real` result scale is the *product* of two already-slightly-drifted operand scales (a real rescale only ever divides by a modulus *close to*, never exactly, `2^scale_bits`), so scale drift roughly *doubles* every doubling step rather than merely accumulating additively the way a single Horner chain's own drift does - eventually exceeding `Scale::compatible`'s tolerance for enough doublings, even with primes chosen close to `2^scale_bits`. Since `sin`/`cos` always share identical drift (both branches rescale by the exact same modulus sequence, so ciphertext-vs-ciphertext operations never see it), only the doubling loop's own ciphertext-vs-*plaintext* `-1` step was exposed - fixed by encoding that constant at the ciphertext's own actual (drifted) scale rather than the nominal `default_scale`, sidestepping the exponential-drift concern entirely rather than needing an ever-wider tolerance as `doublings` grows.

   **Still not connected to a real, genuinely-exhausted ciphertext** - attempted directly (not just scoped), this surfaced two further, deeper gaps beyond the domain-widening itself, both now documented precisely in `Evaluator::raise_level_real`'s own doc comment:
   - `EvalMod`'s arithmetic operates in *decoded* (scale-divided) units, while `raise_level_real` leaves the ciphertext's tracked scale untouched - so the wraparound `EvalMod` actually needs to remove is `(q0/Delta)*I`, not `q0*I`; `raise_modulus` should be `q0/Delta`.
   - Item 2's own `(h+2)/2` bound is on each **raw ring coefficient's** own wraparound, but `EvalMod` operates on the **slot-domain** value `CoeffsToSlots::apply_real`'s forward DFT produces - a DFT can amplify a per-coefficient bound by up to a factor of the ring degree `N` (confirmed numerically to get close to that worst case with ordinary, non-adversarial wraparound, not just in principle), so `doublings` needs to cover `N*(h+2)/2`, not `(h+2)/2` directly.
   - Even accounting for both of the above, a real ring-coefficient wraparound's forward DFT is generically **complex**, not real, while `EvalMod::reduce_mod_q_real`/`reduce_mod_q_real_wide` are real-only (a restriction their own doc comments already flagged in the abstract) - confirmed directly and concretely, not just in principle: decoding a real ciphertext right after a genuine raise and `apply_real`, every slot's imaginary part was nonzero and comparable in magnitude to its real part. A real end-to-end attempt (real ciphertext, encrypted at level zero, raised, bootstrapped via `bootstrap_real_wide` with a domain sized for both of the above) ran to completion without error but did not recover the true message - consistent with this complex-wraparound gap, not a domain-sizing shortfall. That attempt was removed rather than landed once it could not be verified correct, per this repository's own "don't claim success without testing" discipline - the domain-sizing and scale-drift fixes above remain, verified independently against engineered inputs; only the final real-raise-to-real-bootstrap chain remains unverified.

6. [Done, partial] Extend `EvalMod` to reduce a genuinely complex slot-domain wraparound, attempting item 5's own concrete remainder. New `EvalMod::reduce_mod_q_real_complex_wide(input, relin_keys, doublings, conjugation_key)` splits `input` into real and imaginary parts homomorphically (`Re(z) = (z+conj(z))/2`, `Im(z) = (z-conj(z))*(-i/2)`, via `conjugate_real` - both genuinely real-valued once extracted), reduces each independently via the existing real-only `reduce_mod_q_real_wide` (real and imaginary wraparound integers are independent, the same reasoning `reduce_mod_q`'s own transparent scaffold already documents), then recombines `reduced_real + i*reduced_imag`. New `Bootstrapper::bootstrap_real_complex_wide` generalizes the pipeline the same way. Costs `1` (extraction) `+ (19+doublings)` (the shared real-only reduction, run twice but in parallel from the same starting level, so it costs its shared rescale count once, not twice - the same reasoning `reduce_mod_q_real_wide`'s own `sin`/`cos` branches already established) `+ 1` (recombination) `= 21+doublings` total. Verified end to end against an **engineered** genuinely complex slot-domain wraparound (`phase12_ckks_bootstrapping.rs`, independent real and imaginary `I` up to `4` each) - passed on the first attempt.

   **Still not connected to a real, genuinely-exhausted ciphertext** - attempted directly again with the complex-aware pipeline, expecting item 5's three flagged gaps (decoded-units scaling, DFT amplification, real-vs-complex) to now all be accounted for. The attempt ran to completion without error, but again did not recover the true message - and inspecting the actual slot-domain values this time (not just the final output) found something more fundamental than a remaining domain-sizing gap: two of four slots decoded to wraparound values that were **not integer multiples of `raise_modulus` at all** (e.g. `-2.828...`, not close to any integer), which no amount of widening `doublings` can fix, since the whole approach assumes the wraparound is `raise_modulus` times a bounded *integer*.

   Root cause, traced by reading `CoeffsToSlots::apply_real`'s own implementation directly rather than continuing to guess at bounds: it does **not** operate on a ciphertext's raw ring coefficients at all - `phantom_circuits::ckks::LinearTransformEvaluator::apply_real`'s diagonal method rotates and combines whatever the ciphertext's own canonical-embedding *slots* already are (the same values `decode_complex_real` would produce), applying a generic size-`n` DFT (`n = slot_count`) to *that* vector - a deliberate scaffold convention (Workstream 6 item 5's own note: "this scaffold's own `CoeffsToSlots`/`SlotsToCoeffs` are a *square* transform over however many slots the input has ... not the textbook's dimension-*reducing* `N`-coefficients-to-`N/2`-slots embedding matrix"), correct and already verified for `CoeffsToSlots::apply_real`/`SlotsToCoeffs::apply_real` composing with *each other*. But `raise_level_real` perturbs the *raw ring polynomial's own coefficients* directly (real RLWE semantics - that is what a modulus-raise actually is), and the true relationship between those raw coefficients and the ciphertext's canonical-embedding slots is CKKS's own encoder-specific `5^j`-power embedding (`phantom_schemes::ckks::encoder`'s own module doc comment), not a generic Fourier basis. Composing a raw-coefficient perturbation through the canonical embedding (an implicit step, via decryption) and *then* through `CoeffsToSlots::apply_real`'s own unrelated generic DFT is not the same operation real CKKS bootstrapping's own CoeffsToSlots performs (which is specifically the *inverse of the encoder's own embedding*, recovering slot values *from* raw coefficients using the *same* `5^j`-power structure the encoder used to go the other way) - so the two pieces built across this workstream (`raise_level_real`, real ring-coefficient semantics; `CoeffsToSlots::apply_real`, generic-DFT-over-already-decoded-slots semantics) do not compose the way a real bootstrap pipeline needs, independent of domain width, decoded-units scaling, or real-vs-complex handling.

   This is a materially different, and more foundational, finding than items 5/6's own earlier (still individually correct) gaps: those were about *how wide a domain* and *what shape of value* `EvalMod` needs to handle, and both are now genuinely solved for the domain/shape `CoeffsToSlots::apply_real` actually produces from an arbitrary starting slot vector. The remaining gap is that `CoeffsToSlots::apply_real` and `raise_level_real` are built on two different, incompatible notions of "coefficient domain" - reconciling them needs either redesigning `CoeffsToSlots`/`SlotsToCoeffs` to perform the *true* ring-coefficient-to-canonical-embedding transform (the encoder's own `5^j`-power structure, not a generic DFT - a substantial rewrite of an existing, independently-verified piece), or a different way of feeding a real raise's own output into the existing pipeline. Neither attempted here; the failing end-to-end test was removed rather than landed once it could not be verified correct, keeping only the independently-verified pieces (`raise_level_real`'s own raw-coefficient-domain correctness; `reduce_mod_q_real_wide`/`reduce_mod_q_real_complex_wide`'s own engineered-slot-domain correctness).

7. [Done, partial] Redesign `CoeffsToSlots::apply_real`/`SlotsToCoeffs::apply_real` around real CKKS bootstrapping's own CoeffToSlot/SlotToCoeff construction, closing item 6's own finding. Consulted the primary source directly rather than continuing to guess (Cheon-Han-Kim-Kim-Song, EUROCRYPT 2018, `eprint.iacr.org/2018/153`, Section 5.1 - "Putting polynomial coefficients in plaintext slots") once the derivation stalled twice in a row: CoeffToSlot does **not** apply the canonical embedding to the raised ciphertext's own decoded value at all - given the ciphertext's current canonical-embedding slot vector `z' = tau(ct)` and `U` the `(N/2) x N` embedding Vandermonde matrix split into its left/right `(N/2) x (N/2)` halves `U_0, U_1`, it computes `z'_k = (1/N)(conj(U_k)^T . z' + U_k^T . conj(z'))` for `k=0,1` - two **new** ciphertexts whose own slots hold the raised ciphertext's `N` raw ring coefficients directly, `N/2` per ciphertext, not any embedding of them. `SlotToCoeff` is the inverse identity `z' = U_0 . z0 + U_1 . z1`, no conjugation needed. Both identities verified numerically (Python) against an independently-computed reference before implementing: recovered a random coefficient vector's own values exactly (`~1e-15`), and the round trip exactly recovered the original slot vector too.

   Implemented via primitives this crate already had - `A_k . z + B_k . conj(z)` is exactly the `z -> A.z + B.conj(z)` general linear transform the same paper's own Section 4.3 describes, computable as two `LinearTransformEvaluator::apply_real` calls (one against the ciphertext, one against its `conjugate_real`) plus an `add_real`, for each of the two outputs - no new low-level machinery needed, only the correct matrices and composition. `CoeffsToSlots::apply_real`'s own signature changed from `Ciphertext -> Ciphertext` to `Ciphertext -> (Ciphertext, Ciphertext)` (and `SlotsToCoeffs::apply_real`'s from one ciphertext to two) to match - a breaking change to both, and to `Bootstrapper::bootstrap_real`/`bootstrap_real_wide`, all updated together; `bootstrap_real_complex_wide` was removed (no longer meaningful - the two ciphertexts `CoeffsToSlots::apply_real` now produces are each real-valued by construction, so `EvalMod::reduce_mod_q_real_wide`, not the complex-input variant, is what `Bootstrapper::bootstrap_real_wide` needs for each half).

   A first Rust translation of the verified Python math still failed a transparent (unencrypted), round-trip-only test with a period-`2` pattern in its output - traced to a genuine translation bug, not a math error: this crate's own reimplementation of the encoder's `5^j`-power embedding exponents (needed locally since `phantom_schemes::ckks::encoder`'s own version is private) used `n` (this function's own parameter) as if it were the *ring degree* the way the encoder's own version does, but every caller here passes the *slot count* (`n = N/2`) instead - understating the exponent group's own modulus (`2N`) by a factor of `4`, and the precomputed root-power table's own length to match, silently wrapping the `5^j` sequence around after only `2` steps instead of `N/2`. Fixed by deriving `ring_degree = 2*n` and `two_ring_degree = 4*n` explicitly from the slot-count parameter, re-verified against the same transparent test before moving to real ciphertexts. Once fixed, the full real (encrypted) `coeffs_to_slots_and_slots_to_coeffs_apply_real_round_trip` test - genuinely exercising rotations, conjugation, and real noise, not just the transparent matrices - passed unchanged from its own pre-redesign form (same tolerance), confirming the redesigned construction is correct against real encryption, not just in principle.

   **Also found, and partially fixed, while attempting a real end-to-end test with this corrected `CoeffsToSlots`**: `EvalMod::reduce_mod_q_real_wide`'s own pre-scale step (dividing the input by `effective_q = raise_modulus * 2^doublings` before evaluating the `sin`/`cos` polynomials) encodes `1/effective_q` as a single plaintext constant - for a `raise_modulus` on the order of a real ciphertext's own headroom modulus divided by `Delta` (`~2^32`, not the `~100`-scale value every previous test in this file used), `1/effective_q` is smaller than `encode_complex_real`'s own precision floor at the current scale (`~1/2^30`), so it silently rounds to zero during encoding rather than erroring, zeroing the entire computation with no error anywhere in the pipeline. Fixed by splitting the pre-scale into **two** `mul_plain_real` + `rescale_next_real` steps, each dividing by `1/sqrt(effective_q)` (individually representable even when the full `1/effective_q` isn't), costing one additional rescale (`20+doublings` total, not `19+doublings`).

   This closed one concrete failure mode (confirmed: the previously-silent all-zero output became a real, nonzero, wrong result instead) but not the whole picture - a full real end-to-end attempt (`raise_level_real` -> the corrected `CoeffsToSlots::apply_real` -> `reduce_mod_q_real_wide` (twice, one per half) -> `SlotsToCoeffs::apply_real`, no engineered wraparound of any kind, `raise_modulus ~ 2^32`) still does not recover the true message - the reduced ciphertexts decode with a large, non-negligible **imaginary** component despite `reduce_mod_q_real_wide` being fed a real-valued input, pointing at a further precision issue somewhere in the same family (a plaintext constant, likely inside the doubling loop or the base polynomial evaluation, not representable at the scale in play for this magnitude of `raise_modulus`) that has not yet been isolated. That attempt was removed rather than landed once it could not be verified correct - the corrected `CoeffsToSlots`/`SlotsToCoeffs` construction and the two-step pre-scale fix both remain, each independently verified (the former against real encryption directly, the latter by the previously-passing smaller-`raise_modulus` tests continuing to pass with one added modulus for the extra rescale).

8. [Done] Close item 7's own remaining gap - a full real end-to-end `raise_level_real` -> `CoeffsToSlots::apply_real` -> `EvalMod::reduce_mod_q_real_wide` (twice) -> `SlotsToCoeffs::apply_real` chain, run through the actual public `Bootstrapper::bootstrap_real_wide`, recovering the true message. The "large spurious imaginary component" item 7 left unisolated, and the "encoding-precision issue... at the magnitude a real `raise_modulus` actually has" this document's own "Current status" line described, turned out to be neither a precision bug nor a further architectural gap - both symptoms traced to this test's own choice of `raise_modulus`, not to `CoeffsToSlots`, `SlotsToCoeffs`, or `EvalMod` themselves (all three already correct, as this crate's own other passing tests already showed).

   Root cause: `Evaluator::raise_level_real`'s own doc comment already stated that `raise_modulus` must be `q0/Delta` (the raised ciphertext's own lowest modulus divided by its tracked scale), not the raw modulus `q0` - but every attempt at a real end-to-end test up to and including item 7's own last one used `q0` directly (`~2^32`, a real ciphertext's own lowest-modulus magnitude), not `q0/Delta` (`~O(1)`, since every parameter set in this crate keeps `q0` close to `2^scale_bits`, matching `Delta`). Feeding the sin/cos approximation's own bounded absolute fit error (`~1e-7`, `SIN_APPROX_BASE_COEFFICIENTS`'s own doc comment) through a `raise_modulus/(2*pi)` scale-back factor of `~2^32` rather than `~1` amplified it into an error tens of units in absolute size - explaining both the "spurious imaginary component" (from feeding a value far outside the sin approximation's valid domain into `reduce_mod_q_real_wide`, whose own doc comment already restricts it to real-valued messages under `|m| < 0.03*raise_modulus`) and why no amount of extra `default_scale_bits` fixed it (encoding precision was never the bottleneck - the polynomial's own fixed, `q`-independent absolute fit error was, and that error gets multiplied by `raise_modulus` on the way back out regardless of how precisely everything upstream is encoded).

   Once `raise_modulus` was corrected to `q0/Delta`, a first attempt (`q0` chosen close to `Delta`, giving `raise_modulus ~ 1`) still failed - a different, shallower issue: `EvalMod`'s own `|m| < 0.03*raise_modulus` message bound left no room for a message of order `1` once `raise_modulus` itself was only `~1`. Fixed by choosing `q0` several bits above `Delta` (not `q0 ~ Delta`) so `raise_modulus = q0/Delta` (`~128` in the passing test) leaves headroom for a non-trivial message - a parameter-sizing choice for the caller to make, not a code change.

   A second, independent correction fell out of the same debugging: `Evaluator::raise_level_real`'s own doc comment (before this item) additionally claimed `EvalMod` needs `doublings` sized to cover `N*(h+2)/2` (a ring-degree-amplified bound) because `CoeffsToSlots::apply_real`'s forward transform was assumed to be a DFT that could amplify a per-coefficient bound by a factor of `N`. That claim predates item 7's own redesign and was never updated after it: the redesigned `CoeffsToSlots::apply_real` puts raw ring coefficients directly into its two output ciphertexts' own slots (no DFT), so there is no ring-degree amplification - confirmed directly (decoding `CoeffsToSlots::apply_real`'s own output right after a genuine raise showed imaginary parts at encryption-noise scale, `~1e-8`, confirming both that the values are genuinely real *and* that the un-amplified `(h+2)/2` bound is what actually governs them). Using the correct, smaller bound also matters for noise, not just correctness: an earlier attempt at this test, still using the stale `N*(h+2)/2` bound, needed enough `doublings` that the *extra* multiplicative noise those unneeded doubling steps introduced measurably increased the recovered message's error rather than improving it - confirming directly that over-provisioning `doublings` past what the wraparound actually needs is itself a cost, not free margin.

   Verified end to end (`phantom-bootstrapping/tests/phase12_ckks_bootstrapping.rs`, `bootstrap_real_wide_recovers_a_message_through_a_genuine_raise_level_real`): a real message encrypted at level zero, raised via a genuine `raise_level_real` call (not an engineered slot-domain wraparound), bootstrapped end to end through the public `Bootstrapper::bootstrap_real_wide`, recovering the true message to within `0.01` (well inside the `0.2` tolerance used) - robust across several independent RNG seeds (and therefore several different secret Hamming weights), not a single lucky draw. Stale doc comments describing the now-closed gaps (`Evaluator::raise_level_real`, `EvalMod::reduce_mod_q_real_wide`, `Bootstrapper::bootstrap_real_wide`) were corrected alongside this item, not left describing a resolved problem as still-open.

Exit criteria:

- A real, encrypted, level-zero CKKS ciphertext's modulus can genuinely be raised (verified against real decryption, not a transparent scaffold). **Met.**
- The wraparound-integer bound `EvalMod` relies on is derived, not assumed. **Met** - and the derivation surfaced that `EvalMod`'s own domain doesn't yet cover a realistic secret (addressed by item 5's own domain-widening) or a genuinely complex value (addressed by item 6's own complex extension), which in turn surfaced the deeper `CoeffsToSlots`/`raise_level_real` domain-mismatch (addressed by item 7's own redesign, verified against real encryption).
- `Bootstrapper::bootstrap_real_wide` runs end to end starting from a genuinely-exhausted real ciphertext (a real `raise_level_real` output, not a test-constructed, engineered wraparound) and recovers the true message. **Met** (item 8) - the caller must pass a correctly-derived `raise_modulus` (`q0/Delta`, `q0` sized several bits above `Delta`) and `eval_mod_doublings` sized off the un-amplified `(h+2)/2` bound; both requirements are now stated accurately in the relevant doc comments and demonstrated by a passing test.

Workstream 11 is now fully done.

### Recommended Sequencing

1. Finish Phase 0 cleanup first: facade crate, CI, security/contributing docs, dependency policy.
2. Mark scaffold boundaries and feature-gate toy/experimental surfaces.
3. Harden `phantom-ring` with property tests and CPU backend benchmarks.
4. Move into production RLWE/RGSW internals.
5. Rebuild BFV/BGV/CKKS behavior on hardened lattice primitives.
6. Revisit circuits, bootstrapping, and multiparty once ciphertext semantics are real.

Completed implementation phases so far: Phase 1 (`phantom-utils`), Phase 2 (`phantom-ring`), Phase 3 (`phantom-lattice::rlwe`), Phase 4 (`phantom-lattice::rgsw`), Phase 5 (`phantom-schemes::bgv`), Phase 6 (`phantom-schemes::bfv`), Phase 7 (`phantom-schemes::ckks`), Phase 8 (`phantom-circuits::common`), Phase 9 (`phantom-circuits::bgv`), Phase 10 (`phantom-circuits::bfv`), Phase 11 (`phantom-circuits::ckks`), Phase 12 (`phantom-bootstrapping`), Phase 13 (`phantom-multiparty::common`), Phase 14 (`phantom-multiparty::mpbgv`), Phase 15 (`phantom-multiparty::mpbfv`), Phase 16 (`phantom-multiparty::mpckks`), Phase 17 (Serialization and compatibility), and Phase 18 (Examples, benches, and release hardening).
