# Phantom-FHE

`phantom-fhe` is a Rust-native fully homomorphic encryption library for modern RLWE-based cryptography.

The project is being built as an original Rust implementation. Public papers and mature open-source FHE libraries may be used for understanding algorithms, terminology, parameters, and validation behavior, but project source code, tests, examples, documentation, and serialization formats should be authored for this repository.

## Scope

Planned cryptographic stack:

- RNS polynomial ring arithmetic
- RLWE and RGSW core primitives
- BFV, BGV, and CKKS schemes
- Homomorphic circuits
- Scheme bootstrapping, with CKKS first
- Multiparty / threshold protocols
- Examples and benchmarks

## Workspace

Current crates:

- `phantom-utils`: minimal cross-cutting support utilities
- `phantom-ring`: RNS polynomial ring arithmetic
- `phantom-core`: scheme-agnostic RLWE scaffolding

Planned crates:

- `phantom-schemes`
- `phantom-circuits`
- `phantom-bootstrapping`
- `phantom-multiparty`
- `phantom-fhe` facade crate
- examples and benchmarks crates

## Status

Current position: Phase 4 is implemented as a correctness scaffold. The next planned implementation phase is Phase 5, `phantom-schemes::bgv`.

## Roadmap

| Phase | Area | Status |
| --- | --- | --- |
| 0 | Repository foundation | Partial |
| 1 | `phantom-utils` | Done |
| 2 | `phantom-ring` | Done |
| 3 | `phantom-core::rlwe` | Done |
| 4 | `phantom-core::rgsw` | Done |
| 5 | `phantom-schemes::bgv` | Next |
| 6 | `phantom-schemes::bfv` | Pending |
| 7 | `phantom-schemes::ckks` | Pending |
| 8 | `phantom-circuits::common` | Pending |
| 9 | BGV circuits | Pending |
| 10 | CKKS circuits | Pending |
| 11 | Bootstrapping | Pending |
| 12 | Multiparty common layer | Pending |
| 13 | BGV multiparty | Pending |
| 14 | CKKS multiparty | Pending |
| 15 | Serialization and compatibility | Pending |
| 16 | Examples, benches, release hardening | Pending |

Status labels:

- `Partial`: started, but not all phase deliverables are complete
- `Done`: implemented at the current scaffold/correctness level
- `Next`: next planned implementation target
- `Pending`: not started

## Implemented Details

Implemented:

- Phase 1: `phantom-utils`
  - secure byte sampling helpers
  - deterministic test RNG helpers
  - binary buffer reader/writer helpers
  - serialization domain/version helpers

- Phase 2: `phantom-ring`
  - strong domain types
  - modular arithmetic
  - RNS polynomial storage
  - baseline RNS helpers
  - correctness-first negacyclic NTT backend
  - uniform, ternary, and placeholder Gaussian-like samplers

- Phase 3: `phantom-core::rlwe`
  - RLWE parameters, plaintexts, ciphertexts, secret keys, public keys, and evaluation key markers
  - toy exact secret-key and public-key encryption/decryption for correctness scaffolding
  - evaluator operations for add, sub, neg, add-plain, multiplication shape, placeholder relinearization, and coefficient rotation
  - placeholder key-switching and repacking surfaces
  - redacted `Debug` and zero-on-drop behavior for secret keys

- Phase 4: `phantom-core::rgsw`
  - RGSW parameter, key, ciphertext, and gadget decomposition types
  - gadget decomposition/recomposition over RNS polynomials
  - plaintext-backed RGSW ciphertext scaffold for toy semantics
  - toy external product path integrated with RLWE ciphertexts

The current ring, RLWE, and RGSW implementations prioritize correct APIs and testable behavior over production cryptographic hardness or performance. Fast NTT, production RNS basis extension, cryptographic-quality Gaussian sampling, real noise management, key switching, relinearization, and encrypted RGSW rows are future hardening work.

## Development

Run the workspace tests:

```bash
cargo test --workspace
```

Run formatting and lint checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Authorship

This repository should contain original Rust source authored for Phantom-FHE. Do not copy or mechanically translate third-party implementation code, comments, tests, examples, serialization formats, or internal layouts into this repository.
