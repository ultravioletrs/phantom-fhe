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
- `phantom-lattice`: scheme-agnostic RLWE and RGSW primitives
- `phantom-schemes`: concrete scheme APIs, starting with BGV

Planned crates:

- `phantom-circuits`
- `phantom-bootstrapping`
- `phantom-multiparty`
- `phantom-fhe` facade crate
- examples and benchmarks crates

## Status

Current position: Phase 9 is implemented as a correctness scaffold. The next planned implementation phase is Phase 10, BFV circuits.

## Roadmap

| Phase | Area | Status |
| --- | --- | --- |
| 0 | Repository foundation | Partial |
| 1 | `phantom-utils` | Done |
| 2 | `phantom-ring` | Done |
| 3 | `phantom-lattice::rlwe` | Done |
| 4 | `phantom-lattice::rgsw` | Done |
| 5 | `phantom-schemes::bgv` | Done |
| 6 | `phantom-schemes::bfv` | Done |
| 7 | `phantom-schemes::ckks` | Done |
| 8 | `phantom-circuits::common` | Done |
| 9 | BGV circuits | Done |
| 10 | BFV circuits | Next |
| 11 | CKKS circuits | Pending |
| 12 | Bootstrapping | Pending |
| 13 | Multiparty common layer | Pending |
| 14 | BGV multiparty | Pending |
| 15 | CKKS multiparty | Pending |
| 16 | Serialization and compatibility | Pending |
| 17 | Examples, benches, release hardening | Pending |

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

- Phase 3: `phantom-lattice::rlwe`
  - RLWE parameters, plaintexts, ciphertexts, secret keys, public keys, and evaluation key markers
  - toy exact secret-key and public-key encryption/decryption for correctness scaffolding
  - evaluator operations for add, sub, neg, add-plain, multiplication shape, placeholder relinearization, and coefficient rotation
  - placeholder key-switching and repacking surfaces
  - redacted `Debug` and zero-on-drop behavior for secret keys

- Phase 4: `phantom-lattice::rgsw`
  - RGSW parameter, key, ciphertext, and gadget decomposition types
  - gadget decomposition/recomposition over RNS polynomials
  - plaintext-backed RGSW ciphertext scaffold for toy semantics
  - toy external product path integrated with RLWE ciphertexts

- Phase 5: `phantom-schemes::bgv`
  - `BgvParams`, `BgvContext`, keygen, encoder, encryptor, decryptor, evaluator, and modulus-switching surfaces
  - exact integer encode/decode modulo the plaintext modulus
  - add, sub, neg, plaintext addition, multiplication, rotation, slot-sum, and modulus-switching correctness tests
  - transparent ciphertext semantics for the BGV scaffold while production encrypted scheme behavior is still being built

- Phase 6: `phantom-schemes::bfv`
  - `BfvParams`, `BfvContext`, keygen, encoder, encryptor, decryptor, and evaluator surfaces
  - distinct BFV public API over the current exact-arithmetic scaffold
  - unsigned and signed integer slot encoding
  - add, sub, neg, plaintext operations, multiplication, rotation, and slot-sum correctness tests

- Phase 7: `phantom-schemes::ckks`
  - `CkksParams`, `CkksContext`, scale, precision, encoder, keygen, encryptor, decryptor, and evaluator surfaces
  - complex and real approximate slot encoding
  - add, sub, neg, plaintext operations, multiplication, rescale, level alignment, rotation, and conjugation
  - conjugate-invariant real-slot validation and scale/level mismatch tests

The current ring, RLWE, RGSW, BGV, BFV, and CKKS implementations prioritize correct APIs and testable behavior over production cryptographic hardness or performance. Fast NTT, production RNS basis extension, cryptographic-quality Gaussian sampling, real noise management, key switching, relinearization, encrypted RGSW rows, production BGV/BFV ciphertext semantics, and production CKKS encoding/noise analysis are future hardening work.

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
