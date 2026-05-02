# Phantom-FHE
## Product Requirements Document (PRD)
**Rust-native, Best-of-Breed Full-Stack Fully Homomorphic Encryption Library**

---

# 1. Product Overview

**phantom-fhe** is a **Rust-native, production-grade Fully Homomorphic Encryption (FHE) library** designed to be a best-of-breed Rust architecture for modern encrypted computation.

The library implements:

- RLWE-based cryptography
- BFV, BGV, and CKKS schemes
- Advanced homomorphic circuits
- Multiparty (threshold/distributed) protocols
- Bootstrapping (CKKS first-class)
- Extensible backend architecture (CPU first, GPU/FPGA-ready)

The design is informed by public cryptographic literature and mature open-source FHE libraries, while this repository defines its own Rust-native architecture and APIs.

It is designed to become:

> The **reference Rust implementation** of modern RLWE-based FHE for encrypted analytics, privacy-preserving machine learning, and secure multi-party computation.

Primary downstream use cases include encrypted analytics, privacy-preserving ML, secure collaboration, and data clean room infrastructure.

---

# 2. Vision

> Enable developers to compute on encrypted data securely, efficiently, and at scale using a complete, modular, and high-performance Rust-native FHE stack.

---

# 3. Product Scope

## 3.1 In Scope (Full Library)

### Cryptographic Layers
- Ring arithmetic (RNS, NTT, sampling)
- RLWE core primitives
- RGSW primitives and external products
- BFV scheme (exact arithmetic)
- BGV scheme (exact arithmetic)
- CKKS scheme (approximate arithmetic)

### Advanced Features
- Bootstrapping, with CKKS first and room for BGV/BFV bootstrapping where appropriate
- Homomorphic circuits (linear transforms, polynomial evaluation, DFT, comparison, inverse, mod1)
- Multiparty protocols (BFV, BGV, CKKS)
- Interactive bootstrapping

### System Features
- Canonical serialization
- Parameter presets
- Backend abstraction (CPU-first, GPU/FPGA-ready)
- Examples, benches, and conformance tests
- Original Rust implementation authored for this repository

---

## 3.2 Out of Scope (Initial Releases)

- TFHE (boolean gate FHE)
- ZKP integration (handled in separate repository)
- GPU/FPGA implementations (planned but not blocking)
- Formal verification as a release blocker
- Production GPU/FPGA kernels in the first stable releases

---

# 4. Target Users

- Cryptography engineers
- Distributed systems engineers
- Privacy-preserving ML teams
- Data clean room platform builders
- Research institutions
- Secure data platform builders

---

# 5. Functional Requirements

## 5.1 Algebra Layer (`phantom-ring`)
- Polynomial arithmetic in R_q = Z_q[X] / (X^N + 1)
- RNS: basis decomposition, extension, CRT reconstruction
- Modular arithmetic: Montgomery, Barrett
- NTT: forward, inverse, lazy reduction
- Sampling: uniform, Gaussian, ternary, secure byte sampling hooks

## 5.2 RLWE Lattice Layer (`phantom-lattice::rlwe`)
- Plaintext / Ciphertext structures
- Keys: secret, public, evaluation
- Operations: encrypt, decrypt, add, multiply foundations, relinearize, key switch, automorphisms, rotate, repack

## 5.3 RGSW (`phantom-lattice::rgsw`)
- RGSW ciphertexts
- External product
- Used for bootstrapping and advanced circuits

## 5.4 Schemes (`phantom-schemes`)
### BFV
- Exact integer arithmetic
- SIMD batching

### BGV
- Full-RNS implementation
- Efficient modulus switching

### CKKS
- Approximate arithmetic
- Rescaling and precision tracking

## 5.5 Circuits (`phantom-circuits`)
- Common linear transformation and polynomial evaluation machinery
- BGV linear transformations and polynomial evaluation
- CKKS: minimax, comparison, inverse, mod1, DFT

## 5.6 Bootstrapping (`phantom-bootstrapping`)
- Separate Rust crate for scheme bootstrapping
- CKKS centralized bootstrapping first, with slot/coefficient transforms, precision control, sparse packing/unpacking, smaller-ring packing/unpacking, and batch bootstrapping
- Future centralized BGV/BFV bootstrapping modules where useful and sound
- BGV/BFV must not reuse the CKKS bootstrapping circuit directly; exact-arithmetic schemes need scheme-appropriate designs
- BGV and CKKS interactive refresh/bootstrapping live under `phantom-multiparty`

## 5.7 Multiparty (`phantom-multiparty`)
- CKG, RKG, GKG
- Secret sharing
- Partial decryption
- Interactive bootstrapping

## 5.8 Serialization
- Canonical, deterministic, versioned binary format implemented across the owning crates
- Optional `serde` support behind a feature flag

## 5.9 Support Utilities (`phantom-utils`)
- Minimal cross-cutting support crate
- Secure byte sampling, deterministic test RNG helpers, binary buffer helpers, and serialization domain/version helpers
- Domain-specific utilities stay with their owning crates: ring factorization in `phantom-ring`, polynomial approximation in `phantom-circuits`/`phantom-bootstrapping`, and scheme-specific matrices/packing structures in their scheme or circuit crate

---

# 6. Architecture

## Dependency Hierarchy
The library must preserve a strict acyclic hierarchy:

```text
phantom-ring
  |
  v
phantom-lattice
  |-- rlwe
  `-- rgsw
  |
  v
phantom-schemes
  |-- bfv
  |-- bgv
  `-- ckks
  |
  v
phantom-circuits
  |-- common
  |-- bgv
  `-- ckks
  |
  v
phantom-bootstrapping
  |-- ckks
  |-- bgv (planned)
  `-- bfv (planned or via bgv)
  |
  v
phantom-multiparty
  |-- mpbgv
  `-- mpckks

phantom-utils is a sidecar support crate used by the layers above.
```

`phantom-utils` may be used by all layers, but it must not depend on cryptographic layers.

## Workspace
phantom-fhe/
  crates/
    phantom-fhe
    phantom-ring
    phantom-lattice
    phantom-schemes
    phantom-circuits
    phantom-bootstrapping
    phantom-multiparty
    phantom-utils
    phantom-examples
    phantom-benches

---

# 7. API Principles

- Rust-native
- Trait-driven
- Zero-cost abstractions
- Composable
- Strong domain types for parameters
- Builder-based parameter construction
- In-place hot-path APIs plus ergonomic out-of-place wrappers
- Clear separation between stable and experimental APIs

---

# 8. Performance

- SIMD-friendly
- Multithreading
- Optimized NTT
- Minimal allocations
- Benchmark-driven optimization
- Backend traits that allow CPU, SIMD, GPU, and FPGA implementations without changing public scheme APIs

---

# 9. Security

- >=128-bit security
- Constant-time operations
- CSPRNG
- Parameter validation
- Secret material zeroization
- Redacted debugging for secret-bearing types
- Original authorship discipline; avoid third-party source inclusion in project files

---

# 10. Testing

- Algebra invariants
- Encrypt/decrypt cycles
- Property testing
- Cross-validation
- Scheme-level conformance tests
- Example execution tests
- Criterion benchmarks for hot paths

---

# 11. Roadmap

The detailed coding sequence is defined in `implementation-plan.md`.

1. Repository foundation and original implementation policy
2. Ring arithmetic, RNS, NTT, and samplers
3. RLWE core and RGSW foundations
4. BGV and BFV exact arithmetic
5. CKKS approximate arithmetic
6. Circuits
7. Bootstrapping crate, with CKKS production support first and BGV/BFV extension points
8. Multiparty protocols
9. Examples, benchmarks, optimization, and release hardening

---

# 12. Risks

- NTT complexity
- CKKS precision
- Bootstrapping difficulty
- Accidental inclusion of third-party source material
- Unsafe parameter sets or accidental toy-parameter use
- Public API instability during early architecture work

---

# 13. Success Criteria

- Feature parity with leading FHE libs
- Competitive performance
- Adoption by developers
- Clear Rustdoc and examples for every stable public API
- Passing correctness, property, conformance, and benchmark suites
- Stable crate boundaries that support long-term maintenance

---

# 14. Positioning

phantom-fhe is a **full-stack Rust-native FHE library**, not a wrapper or prototype.

---

# 15. Final Statement

phantom-fhe is foundational infrastructure for privacy-preserving systems and encrypted computation platforms.
