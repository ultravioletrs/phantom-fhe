# phantom-fhe
## Rust-native Full-Stack FHE Library - Technical Specification

**Repository:** `phantom-fhe`  
**Language:** Rust  
**Architecture style:** Rust-first strict hierarchy for modern RLWE-based FHE  
**Scope:** Full FHE library only - no Phantom Core, no SaaS platform, no DataFusion engine, no ZKP logic

---

# 1. Overview

`phantom-fhe` is a Rust-native full-stack homomorphic encryption library. The architecture should choose the best Rust crate boundaries, feature gates, ownership model, and public APIs for a modern FHE stack.

The target is broad feature parity with leading FHE libraries: ring arithmetic, RLWE, RGSW, BFV, BGV, CKKS, circuits, bootstrapping, multiparty protocols, utilities, examples, tests, and benchmarks. Parity means equivalent or better user-facing cryptographic capabilities and architecture quality, implemented in idiomatic Rust.

The library provides a complete cryptographic stack:

- Low-level ring arithmetic over polynomial rings in RNS representation
- RLWE core primitives
- RGSW primitives
- BFV, BGV, and CKKS schemes
- Homomorphic circuits
- Bootstrapping, with CKKS first and room for BGV/BFV bootstrapping where appropriate
- Multiparty / threshold protocols
- Utilities, examples, tests, and benchmarks

The project is not a wrapper around existing C++, Go, or Python libraries. Compatible open-source projects and public papers may be used as references for algorithms, terminology, and validation, but the implementation should be written from scratch in Rust.

Influences include mature open-source FHE libraries and public cryptographic literature. These references inform scope and design choices; this specification defines Phantom-FHE's own Rust architecture.

---

# 2. Non-Goals

`phantom-fhe` must not include:

- Phantom Core analytics engine
- SQL or DataFusion execution logic
- SaaS / multi-user platform logic
- API server logic
- IAM / RBAC / billing / audit workflows
- ZKP implementation
- Application-specific business logic

The library must remain a focused cryptographic and mathematical FHE library.

---

# 3. Core Architectural Principle

The library follows a strict hierarchy:

```text
ring
  |
  v
core
  |-- rlwe
  `-- rgsw
  |
  v
schemes
  |-- bfv
  |-- bgv
  `-- ckks
  |
  v
circuits
  |-- common
  |-- bgv
  `-- ckks
  |
  v
bootstrapping
  |-- ckks
  |-- bgv (planned)
  `-- bfv (planned or via bgv)
  |
  v
multiparty
  |-- mpbgv
  `-- mpckks
```

Each layer may depend only on lower layers. No circular dependencies are allowed.

---

# 4. Rust Workspace Layout

The implementation should be a Cargo workspace.

```text
phantom-fhe/
  Cargo.toml
  README.md
  LICENSE
  SECURITY.md
  CONTRIBUTING.md

  crates/
    phantom-fhe/
    phantom-ring/
    phantom-lattice/
    phantom-schemes/
    phantom-circuits/
    phantom-bootstrapping/
    phantom-multiparty/
    phantom-utils/
    phantom-examples/
    phantom-benches/
```

Recommended crate roles:

```text
phantom-fhe             Public facade crate that re-exports stable modules
phantom-ring            Low-level RNS polynomial arithmetic, NTT, sampling
phantom-lattice         RLWE and RGSW primitives
phantom-schemes         BFV, BGV, CKKS implementations
phantom-circuits        Homomorphic circuits for BGV, BFV, and CKKS
phantom-bootstrapping   Scheme bootstrapping crate: CKKS first, BGV/BFV-capable architecture
phantom-multiparty      Distributed / threshold protocols
phantom-utils           Minimal cross-cutting support crate
phantom-examples        Executable examples
phantom-benches         Criterion benchmarks
```

This keeps a clear mathematical dependency hierarchy while allowing Rust-specific improvements. The facade crate should be thin: it exposes stable public APIs and feature flags, while implementation ownership remains in the focused crates.

Workspace dependency rules:

```text
phantom-utils -> no crypto crate dependencies
phantom-ring -> phantom-utils
phantom-lattice -> phantom-ring, phantom-utils
phantom-schemes -> phantom-lattice, phantom-ring, phantom-utils
phantom-circuits -> phantom-schemes, phantom-lattice, phantom-ring, phantom-utils
phantom-bootstrapping -> phantom-circuits, phantom-schemes, phantom-lattice, phantom-ring, phantom-utils
phantom-multiparty -> phantom-bootstrapping, phantom-circuits, phantom-schemes, phantom-lattice, phantom-ring, phantom-utils
phantom-fhe -> public re-exports only
```

Rust adaptation note: Phantom-FHE intentionally uses a separate `phantom-bootstrapping` crate because bootstrapping is large, optional, scheme-specialized, and dependency-heavy. CKKS is the first supported centralized bootstrapper; the crate must remain open to future BGV/BFV centralized bootstrapping implementations if they are useful and sound. The canonical public path is:

```rust
phantom_fhe::bootstrapping::ckks
```

---

# 5. Original Authorship Policy

`phantom-fhe` should be authored from scratch in Rust so the repository's source files, comments, tests, examples, and documentation can be distributed under this project's own copyright.

Allowed:

- study existing FHE libraries, public algorithms, implementation strategies, parameters, and tests for understanding
- use public academic papers, specifications, standards, and mathematical descriptions
- perform behavioral comparison with existing libraries for validation

Required:

- write original Rust code, comments, tests, examples, documentation, and serialization formats
- keep implementation notes in our own words
- avoid incorporating third-party source material that would require carrying external copyright notices

Not allowed:

- copy or mechanically translate implementation code from another FHE library
- copy comments, tests, examples, serialization formats, or internal layouts from another FHE library
- incorporate third-party code into this repository without an explicit project-level decision
- import source material that would force external copyright notices into normal project files
- imply that third-party implementation work is original to `phantom-fhe`

---

# 6. Crate: `phantom-ring`

## 6.1 Purpose

`phantom-ring` is the lowest-level cryptographic crate. It provides modular arithmetic operations for polynomials in the RNS basis.

## 6.2 Mathematical Ring

The primary polynomial ring is:

```text
R_q = Z_q[X] / (X^N + 1)
```

where:

- `N` is a power of two
- `q` is represented as an RNS basis of machine-word moduli
- coefficients are stored per modulus

## 6.3 Modules

```text
phantom-ring/
  src/
    lib.rs
    error.rs
    modulus.rs
    poly.rs
    ring.rs

    reduce/
      mod.rs
      barrett.rs
      montgomery.rs
      lazy.rs

    ntt/
      mod.rs
      table.rs
      cpu.rs
      backend.rs

    rns/
      mod.rs
      basis.rs
      crt.rs
      extension.rs
      rescale.rs

    sampling/
      mod.rs
      uniform.rs
      gaussian.rs
      ternary.rs
```

## 6.4 Core Types

```rust
pub struct Modulus {
    value: u64,
}

pub struct Ring {
    degree: usize,
    moduli: Vec<Modulus>,
}

pub struct Poly {
    degree: usize,
    coeffs: Vec<Vec<u64>>,
}
```

`Poly` stores coefficients in RNS form:

```text
coeffs[modulus_index][coefficient_index]
```

## 6.5 Required Features

### Modular Arithmetic

- addition modulo q_i
- subtraction modulo q_i
- negation modulo q_i
- multiplication modulo q_i
- Barrett reduction
- Montgomery reduction
- lazy reduction support

### Polynomial Arithmetic

- add
- subtract
- negate
- scalar multiplication
- coefficient-wise multiplication
- zero polynomial
- copy / clone
- in-place operations
- out-of-place convenience wrappers

### RNS

- RNS basis representation
- basis extension
- basis decomposition
- CRT reconstruction for testing/debugging
- rescaling
- modulus dropping

### NTT

- forward NTT
- inverse NTT
- in-place NTT
- out-of-place NTT
- NTT table generation
- NTT-compatible modulus validation

### Sampling

- uniform polynomial sampling
- discrete Gaussian sampling
- ternary sampling
- secure byte sampling integration

## 6.6 Backend Abstraction

Define an idiomatic Rust trait:

```rust
pub trait NttBackend {
    fn forward(&self, ring: &Ring, poly: &mut Poly) -> Result<(), RingError>;
    fn inverse(&self, ring: &Ring, poly: &mut Poly) -> Result<(), RingError>;
}
```

Initial backend:

```text
CpuNttBackend
```

Future backends:

```text
SimdNttBackend
GpuNttBackend
FpgaNttBackend
```

## 6.7 Acceptance Tests

- NTT followed by inverse NTT returns original polynomial
- NTT multiplication matches schoolbook multiplication for small rings
- RNS CRT reconstruction is correct
- basis extension preserves values
- rescaling behaves correctly
- samplers produce valid polynomial dimensions and coefficient ranges

---

# 7. Crate: `phantom-lattice`

## 7.1 Purpose

`phantom-lattice` implements the common cryptographic functionality for RLWE-based homomorphic encryption and RGSW.

This crate must remain scheme-agnostic. It must not depend on BFV, BGV, or CKKS.

## 7.2 Internal Structure

```text
phantom-lattice/
  src/
    lib.rs
    error.rs

    rlwe/
      mod.rs
      params.rs
      plaintext.rs
      ciphertext.rs
      secret_key.rs
      public_key.rs
      evaluation_key.rs
      keygen.rs
      encryptor.rs
      decryptor.rs
      evaluator.rs
      keyswitch.rs
      relinearization.rs
      automorphism.rs
      repacking.rs

    rgsw/
      mod.rs
      params.rs
      ciphertext.rs
      key.rs
      decomposition.rs
      external_product.rs
```

---

## 7.3 RLWE

### Purpose

The `rlwe` module provides generic RLWE-based cryptographic primitives.

### Required Types

```rust
pub struct RlweParams;
pub struct Plaintext;
pub struct Ciphertext;
pub struct SecretKey;
pub struct PublicKey;
pub struct EvaluationKey;
pub struct RelinearizationKey;
pub struct GaloisKey;
```

### Required Features

- parameter validation
- plaintext representation
- ciphertext representation
- secret key generation
- public key generation
- encryption
- decryption
- key switching
- relinearization
- automorphisms
- rotations
- RLWE repacking

### RLWE Design Rule

RLWE must define all scheme-independent structs and operations.

BFV/BGV/CKKS should wrap or specialize RLWE, not duplicate it.

---

## 7.4 RGSW

### Purpose

The `rgsw` module implements Full-RNS Ring-GSW ciphertexts and external product.

### Required Features

- RGSW ciphertext representation
- gadget decomposition
- external product
- integration with RLWE ciphertexts
- preparation for bootstrapping

### Required Types

```rust
pub struct RgswCiphertext;
pub struct RgswKey;
pub struct GadgetDecomposition;
```

---

## 7.5 Acceptance Tests

- RLWE encrypt/decrypt works for toy parameters
- RLWE addition preserves plaintext semantics
- RLWE multiplication skeleton is compatible with evaluator
- key switching preserves decryptability
- relinearization preserves decryptability
- automorphism/rotation works for small test cases
- RGSW external product passes small-ring correctness tests

---

# 8. Crate: `phantom-schemes`

## 8.1 Purpose

`phantom-schemes` contains the concrete RLWE-based homomorphic encryption schemes:

- BFV
- BGV
- CKKS

## 8.2 Structure

```text
phantom-schemes/
  src/
    lib.rs
    error.rs

    bfv/
      mod.rs
      params.rs
      encoder.rs
      plaintext.rs
      ciphertext.rs
      keygen.rs
      encryptor.rs
      decryptor.rs
      evaluator.rs

    bgv/
      mod.rs
      params.rs
      encoder.rs
      plaintext.rs
      ciphertext.rs
      keygen.rs
      encryptor.rs
      decryptor.rs
      evaluator.rs
      modulus_switch.rs

    ckks/
      mod.rs
      params.rs
      scale.rs
      precision.rs
      encoder.rs
      plaintext.rs
      ciphertext.rs
      keygen.rs
      encryptor.rs
      decryptor.rs
      evaluator.rs
      rescale.rs
      conjugate_invariant.rs
```

---

## 8.3 BFV

### Purpose

BFV provides exact modular arithmetic over integers.

### Features

- Full-RNS BFV variant
- exact arithmetic modulo plaintext modulus `t`
- batching / SIMD packing
- scale-invariant operations
- encryption / decryption
- homomorphic addition
- homomorphic multiplication
- plaintext-ciphertext operations
- relinearization
- rotations
- slot summation

### API Sketch

```rust
let params = BfvParams::builder()
    .degree(8192)
    .plaintext_modulus(65537)
    .security_128()
    .build()?;

let ctx = BfvContext::new(params)?;
let keys = ctx.keygen().generate()?;

let pt = ctx.encoder().encode_u64(&[1, 2, 3, 4])?;
let ct = ctx.encryptor(&keys.public).encrypt(&pt)?;

let out = ctx.decryptor(&keys.secret).decrypt(&ct)?;
let values = ctx.encoder().decode_u64(&out)?;
```

---

## 8.4 BGV

### Purpose

BGV provides exact modular arithmetic over integers using a Full-RNS generalized design.

### Features

- Full-RNS BGV
- plaintext modulus handling
- modulus switching
- exact integer arithmetic
- batching / SIMD packing
- encryption / decryption
- add / multiply
- plaintext operations
- relinearization
- rotations

### Design Note

BFV may reuse BGV internals where mathematically appropriate, but this must be designed clearly in Rust and not hard-coded as a hack.

---

## 8.5 CKKS

### Purpose

CKKS provides approximate fixed-point arithmetic over complex numbers and real numbers in the conjugate-invariant variant.

### Features

- complex vector encoding
- real vector encoding
- scale management
- rescaling
- precision tracking
- conjugation
- rotations
- encryption / decryption
- add / multiply
- plaintext operations

### API Sketch

```rust
let params = CkksParams::builder()
    .degree(16384)
    .default_scale_bits(40)
    .security_128()
    .build()?;

let ctx = CkksContext::new(params)?;
let keys = ctx.keygen().generate()?;

let pt = ctx.encoder().encode_real(&[1.0, 2.0, 3.5])?;
let ct = ctx.encryptor(&keys.public).encrypt(&pt)?;

let squared = ctx.evaluator().mul(&ct, &ct)?;
let squared = ctx.evaluator().rescale_next(&squared)?;

let out = ctx.decryptor(&keys.secret).decrypt(&squared)?;
let values = ctx.encoder().decode_real(&out)?;
```

---

## 8.6 Acceptance Tests

### BFV

- exact encode/decode
- exact encrypt/decrypt
- exact addition
- exact multiplication
- rotation correctness
- slot-sum correctness

### BGV

- exact encode/decode
- exact encrypt/decrypt
- modulus switching correctness
- multiplication after modulus switching
- rotation correctness

### CKKS

- encode/decode within tolerance
- add within tolerance
- multiply/rescale within tolerance
- rotation within tolerance
- conjugation correctness
- precision tracking sanity

---

# 9. Crate: `phantom-circuits`

## 9.1 Purpose

`phantom-circuits` implements reusable homomorphic circuits for BGV, BFV, and CKKS.

## 9.2 Structure

```text
phantom-circuits/
  src/
    lib.rs
    error.rs

    common/
      mod.rs
      lintrans.rs
      polynomial.rs

    bgv/
      mod.rs
      lintrans.rs
      polynomial.rs

    bfv/
      mod.rs
      lintrans.rs
      polynomial.rs

    ckks/
      mod.rs
      lintrans.rs
      polynomial.rs
      minimax.rs
      comparison.rs
      inverse.rs
      mod1.rs
      dft.rs
```

---

## 9.3 Common Circuits

### Linear Transformations

- arbitrary linear transformations
- diagonal representation
- slot permutations
- baby-step giant-step optimization where appropriate

### Polynomial Evaluation

- generic polynomial evaluator
- power basis strategy
- Paterson-Stockmeyer strategy where appropriate

---

## 9.4 BGV Circuits

Required modules:

```text
bgv/lintrans
bgv/polynomial
```

Features:

- linear transformations over packed BGV slots
- polynomial evaluation over exact modular integer plaintext space

---

## 9.5 BFV Circuits

Required modules:

```text
bfv/lintrans
bfv/polynomial
```

Features:

- linear transformations over packed BFV slots
- polynomial evaluation over exact modular integer plaintext space
- signed and unsigned BFV encoding semantics through circuit evaluation

---

## 9.6 CKKS Circuits

Required modules:

```text
ckks/lintrans
ckks/polynomial
ckks/minimax
ckks/comparison
ckks/inverse
ckks/mod1
ckks/dft
ckks/bootstrapping
```

Features:

- linear transformations
- polynomial evaluation
- minimax composite polynomial evaluation
- sign approximation
- max approximation
- step approximation
- inverse approximation
- mod1 function
- homomorphic DFT

---

## 9.7 Acceptance Tests

- linear transformation correctness
- slot permutation correctness
- polynomial evaluation correctness
- CKKS inverse approximation tolerance
- CKKS comparison approximation tolerance
- DFT round-trip tolerance

---

# 10. Crate: `phantom-bootstrapping`

## 10.1 Purpose

`phantom-bootstrapping` is the scheme bootstrapping crate.

The first implementation target is centralized CKKS bootstrapping for fixed-point approximate ciphertexts over real/complex slots. This belongs in a separate Rust crate for build-time, feature-gating, and dependency-boundary reasons because it composes CKKS DFT, Mod1, polynomial circuits, CKKS scheme parameters/evaluators, RLWE types, ring arithmetic, and utility code.

Phantom-FHE should not structurally assume that bootstrapping is CKKS-only forever. BGV and BFV can support bootstrapping in general FHE literature and may receive centralized bootstrapping modules later. BGV/BFV must not reuse the CKKS bootstrapping circuit directly; they need scheme-appropriate bootstrapping designs. BGV interactive refresh/bootstrapping belongs in `phantom-multiparty::mpbgv`; CKKS multiparty refresh/interactive bootstrapping belongs in `phantom-multiparty::mpckks` and may depend on CKKS bootstrapping interfaces.

## 10.2 Structure

```text
phantom-bootstrapping/
  src/
    lib.rs
    error.rs

    ckks/
      mod.rs
      params.rs
      params_literal.rs
      default_params.rs
      keys.rs
      bootstrapper.rs
      evaluator.rs
      secret_key_bootstrapper.rs
      coeffs_to_slots.rs
      slots_to_coeffs.rs
      eval_mod.rs
      pack.rs
      unpack.rs
      precision.rs

    bgv/
      mod.rs
      params.rs
      evaluator.rs
      keys.rs

    bfv/
      mod.rs
      params.rs
      evaluator.rs
      keys.rs
```

The `bgv` and `bfv` modules are architectural placeholders until centralized exact-arithmetic bootstrapping is implemented. They should be gated behind `experimental` until mature.

## 10.3 Required Features

### CKKS

- CKKS bootstrapping
- coefficient-to-slot transform
- slot-to-coefficient transform
- eval-mod circuit
- batch bootstrapping
- automatic packing/unpacking of sparse ciphertexts and smaller-ring ciphertexts
- arbitrary precision bootstrapping
- conjugate-invariant ring support
- bootstrapping with different residual and bootstrapping parameter sets
- advanced circuit customization and parameterization

### BGV/BFV

- reserve stable module locations for future exact-arithmetic bootstrapping
- do not expose production APIs until parameters, security, correctness, and tests are mature
- BFV may reuse BGV bootstrapping internals where mathematically appropriate

## 10.4 Acceptance Tests

- bootstrapping refresh preserves message within tolerance
- level/noise/precision improves after bootstrap
- batch bootstrapping correctness
- sparse-packed bootstrapping correctness
- smaller-ring packing/unpacking correctness
- conjugate-invariant bootstrapping correctness
- invalid parameters are rejected
- BGV/BFV placeholder modules do not expose stable APIs unless implemented and tested

---

# 11. Crate: `phantom-multiparty`

## 11.1 Purpose

`phantom-multiparty` provides distributed / threshold protocols.

## 11.2 Structure

```text
phantom-multiparty/
  src/
    lib.rs
    error.rs

    common/
      mod.rs
      participant.rs
      session.rs
      transcript.rs
      shares.rs

    mpbgv/
      mod.rs
      ckg.rs
      rkg.rs
      gkg.rs
      partial_decrypt.rs
      reencryption.rs
      interactive_bootstrap.rs

    mpckks/
      mod.rs
      ckg.rs
      rkg.rs
      gkg.rs
      partial_decrypt.rs
      reencryption.rs
      interactive_bootstrap.rs
```

## 11.3 Required Features

### Common

- participant IDs
- protocol sessions
- transcript objects
- share aggregation
- deterministic transcript hashing
- secret-shared secret key support

### BGV Multiparty

- collective public key generation
- collective relinearization key generation
- collective Galois key generation
- partial decryption
- re-encryption from shares
- interactive bootstrapping

### CKKS Multiparty

- collective public key generation
- collective relinearization key generation
- collective Galois key generation
- partial decryption
- re-encryption from shares
- interactive bootstrapping

## 11.4 Acceptance Tests

- collective public key can encrypt decryptable ciphertexts
- partial decryptions reconstruct correct plaintext
- invalid/missing share is detected
- re-encryption from shares works
- interactive bootstrapping correctness for CKKS
- interactive bootstrapping correctness for BGV where implemented

---

# 12. Crate: `phantom-utils`

## 12.1 Purpose

`phantom-utils` is a minimal cross-cutting support crate for functionality that is genuinely shared across several layers and has no cryptographic-layer dependencies. Rust has strong standard-library and ecosystem primitives, so domain-specific utilities should live with the owning crate instead of accumulating in a broad grab-bag crate.

Ownership rules:

- secure byte sampling and deterministic test RNG helpers belong here
- canonical binary primitive readers/writers belong here
- tiny generic helpers used by several crates may live here
- modulus search and factorization should live in `phantom-ring`
- arbitrary precision polynomial approximation should live in `phantom-circuits` or `phantom-bootstrapping`, unless shared broadly enough to justify extraction
- scheme-specific matrices, vectors, maps, and packing structures should live with the scheme/circuit that owns their semantics
- no crate in `phantom-utils` may depend on `phantom-ring`, `phantom-lattice`, `phantom-schemes`, `phantom-circuits`, `phantom-bootstrapping`, or `phantom-multiparty`

## 12.2 Structure

```text
phantom-utils/
  src/
    lib.rs

    buffer/
      mod.rs
      reader.rs
      writer.rs

    sampling/
      mod.rs
      bytes.rs

    serialization/
      mod.rs
      version.rs
      domain.rs

    test/
      mod.rs
      rng.rs
```

## 12.3 Required Features

- efficient read/write buffers
- secure byte sampling
- deterministic test RNG helpers behind test/dev features
- deterministic binary primitive encoding used by crate-owned serializers
- serialization domain/version helpers
- optional `serde` adapters behind the `serde` feature

## 12.4 Serialization Ownership

Serialization is not a separate cryptographic layer. Each crate owns canonical encoding for its own public types, using shared buffer helpers from `phantom-utils`.

Rules:

- public artifacts may implement stable serialization once their type layout is stable
- secret-bearing artifacts require explicit opt-in APIs and must not serialize accidentally
- every serialized object must include versioning and domain separation
- decoders must reject trailing bytes, malformed lengths, invalid parameters, and unsupported versions

---

# 13. Crate: `phantom-examples`

## 13.1 Purpose

Executable Rust examples demonstrating library usage.

## 13.2 Required Examples

```text
examples/
  bfv_basic.rs
  bfv_batching.rs
  bfv_rotation.rs
  bgv_basic.rs
  bgv_polynomial.rs
  ckks_basic.rs
  ckks_rescale.rs
  ckks_dft.rs
  ckks_inverse.rs
  ckks_bootstrapping.rs
  mpbgv_basic.rs
  mpckks_basic.rs
  mpckks_interactive_bootstrap.rs
```

Examples must run with:

```bash
cargo run -p phantom-examples --example ckks_basic
```

---

# 14. Crate: `phantom-benches`

## 14.1 Purpose

Criterion-based benchmarks.

## 14.2 Required Benchmarks

```text
benches/
  ring_ntt.rs
  ring_rns.rs
  rlwe_encrypt.rs
  rlwe_keyswitch.rs
  bfv_eval.rs
  bgv_eval.rs
  ckks_eval.rs
  ckks_bootstrapping.rs
  multiparty.rs
```

Benchmarks should report:

- parameters
- operation latency
- throughput
- allocations where possible
- CPU information where possible

---

# 15. Idiomatic Rust Design Rules

## 15.1 Strong Types

Use explicit domain types:

```rust
Degree
Level
Scale
Modulus
PlaintextModulus
SecurityLevel
```

Avoid raw `usize`, `u64`, or tuples in public APIs where a semantic type is clearer.

## 15.2 Builders for Parameters

All parameter objects must use builders.

Example:

```rust
let params = CkksParams::builder()
    .degree(Degree::new(16384)?)
    .default_scale_bits(40)
    .security_128()
    .build()?;
```

## 15.3 Context Objects

Each scheme should expose a context object:

```rust
BfvContext
BgvContext
CkksContext
```

Each context provides:

```rust
ctx.params()
ctx.keygen()
ctx.encoder()
ctx.encryptor(...)
ctx.decryptor(...)
ctx.evaluator()
```

## 15.4 Traits for Shared Behavior

Use traits for shared behavior, but avoid overengineering.

Examples:

```rust
pub trait Encoder {
    type Message;
    type Plaintext;

    fn encode(&self, msg: &Self::Message) -> Result<Self::Plaintext, Error>;
    fn decode(&self, pt: &Self::Plaintext) -> Result<Self::Message, Error>;
}
```

```rust
pub trait Evaluator {
    type Ciphertext;
    type Plaintext;

    fn add(&self, lhs: &Self::Ciphertext, rhs: &Self::Ciphertext) -> Result<Self::Ciphertext, Error>;
    fn mul(&self, lhs: &Self::Ciphertext, rhs: &Self::Ciphertext) -> Result<Self::Ciphertext, Error>;
}
```

## 15.5 Ownership and Allocation

- Prefer borrowing over cloning.
- Provide in-place APIs for hot paths.
- Provide out-of-place wrappers for convenience.
- Avoid hidden allocations in core arithmetic loops.
- Use `Cow` only where justified.
- Avoid global mutable state.

## 15.6 Unsafe Code

- Avoid unsafe code initially.
- If unsafe is required for performance, isolate it.
- Every unsafe block must document its safety invariant.
- Unsafe code must have tests and benchmarks.

---

# 16. Security Requirements

## 16.1 Security Level

The library must support at least:

```rust
SecurityLevel::Classical128
```

Future:

```rust
SecurityLevel::Classical192
SecurityLevel::Classical256
```

## 16.2 Secret Material

Secret types must:

- zeroize on drop
- avoid normal `Debug`
- avoid accidental serialization
- avoid logs
- use redacted debug representations

Secret types include:

- secret keys
- secret shares
- masks
- ephemeral encryption randomness

## 16.3 Randomness

Use CSPRNG only.

Allowed:

- `rand_core::CryptoRng`
- `rand_chacha`
- OS randomness wrappers

No non-cryptographic RNG for key generation, encryption, or secret sharing.

## 16.4 Constant-Time Considerations

Constant-time behavior is required for secret-dependent operations where applicable.

Use `subtle` where appropriate.

## 16.5 Parameter Validation

Reject invalid or unsafe parameters by default.

Toy parameters are allowed only in tests/examples and must be clearly marked.

---

# 17. Testing Strategy

## 17.1 Unit Tests

Every module must test local invariants.

## 17.2 Integration Tests

Required integration tests:

```text
tests/
  ring_ntt.rs
  ring_rns.rs
  core_rlwe.rs
  core_rgsw.rs
  bfv_correctness.rs
  bgv_correctness.rs
  ckks_correctness.rs
  circuits_bgv.rs
  circuits_ckks.rs
  ckks_bootstrapping.rs
  multiparty_bgv.rs
  multiparty_ckks.rs
```

## 17.3 Property Tests

Use `proptest` for:

- modular arithmetic
- polynomial arithmetic
- NTT round trips
- encode/decode cycles
- encrypt/decrypt cycles

## 17.4 Cross-Validation

Cross-validation with existing libraries may use black-box behavior, source-level tests, and license-compatible reference implementations.

Allowed:

- run an existing library externally
- compare decrypted outputs
- compare mathematical behavior
- compare against public parameter sets where license review permits
- use independently written tests that check equivalent mathematical behavior

Not allowed:

- copying material from incompatible licenses
- copying test vectors without license review
- copying serialization formats without license review and an explicit compatibility decision

---

# 18. CI Requirements

Use GitHub Actions.

Required jobs:

```text
fmt:
  cargo fmt --check

clippy:
  cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
  cargo test --workspace --all-features

doc:
  cargo doc --workspace --no-deps

audit:
  cargo audit
```

Optional:

```text
bench:
  cargo bench
```

---

# 19. Feature Flags

Recommended feature flags:

```toml
[features]
default = ["std", "parallel"]
std = []
parallel = ["rayon"]
serde = ["dep:serde"]
zeroize = ["dep:zeroize"]
experimental = []
gpu = []
fpga = []
```

Rules:

- default features must compile and run stable APIs
- experimental features must be clearly marked
- GPU/FPGA are placeholders until implemented

---

# 20. Implementation Roadmap

Although the goal is a full library, implementation must follow dependency order.

The detailed coding plan is maintained in `implementation-plan.md`. This section is the compact roadmap; `implementation-plan.md` is authoritative for phase gates, tests, benchmarks, and immediate coding tasks.

## Phase 0 - Repository Foundation

Deliver:

- workspace
- crate skeletons
- CI
- README
- SECURITY
- CONTRIBUTING

## Phase 1 - Ring

Deliver:

- moduli
- polynomial representation
- modular arithmetic
- RNS basis
- NTT/inverse NTT
- samplers

## Phase 2 - Lattice RLWE/RGSW

Deliver:

- RLWE plaintext/ciphertext
- keys
- keygen
- encryption/decryption
- key switching
- relinearization
- automorphisms
- RGSW external product

## Phase 3 - BFV/BGV

Deliver:

- BFV exact arithmetic
- BGV exact arithmetic
- batching
- rotations
- modulus switching

## Phase 4 - CKKS

Deliver:

- CKKS encoder
- approximate arithmetic
- rescale
- precision tracking
- conjugate-invariant variant

## Phase 5 - Circuits

Deliver:

- lintrans
- polynomial evaluation
- minimax
- comparison
- inverse
- mod1
- DFT

## Phase 6 - CKKS Bootstrapping

Deliver:

- bootstrapping params
- bootstrapping keys
- coeffs-to-slots
- slots-to-coeffs
- eval-mod
- batch bootstrapping
- sparse packing/unpacking

## Phase 7 - Multiparty

Deliver:

- mpbgv
- mpckks
- collective keygen
- collective evaluation keys
- partial decryption
- re-encryption
- interactive bootstrapping

## Phase 8 - Examples and Benchmarks

Deliver:

- executable examples
- Criterion benchmarks
- performance documentation

---

# 21. Definition of Done

A feature is done only when:

1. It compiles.
2. Unit tests pass.
3. Integration tests pass.
4. Public APIs have Rustdoc.
5. Errors use `Result`.
6. Secret data is protected.
7. Parameters are validated.
8. No third-party source material is incorporated into project files.
9. Benchmarks exist for performance-sensitive operations.
10. Examples are updated when user-facing APIs change.

---

# 22. Final Statement

`phantom-fhe` is a full-stack, Rust-native FHE library following a strict mathematical dependency hierarchy:

```text
ring -> core/rlwe + core/rgsw -> schemes -> circuits -> bootstrapping -> multiparty
```

The implementation must remain idiomatic, modular, secure, and original.

The goal is not to build a product platform inside this repository.

The goal is to build the Rust-native FHE library that Rust currently lacks.
