# Architecture

This document describes how Phantom-FHE is put together: the crate hierarchy, why it's shaped that way, and how data flows from raw ring arithmetic up to multiparty protocols. For the mathematics behind each layer, see [`concepts.md`](concepts.md). For "is this real cryptography yet," see [SECURITY.md](../SECURITY.md).

## Design goals

Phantom-FHE follows a few consistent rules across every crate:

- **Strict, acyclic layering.** Each crate depends only on crates below it. Nothing in `phantom-ring` knows about RLWE; nothing in `phantom-lattice` knows about BFV/BGV/CKKS. This keeps the dependency graph easy to reason about and lets each layer be hardened independently (see the workstream breakdown in [`internal/implementation-plan.md`](internal/implementation-plan.md)).
- **Strong domain types over raw primitives.** Ring degree, RNS moduli, scheme parameters, scale, precision, session/participant identifiers — all of these are wrapped in validated types (`Degree`, `Modulus`, `Scale`, `ParticipantId`, ...) rather than passed around as bare `usize`/`u64`/`f64`. Construction validates; once you have the type, it's valid.
- **Builder-based parameter construction.** Every scheme's parameters (`BgvParams`, `BfvParams`, `CkksParams`, `BootstrapParams`, ...) are built through a `Builder` type with a `build()` that validates the whole parameter set at once, in addition to a direct `new()` constructor for the already-validated case.
- **One error enum per crate**, built with `thiserror`, wrapping lower-layer errors via `#[from]`/`#[error(transparent)]`. A `Result<T>` alias is exported from each crate's root so call sites read `phantom_ring::Result<T>`, `phantom_lattice::Result<T>`, etc.
- **Canonical, versioned binary serialization**, hand-rolled per crate rather than via `serde` (see [Serialization](#serialization) below and the full format reference in [`technical-manual.md`](technical-manual.md#serialization-format)).
- **Redacted `Debug` and zero-on-`Drop` for secret material.** `phantom_lattice::rlwe::SecretKey` is the current example: its `Debug` impl prints `<redacted>` and its `Drop` impl zeroes the underlying coefficients.

## Crate dependency graph

```text
phantom-utils   (no crypto-crate dependencies)
     |
     v
phantom-ring    (RNS polynomial arithmetic, NTT, sampling)
     |
     v
phantom-lattice (RLWE + RGSW primitives; scheme-agnostic)
     |
     v
phantom-schemes (BGV, BFV, CKKS)
     |
     v
phantom-circuits (linear transforms, polynomial evaluation, CKKS-specific circuits)
     |
     v
phantom-bootstrapping (CKKS bootstrapping; reserved BGV/BFV modules)
     |
     v
phantom-multiparty (mpbgv, mpbfv, mpckks threshold protocols)

phantom-fhe        -- facade crate, re-exports the stack above
phantom-examples    -- workspace-only, depends on everything
phantom-benches      -- workspace-only, depends on everything
```

`phantom-utils` sits outside the crypto hierarchy: every layer may depend on it, but it must never depend on any of them. Concretely, the workspace's `Cargo.toml` path dependencies are:

| Crate | Depends on |
| --- | --- |
| `phantom-utils` | *(external crates only)* |
| `phantom-ring` | `phantom-utils` |
| `phantom-lattice` | `phantom-ring`, `phantom-utils` |
| `phantom-schemes` | `phantom-lattice`, `phantom-ring`, `phantom-utils` |
| `phantom-circuits` | `phantom-lattice`, `phantom-schemes`, `phantom-utils` (dev: `phantom-ring`) |
| `phantom-bootstrapping` | `phantom-circuits`, `phantom-schemes`, `phantom-utils` (dev: `phantom-ring`) |
| `phantom-multiparty` | `phantom-bootstrapping`, `phantom-lattice`, `phantom-ring`, `phantom-schemes` |
| `phantom-fhe` | all of the above |

## Crate responsibilities

### `phantom-utils`

The only crate with no cryptographic knowledge. It provides:

- `sampling` — thin wrappers over `rand_core::{RngCore, CryptoRng}` for filling byte buffers from a secure RNG (`fill_bytes`, `random_bytes`, and, behind the `std` feature, `random_bytes_from_os` via `rand_core::OsRng`).
- `buffer` — `BufferReader<R>` / `BufferWriter<W>` wrapping `std::io::{Read, Write}` with deterministic little-endian primitive encoding (`u8`/`u16`/`u32`/`u64`, fixed-size arrays, length-prefixed byte vectors).
- `serialization` — `DomainTag` (an 8-byte ASCII tag identifying an encoded type), `Version` (a `u16`), and `SerializationHeader` combining the two, with `write_to`/`read_expected` that rejects wrong-domain or wrong-version payloads.
- `test` (under `test-utils` feature or `cfg(test)`) — `deterministic_rng(seed)` / `zero_seed_rng()` built on `ChaCha20Rng`, used throughout the workspace's tests and examples for reproducibility.

Every other crate's `UtilsError` case wraps `phantom_utils::UtilsError` via `#[from]`.

### `phantom-ring`

The lowest cryptographic layer: polynomial arithmetic over `R_q = Z_q[X] / (X^N + 1)` in RNS (Residue Number System) representation. Its public surface (re-exported at the crate root):

- `Modulus` — a validated odd `u64` modulus; `supports_ntt(n)` checks `(q - 1) % 2n == 0`, the condition for a negacyclic NTT of degree `n`.
- `Degree` — a validated non-zero power-of-two ring degree.
- `Ring` — holds a `Degree` and a `Vec<Modulus>`; owns `add`/`sub`/`neg`/`scalar_mul`/`coeffwise_mul`/`schoolbook_mul` and their `_assign` in-place variants.
- `Poly` — RNS-form polynomial storage: `coeffs: Vec<Vec<u64>>` indexed `[modulus_index][coefficient_index]`.
- `ntt` — `NttBackend` trait (`forward`/`inverse`) with one implementation, `CpuNttBackend`, plus `NttTable` (root-of-unity table per modulus/degree).
- `reduce` — `add_mod`/`sub_mod`/`neg_mod`/`mul_mod`/`pow_mod`/`inv_mod` free functions, plus `BarrettReducer`/`MontgomeryReducer`/`reduce_once` types.
- `rns` — `RnsBasis`, CRT reconstruction (`reconstruct_residue`/`reconstruct_poly`), basis extension (`extend_basis`), and modulus dropping (`drop_last_modulus`).
- `sampling` — `sample_uniform`, `sample_ternary`, `sample_discrete_gaussian`, all generic over `R: RngCore + CryptoRng`.

See [`concepts.md`](concepts.md#ring-arithmetic) for the math and [`technical-manual.md`](technical-manual.md#ring-internals) for exactly how far each of these is from a production implementation (the NTT and reducers in particular).

### `phantom-lattice`

Scheme-agnostic RLWE and RGSW primitives — the crate every scheme is built on. Two modules:

- `rlwe` — `RlweParams`, `Plaintext`, `Ciphertext` (a `Vec<Poly>` of arbitrary degree), `SecretKey`/`PublicKey`, `EvaluationKey`/`RelinearizationKey`/`GaloisKey`, `KeyGenerator`, `Encryptor` (secret-key or public-key variant), `Decryptor`, `Evaluator` (add/sub/neg/add_plain/mul/relinearize/rotate_coefficients), plus `keyswitch::key_switch_identity`, `repacking::repack_identity`, and `AutomorphismKey`.
- `rgsw` — `RgswParams` (gadget base/levels), `RgswKey`, `RgswCiphertext`, `GadgetDecomposition`/`GadgetDecompositionParams` (base-`2^base_log` coefficient decomposition and recomposition), and `external_product`.

`phantom-lattice::serialization` encodes `PublicKey` and `EvaluationKey` under domain tags `RLWEPK01`/`RLWEEK01`.

### `phantom-schemes`

Concrete BGV, BFV, and CKKS APIs, each as its own module (`bgv`, `bfv`, `ckks`) with a parallel shape: `Params`/`ParamsBuilder`, `Context` (the entry point — creates encoders/keygen/encryptor/decryptor/evaluator), `Plaintext`, `Ciphertext`, `Encoder`, `Encryptor`, `Decryptor`, `Evaluator`, `KeyGenerator`.

The one structural wrinkle worth knowing: **`bfv` is built as a thin wrapper around `bgv`**, not an independent implementation. `BfvParams` wraps a `bgv::BgvParams`; `bfv::Encryptor`, `Decryptor`, `Evaluator` all delegate to the corresponding `bgv::*` type; `bfv::BatchEncoder` adds signed (`encode_i64`/`decode_i64`) encoding on top of `bgv::BatchEncoder`'s unsigned path. CKKS is independent of both — see [`concepts.md`](concepts.md#ckks) for why its ciphertext representation (transparent complex slots plus scale/level/precision metadata) looks nothing like BGV/BFV's.

### `phantom-circuits`

Circuit planning and evaluation on top of `phantom-schemes`. `common` is scheme-independent: `LinearTransform<T>`/`DiagonalMatrix<T>`/`BabyStepGiantStepPlan` for the diagonal method, and `PolynomialEvalPlan`/`PowerBasisPlan`/`PatersonStockmeyerPlan` for polynomial evaluation strategy selection. `bgv` and `bfv` each provide a `LinearTransformEvaluator` and `PolynomialEvaluator` over exact coefficient slots. `ckks` provides the same plus CKKS-specific circuits: `DftEvaluator`, `ComparisonEvaluator` (sign/step/max), `InverseEvaluator` (reciprocal), `Mod1Evaluator` (centered fractional part), and `MinimaxEvaluator` (composite polynomial evaluation) — the building blocks CKKS bootstrapping is assembled from.

### `phantom-bootstrapping`

A separate crate because bootstrapping is large, optional, and scheme-specialized. `ckks` is the implemented pipeline: `CoeffsToSlots`/`SlotsToCoeffs` (built on `phantom_circuits::ckks::DftEvaluator`), `EvalMod`, `Packer`/`Unpacker` for sparse packing, `BootstrapKeyGenerator`/`BootstrapKey`, and `Bootstrapper` tying the stages together (plus `SecretKeyBootstrapper` for tests/examples that don't need separate key material). `bgv` and `bfv` are reserved module locations — see [`concepts.md`](concepts.md#bootstrapping) for what's actually implemented behind that pipeline shape today.

### `phantom-multiparty`

Threshold/distributed protocols. `common` is protocol-independent: `ParticipantId`/`ParticipantSet`, `SessionId`/`ProtocolKind`/`SessionState` (with a threshold and a round counter), `Share`/`ShareKind`/`ShareAggregator`, and `Transcript`/`TranscriptMessage` with deterministic encoding and a 256-bit transcript hash. `mpbgv`, `mpbfv`, and `mpckks` each implement the same six protocols over their scheme: `CollectiveKeyGen` (ckg), `RelinearizationKeyGen` (rkg), `GaloisKeyGen` (gkg), `PartialDecryptor`, `ReEncryptor`, and `InteractiveBootstrap`. `mpckks::InteractiveBootstrap` is the one that actually calls into `phantom_bootstrapping::ckks::Bootstrapper`; `mpbgv`/`mpbfv` interactive bootstrap is self-contained within the multiparty crate.

### `phantom-fhe`

The public facade. It re-exports each crate above as a module of the same shorthand name:

```rust
pub use phantom_bootstrapping as bootstrapping;
pub use phantom_circuits as circuits;
pub use phantom_lattice as lattice;
pub use phantom_multiparty as multiparty;
pub use phantom_ring as ring;
pub use phantom_schemes as schemes;
pub use phantom_utils as utils;
```

`utils` is included even though it isn't part of the cryptographic hierarchy, because `phantom_utils::UtilsError` leaks into the public error enums of `phantom-lattice` and `phantom-schemes` (via `#[from]`) — a consumer catching those errors needs the type in scope. The facade carries no logic of its own beyond these re-exports; ownership of every implementation stays in its focused crate. `phantom-examples` and `phantom-benches` deliberately depend on the individual `phantom-*` crates directly rather than the facade (see the README's [Workspace](../README.md#workspace) section for why).

## Data flow example: encrypting and evaluating

To make the layering concrete, here's what happens underneath a BFV `encrypt` → `mul` → `decrypt` call, top to bottom:

1. **`phantom-schemes::bfv`** — `Encryptor::encrypt` delegates to `bgv::Encryptor::encrypt`, which constructs a `phantom_lattice::rlwe::Ciphertext`.
2. **`phantom-lattice::rlwe`** — the ciphertext is a `Vec<Poly>`; `Evaluator::mul` multiplies component-wise via `Ring::schoolbook_mul` and accumulates into a higher-degree ciphertext.
3. **`phantom-ring`** — `schoolbook_mul` runs O(N²) negacyclic polynomial multiplication per RNS component using `reduce::{mul_mod, add_mod, sub_mod}`.
4. Back up through `phantom-lattice` → `phantom-schemes::bgv` → `phantom-schemes::bfv`, each layer wrapping the lower layer's type in its own newtype (`bgv::Ciphertext(rlwe::Ciphertext)`, `bfv::Ciphertext(bgv::Ciphertext)`... — actually `bfv::Ciphertext` wraps `rlwe::Ciphertext` directly, delegating through `bgv::Evaluator`).

The point of walking this: every operation you call on a scheme type ultimately bottoms out in `phantom-ring`'s modular polynomial arithmetic. Nothing above `phantom-ring` implements its own arithmetic from scratch.

## Serialization

Every crate that defines a public wire format (`phantom-lattice`, `phantom-schemes`, `phantom-bootstrapping`) puts it in a `serialization` module with the same shape:

1. A `const VERSION: Version = Version::new(N)` and one `const XXX_DOMAIN: DomainTag = DomainTag::from_array(*b"XXXXXXXX")` per encoded type (exactly 8 ASCII bytes).
2. `encode_xxx(&Type) -> Result<Vec<u8>>` writes the header (`SerializationHeader::write_to`) followed by the type's fields via `BufferWriter`.
3. `decode_xxx(&[u8]) -> Result<Type>` reads and validates the header (`SerializationHeader::read_expected`, which rejects a wrong domain tag or wrong version) before reading fields back via `BufferReader`.

This means a payload for the wrong type, or an old-format payload, fails fast with a typed error instead of silently misparsing. The full domain-tag catalog and byte layout are in [`technical-manual.md`](technical-manual.md#serialization-format).

## Where to go next

- The math behind every layer above: [`concepts.md`](concepts.md)
- Using the library as a consumer: [`user-guide.md`](user-guide.md)
- Contributing code, testing conventions, adding a new scheme: [`developer-guide.md`](developer-guide.md)
- Exact algorithm/format reference and honest "what's real" status: [`technical-manual.md`](technical-manual.md)
