# User Guide

Practical, runnable guidance for using Phantom-FHE: adding it as a dependency, working with each scheme, circuits, multiparty protocols, and serialization. For first-run setup, see [`getting-started.md`](getting-started.md). For the math behind the calls here, see [`concepts.md`](concepts.md). For current cryptographic status, see [`technical-manual.md`](technical-manual.md) and [SECURITY.md](../SECURITY.md) — every example in this guide uses small development parameters, deliberately.

## Adding the dependency

Phantom-FHE isn't on crates.io yet; depend on it from git:

```toml
[dependencies]
phantom-fhe = { git = "https://github.com/ultravioletrs/phantom-fhe" }
rand_chacha = "0.3"
rand_core = "0.6"
```

Every code sample below imports from `phantom_fhe::{ring, lattice, schemes, circuits, bootstrapping, multiparty, utils}` — the facade's re-exported modules (see [`architecture.md`](architecture.md#phantom-fhe)). If you're working inside this workspace itself (contributing, not consuming), import from the individual `phantom_ring`/`phantom_lattice`/`phantom_schemes`/... crates directly instead; the types are identical either way.

All examples below need a seeded RNG:

```rust
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

let mut rng = ChaCha20Rng::from_seed([7; 32]); // any 32-byte seed
```

A real deployment should use an OS-backed CSPRNG (`rand_core::OsRng`, or `phantom_fhe::utils::sampling::random_bytes_from_os`) instead of a fixed seed — seeded RNGs here are for reproducibility in docs, tests, and examples only.

## BFV: exact integer arithmetic

```rust
use phantom_fhe::ring::{Degree, Modulus, Ring};
use phantom_fhe::schemes::bfv::{BfvContext, BfvParams};

let ring = Ring::new(Degree::new(8)?, vec![Modulus::new(257)?, Modulus::new(769)?])?;
let ctx = BfvContext::new(BfvParams::new(ring, 17)?); // plaintext modulus t = 17

let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
let encoder = ctx.encoder();
let evaluator = ctx.evaluator()?;

// Signed integers, one per slot:
let pt_a = encoder.encode_i64(&[-2, 3, 5, -6])?;
let pt_b = encoder.encode_i64(&[10, -1, 0, 4])?;

let encryptor = ctx.encryptor(keys.public.clone())?; // or ctx.secret_key_encryptor(keys.secret.clone())?
let ct_a = encryptor.encrypt(&pt_a, &mut rng)?;
let ct_b = encryptor.encrypt(&pt_b, &mut rng)?;

let ct_sum = evaluator.add(&ct_a, &ct_b)?;
let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ct_sum)?;
assert_eq!(&encoder.decode_i64(&decrypted)?[..4], &[8, 2, 5, -2]);
```

- `encode_u64`/`decode_u64` for unsigned integers modulo `t`; `encode_i64`/`decode_i64` for signed (centered around 0, range roughly `[-t/2, t/2)`).
- `evaluator.mul(&ct_a, &ct_b, evaluation_keys)` takes `Option<&EvaluationKeys>` — pass `None` to get an unrelinearized (higher-degree) product, or `Some(&keys)` (from `ctx.keygen()?.generate_evaluation_keys(&secret, &rotation_elements)`) to relinearize back down.
- `evaluator.rotate_slots(&ct, shift)` and `evaluator.sum_slots(&ct, count)` for moving data between slots.
- `slot_count()` (on `BfvParams` or the encoder) tells you how many values fit per ciphertext — equal to the ring degree in the current batching scaffold.

## BGV: exact integer arithmetic with modulus switching

BGV's API is nearly identical to BFV's (unsigned-only encoding, plus explicit modulus switching):

```rust
use phantom_fhe::schemes::bgv::{BgvContext, BgvParams};

let ctx = BgvContext::new(BgvParams::new(ring, 17)?);
let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
let encoder = ctx.encoder();
let evaluator = ctx.evaluator()?;

let pt = encoder.encode_u64(&[1, 2, 3, 4])?;
let ct = ctx.encryptor(keys.public)?.encrypt(&pt, &mut rng)?;

let ct = evaluator.modulus_switch_next(&ct)?; // move to the next RNS level
let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ct)?;
assert_eq!(&encoder.decode_u64(&decrypted)?[..4], &[1, 2, 3, 4]);
```

Prefer BFV when you want signed-integer ergonomics for free; prefer BGV when you want explicit control over modulus switching. Given the current implementation (BFV is a wrapper around BGV internals — see [`architecture.md`](architecture.md#phantom-schemes)), there's no behavioral reason to pick one over the other beyond that API preference today.

## CKKS: approximate real/complex arithmetic

```rust
use phantom_fhe::schemes::ckks::{CkksContext, CkksParams};

let params = CkksParams::builder()
    .degree(8)
    .moduli(vec![257, 769, 3329])
    .default_scale_bits(10) // scale = 2^10
    .build()?;
let ctx = CkksContext::new(params);

let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
let encoder = ctx.encoder();
let evaluator = ctx.evaluator(); // note: no `?` here, unlike BFV/BGV — see below

let pt_a = encoder.encode_real(&[0.5, -1.25, 4.0])?;
let pt_b = encoder.encode_real(&[1.5, 0.25, -2.0])?;

let ct_a = ctx.encryptor(keys.public.clone())?.encrypt(&pt_a, &mut rng)?;
let ct_b = ctx.encryptor(keys.public)?.encrypt(&pt_b, &mut rng)?;

let ct_mul = evaluator.mul(&ct_a, &ct_b, None)?;
let ct_mul = evaluator.rescale_next(&ct_mul)?; // bring the scale back down a level

let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ct_mul)?;
let values = encoder.decode_real(&decrypted)?; // approximately [0.75, -0.3125, -8.0]
```

> `CkksContext::evaluator()` returns `Evaluator` directly (not wrapped in `Result`) — the one asymmetry versus `BfvContext`/`BgvContext::evaluator()`, which both return `Result<Evaluator>`. Worth double-checking if you're writing code generic over scheme contexts.

Things specific to CKKS:

- **Real vs. complex slots**: `encode_real`/`decode_real` for `f64`; `encode_complex`/`decode_complex` (using `phantom_fhe::schemes::ckks::Complex64`) for complex values. Enabling `.conjugate_invariant(true)` on the params builder restricts you to real-only slots but doubles `slot_count()`.
- **Scale tracking**: every ciphertext/plaintext carries a `Scale`; binary operations check `Scale::compatible` and error (`InvalidParameters("scale mismatch")`) if they've drifted apart — typically because one operand was rescaled/leveled differently. Use `evaluator.align_levels(&a, &b)` to bring two ciphertexts to a common level before an operation that needs it.
- **Level budget**: `rescale_next` consumes one level; once a ciphertext's `level()` reaches 0 it can't be rescaled further (multiplication is still possible but the scale keeps growing) — this is the point at which you'd bootstrap (see below) in a scheme with real bootstrapping.
- **Precision**: `ciphertext.precision()` is a running bit-estimate you can inspect to reason about accumulated approximation error across a computation.

## Circuits: linear transforms and polynomial evaluation

Circuits operate on top of a scheme's evaluator. For BGV/BFV they require **degree-zero ciphertexts** (i.e. no pending unrelinearized products); for CKKS there's no such restriction.

### Linear transforms

```rust
use phantom_fhe::circuits::bgv::LinearTransformEvaluator;
use phantom_fhe::circuits::common::LinearTransform;

let lintrans = LinearTransformEvaluator::new(bgv_params.clone());

// A 4x4 dense matrix over the plaintext modulus:
let matrix = LinearTransform::dense(vec![
    vec![1, 0, 0, 0],
    vec![0, 1, 0, 0],
    vec![0, 0, 1, 0],
    vec![0, 0, 0, 1],
])?;

let result = lintrans.apply(&ciphertext, &matrix)?;
```

For a structured (mostly-zero) matrix, convert to diagonals first and plan a baby-step giant-step rotation schedule before applying — this is what a real (rotation-key-constrained) deployment would use instead of the dense `apply` path:

```rust
let diagonals = lintrans.diagonalize(&matrix)?;
let plan = diagonals.bsgs_plan(baby_step_count)?;
let result = lintrans.apply_diagonal(&ciphertext, &diagonals)?;
```

CKKS's `phantom_fhe::circuits::ckks::LinearTransformEvaluator` has the identical shape, over `Complex64` matrices and without the degree-zero restriction.

### Polynomial evaluation

```rust
use phantom_fhe::circuits::bgv::PolynomialEvaluator;

let poly_eval = PolynomialEvaluator::new(bgv_params)?;
let plan = poly_eval.plan(&coefficients)?; // inspect plan.strategy() if you care which one was picked
let result = poly_eval.evaluate(&ciphertext, &coefficients, None)?; // c_0 + c_1*x + ... mod t
```

CKKS's `phantom_fhe::circuits::ckks::PolynomialEvaluator::evaluate_real`/`evaluate_complex` is the approximate-arithmetic equivalent; `MinimaxEvaluator::evaluate_composite` chains several polynomial stages for approximating a more complex function.

## CKKS bootstrapping

```rust
use phantom_fhe::bootstrapping::ckks::{default_bootstrap_params, BootstrapKeyGenerator, Bootstrapper};

let bootstrap_params = default_bootstrap_params(ckks_params.clone())?;
let key = BootstrapKeyGenerator::new(bootstrap_params.clone()).generate(&[]); // rotation elements needed, if any
let bootstrapper = Bootstrapper::new(bootstrap_params, key);

let refreshed = bootstrapper.bootstrap(&ciphertext)?;
// or, for several ciphertexts at once:
let refreshed_batch = bootstrapper.bootstrap_batch(&ciphertexts)?;
```

`SecretKeyBootstrapper::new(params, rotation_elements)` is a convenience wrapper for tests/examples that generates its own key marker internally, skipping the explicit `BootstrapKeyGenerator` step. See [`concepts.md#bootstrapping`](concepts.md#bootstrapping) for what the pipeline does, and [`technical-manual.md#bootstrapping-internals`](technical-manual.md#bootstrapping-internals) for what it does *today* (the middle `EvalMod` stage is currently a message-preserving identity, not the real modular-reduction approximation).

## Multiparty / threshold protocols

Every `mpXXX` protocol follows the same session → share → aggregate shape. Here's the pattern with `mpbgv`'s `PartialDecryptor` as the concrete example — `mpbfv`/`mpckks` and the other protocol types (`CollectiveKeyGen`, `RelinearizationKeyGen`, `GaloisKeyGen`, `ReEncryptor`, `InteractiveBootstrap`) all follow it identically:

```rust
use phantom_fhe::multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState, ShareAggregator, ShareKind,
};
use phantom_fhe::multiparty::mpbgv::PartialDecryptor;

// 1. Describe who's participating and the threshold required to act.
let participants = ParticipantSet::new(vec![
    ParticipantId::new(1)?, ParticipantId::new(2)?, ParticipantId::new(3)?,
])?;
let session = SessionState::new(
    SessionId::new(1)?,
    ProtocolKind::PartialDecryption,
    participants,
    2, // threshold: any 2 of the 3 participants
)?;

// 2. Each participant creates its share of the operation.
let decryptor = PartialDecryptor::new(bgv_params.clone(), session.clone());
let share_1 = decryptor.create_share(ParticipantId::new(1)?, &ciphertext)?;
let share_2 = decryptor.create_share(ParticipantId::new(2)?, &ciphertext)?;

// 3. Collect shares until the threshold is met, then aggregate.
let mut aggregator = ShareAggregator::new(session, ShareKind::PartialDecryption);
aggregator.add_share(share_1)?;
aggregator.add_share(share_2)?;
assert!(aggregator.is_ready());

let plaintext = decryptor.aggregate_plaintext(&aggregator)?;
```

Swap `PartialDecryptor` for `CollectiveKeyGen`/`RelinearizationKeyGen`/`GaloisKeyGen`/`ReEncryptor`/`InteractiveBootstrap` (and their matching `ShareKind`/`ProtocolKind` variant) for the other protocols; swap `mpbgv` for `mpbfv` or `mpckks` for the other schemes. `mpckks::InteractiveBootstrap` additionally needs a `phantom_bootstrapping::ckks::BootstrapParams` alongside the `CkksParams` — see its constructor.

`Transcript`/`TranscriptMessage` (also in `multiparty::common`) give you a deterministic, appendable, hashable log if your protocol needs a public record of what was exchanged — see [`concepts.md#multiparty--threshold-protocols`](concepts.md#multiparty--threshold-protocols).

## Serialization

Every public wire type has matching `encode_*`/`decode_*` functions:

```rust
use phantom_fhe::schemes::serialization::{encode_bgv_ciphertext, decode_bgv_ciphertext};

let bytes = encode_bgv_ciphertext(&ciphertext)?;
let restored = decode_bgv_ciphertext(&bytes)?;
assert_eq!(ciphertext, restored);
```

Decoding a payload against the wrong `decode_*` function, or a truncated/corrupted payload, returns a typed error rather than misparsing — see [`technical-manual.md#serialization-format`](technical-manual.md#serialization-format) for the full domain-tag catalog across every crate. Secret-bearing types (`SecretKey`, RGSW keys) deliberately have no serialization path.

## Choosing parameters

Every parameter set in this guide, in the examples, and in the test suite is a small development preset, chosen for fast iteration in CI and local development rather than production security margins — see [SECURITY.md](../SECURITY.md) for current cryptographic status. The presets used throughout:

| Scheme(s) | Ring degree | Ciphertext moduli | Plaintext modulus / scale |
| --- | --- | --- | --- |
| BFV, BGV | 8 | `257`, `769` | `t = 17` |
| CKKS | 8 | `257`, `769`, `3329` | default scale `2^10` |
| CKKS bootstrapping | (same as CKKS above) | (same) | target precision 20 bits (`default_bootstrap_params`) |

There is currently no production parameter preset to graduate to — adding one is explicitly gated (per Alpha Hardening Workstream 2 in [`internal/implementation-plan.md`](internal/implementation-plan.md)) on the noise-management, RNS, and security-review work tracked in Workstreams 3–7 landing first. If you're evaluating this library for a real deployment, the honest current answer is: not yet: track the roadmap, and treat every parameter set you construct today as a development/testing convenience, not a security decision.

If you're experimenting with a larger ring degree and want a sanity check against the [homomorphicencryption.org](https://homomorphicencryption.org/standard/) 128-bit security table, call `.require_128_bit_security()` on `BgvParams::builder()`/`BfvParams::builder()`/`CkksParams::builder()` before `.build()` — it rejects a ring degree/total-ciphertext-modulus-bits combination the standard's own published table doesn't cover as secure. It's opt-in (every preset in the table above is far below the table's smallest covered degree, `1024`, and would fail this check by design) and is a parameter-shape check only, not a substitute for the noise-management and review work still tracked in the roadmap above.

## Runnable examples

`phantom-examples` (workspace-only; not part of the facade) has one binary per workflow below. Run any of them with `cargo run -p phantom-examples --example <name>`, or all of them with `make examples`:

| Example | What it demonstrates |
| --- | --- |
| `bfv_basic` | BFV encrypt/decrypt round trip with signed slots |
| `bfv_batching` | BFV unsigned batched slot encode/decode |
| `bfv_rotation` | BFV slot rotation |
| `bgv_basic` | BGV encrypt/decrypt round trip |
| `bgv_polynomial` | Polynomial evaluation over BGV slots |
| `ckks_basic` | CKKS encrypt/decrypt round trip |
| `ckks_rescale` | CKKS multiplication and rescale metadata (scale/level) |
| `ckks_dft` | CKKS DFT circuit and its inverse |
| `ckks_inverse` | CKKS reciprocal-approximation circuit |
| `ckks_bootstrapping` | The CKKS bootstrapping pipeline |
| `mpbgv_basic` | Multiparty BGV collective key generation and partial decryption (real) |
| `mpckks_basic` | Multiparty CKKS collective key generation and partial decryption (real) |
| `mpckks_interactive_bootstrap` | Multiparty CKKS interactive bootstrapping |

## Where to go next

- Contributing code, testing conventions, or adding a new scheme: [`developer-guide.md`](developer-guide.md)
- The exact algorithm/format reference: [`technical-manual.md`](technical-manual.md)
- Current security status: [SECURITY.md](../SECURITY.md)
