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

Every `mpXXX` protocol follows the same session → share → aggregate shape — but read this first, since it's easy to assume the wrong security model: all six real protocols (`CollectiveKeyGen`, `RelinearizationKeyGen`, `GaloisKeyGen`, `PartialDecryptor`, `ReEncryptor`, `InteractiveBootstrap`) are **additive n-of-n**, not genuine `t`-of-`n` threshold — *every* participant who was given a share must contribute, not merely `threshold` of them; omitting even one silently produces a result for a different collective secret than the one everyone actually agreed to. `SessionState`'s own `threshold` field and `ShareAggregator::aggregate()` (which truncates to exactly `threshold` shares) exist to support genuine threshold schemes — `phantom_fhe::multiparty::vss`'s Pedersen verifiable secret sharing is the one place in this crate that actually uses them that way — but the six protocols below call `ShareAggregator::all_shares()` internally instead, and their own `SessionState` should be constructed with `threshold` set to the full participant count. See [`concepts.md#multiparty--threshold-protocols`](concepts.md#multiparty--threshold-protocols) for why this was the deliberate choice (collusion resistance: confidentiality holds as long as at least one contributor is honest) and [SECURITY.md](../SECURITY.md) for the full adversary model.

Here's the pattern with `mpbgv`'s real `CollectiveKeyGen` + `PartialDecryptor` as the concrete example (mirroring the runnable `mpbgv_basic` example) — `mpbfv`/`mpckks` and the other four protocol types follow it identically, differing only in the per-share arguments each protocol's own doc comment lists:

```rust
use phantom_fhe::lattice::rlwe::SecretKey;
use phantom_fhe::multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, ReplayGuard, SessionId, SessionState,
    ShareAggregator, ShareKind,
};
use phantom_fhe::multiparty::mpbgv::{CollectiveKeyGen, PartialDecryptor};
use phantom_fhe::ring::rns::extension::embed_centered_coeffs;
use phantom_fhe::ring::{Degree, Modulus, Ring};
use phantom_fhe::schemes::bgv::{BgvContext, BgvParams};

// Real multiparty protocols need a noise-safe modulus, not the toy `257`
// preset used elsewhere in this guide - see "Choosing parameters" above.
let ring = Ring::new(Degree::new(8)?, vec![Modulus::new(1_000_000_000_000_037)?])?;
let params = BgvParams::new(ring.clone(), 17)?; // plaintext modulus t = 17

// Every participant who contributes a session key/decrypt share below.
let participants = ParticipantSet::new(vec![ParticipantId::new(1)?, ParticipantId::new(2)?])?;

// Each participant's own ordinary, independently-generated small secret -
// never a Shamir share of anything, kept entirely local; only the public
// shares each protocol below computes from it are ever transmitted.
let secrets = [
    SecretKey::new(embed_centered_coeffs(&[1, -1, 0, 1, -1, 0, 1, -1], ring.moduli())?),
    SecretKey::new(embed_centered_coeffs(&[-1, 1, 0, -1, 1, 0, -1, 1], ring.moduli())?),
];
// One `ReplayGuard` per participant, reused across every real protocol
// call that participant makes - refuses to reuse a session's own
// deterministic public randomness twice.
let mut guards = [ReplayGuard::new(), ReplayGuard::new()];

// 1. Collectively generate a public key nobody individually holds the
//    secret for - threshold == participant count, since this is n-of-n.
let ckg_session = SessionState::new(
    SessionId::new(1)?, ProtocolKind::CollectiveKeyGen, participants.clone(), 2,
)?;
let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
for (i, secret) in secrets.iter().enumerate() {
    let share = ckg.create_share(ParticipantId::new(i as u64 + 1)?, secret, &mut guards[i], &mut rng)?;
    ckg_aggregator.add_share(share)?;
}
let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator)?;

// 2. Encrypt under the collective key like any ordinary public key.
let ctx = BgvContext::new(params.clone());
let encoder = ctx.encoder();
let ciphertext = ctx
    .real_encryptor(collective_public_key)
    .encrypt(&encoder.encode_u64(&[7, 8, 9, 10])?, &mut rng)?;

// 3. Collectively decrypt - each participant's own share alone reveals
//    nothing; `ciphertext_noise_bound` is the caller's own worst-case
//    bound on this ciphertext's current noise (see the type's own doc
//    comment for why it can't be derived internally).
let ciphertext_noise_bound = phantom_fhe::schemes::bgv::noise::fresh_public_key_noise_bound(ring.degree());
let partial_session = SessionState::new(
    SessionId::new(2)?, ProtocolKind::PartialDecryption, participants, 2,
)?;
let partial = PartialDecryptor::new(
    params, partial_session.clone(), phantom_fhe::lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS,
);
let mut aggregator = ShareAggregator::new(partial_session, ShareKind::PartialDecryption);
for (i, secret) in secrets.iter().enumerate() {
    let share = partial.create_share(
        ParticipantId::new(i as u64 + 1)?, secret, &ciphertext, ciphertext_noise_bound, &mut guards[i], &mut rng,
    )?;
    aggregator.add_share(share)?;
}
let plaintext = partial.aggregate_plaintext(&aggregator, &ciphertext)?;
assert_eq!(&encoder.decode_u64(&plaintext)?[..4], &[7, 8, 9, 10]);
```

Swap `mpbgv` for `mpbfv`/`mpckks` for the other schemes (BFV drops BGV's own `t`-scaled noise; CKKS additionally needs `at_level`-aware secret truncation for `ReEncryptor`/`PartialDecryptor`/`InteractiveBootstrap` once a ciphertext has been rescaled - see each type's own doc comment). `RelinearizationKeyGen` is a multi-round protocol (two rounds for `mpbgv`, three for `mpbfv`/`mpckks`'s own RNS-hybrid construction) rather than the single round shown above. `mpbgv_basic`/`mpckks_basic` (CKG + `PartialDecryptor`) and `mpckks_interactive_bootstrap` (CKG + `InteractiveBootstrap`) in `phantom-examples` are complete, runnable versions of this pattern; `GaloisKeyGen`/`RelinearizationKeyGen`/`ReEncryptor` aren't exposed as example binaries yet, but `phantom-multiparty`'s own integration tests (`phase14_mpbgv.rs`/`phase15_mpbfv.rs`/`phase16_mpckks.rs`) exercise all six protocols end to end and are the most complete reference for those three.

`Transcript`/`TranscriptMessage` (also in `multiparty::common`) give you a deterministic, appendable, hashable log if your protocol needs a public record of what was exchanged.

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

Every parameter set in this guide, in the examples, and in the test suite is a small development preset, chosen for fast iteration in CI and local development rather than production security margins — see [SECURITY.md](../SECURITY.md) for current cryptographic status. The presets used throughout, each with its own security note:

| Preset | Used by | Ring degree | Ciphertext moduli | Plaintext modulus / scale | Security note |
| --- | --- | --- | --- | --- | --- |
| BFV/BGV toy | `bfv_basic`/`bfv_batching`/`bfv_rotation`/`bgv_basic`/`bgv_polynomial` examples, most of the test suite | 8 | `257`, `769` | `t = 17` | Development-only. Degree 8 is far below `1024`, the smallest degree any published 128-bit security table (including the one `.require_128_bit_security()` checks against) covers at all — no modulus choice at this degree carries any security margin. |
| CKKS toy | `ckks_basic`/`ckks_dft`/`ckks_inverse`/`ckks_rescale` examples, most of the CKKS test suite | 8 | `257`, `769`, `3329` | default scale `2^10` | Same as BFV/BGV toy above. |
| CKKS bootstrapping | `ckks_bootstrapping` example | (same as CKKS toy) | (same) | target precision 20 bits (`default_bootstrap_params`) | Same as CKKS toy above — bootstrapping doesn't change the underlying parameters' own security status, only what operations can be performed on them. |
| Real-noise-headroom preset | `bgv_real_basic`/`bfv_real_basic`/`ckks_real_basic` examples, every real (non-transparent) multiparty example and test | 8 | a single much larger modulus, e.g. `1_000_000_000_000_037` (CKKS additionally uses a second, smaller rescale modulus) | `t = 17` | **Still degree 8** — the same security status as the toy presets above, despite the larger modulus. The larger modulus exists purely to give real encryption noise (and, for multiparty, smudging noise) enough headroom to actually round-trip; it is not, and was never intended as, a security margin. |
| Production-shaped example | `crates/phantom-schemes/tests/production_preset.rs` only (not yet used by any example or the rest of the test suite) | `8192` | 3 NTT-friendly ~55-bit primes (~165 bits total, under the table's 218-bit budget at this degree) | `t = 65537` / scale `2^55` | Passes `.require_128_bit_security()` for the ciphertext modulus itself — see the dedicated subsection below for the full note, since this preset has more nuance (an auxiliary modulus the security check doesn't cover, and no independent review) than a one-line note can carry. |

There is no general-purpose production parameter methodology yet, and no independent cryptographic security review of any specific choice — the production-shaped example above is one representative exception, not a general answer. If you're evaluating this library for a real deployment beyond that one example, the honest current answer is: not yet: track the roadmap ([`internal/implementation-plan.md`](internal/implementation-plan.md)), and treat every other parameter set in the table above as a development/testing convenience, not a security decision.

If you're experimenting with a larger ring degree and want a sanity check against the [homomorphicencryption.org](https://homomorphicencryption.org/standard/) 128-bit security table, call `.require_128_bit_security()` on `BgvParams::builder()`/`BfvParams::builder()`/`CkksParams::builder()` before `.build()` — it rejects a ring degree/total-ciphertext-modulus-bits combination the standard's own published table doesn't cover as secure. It's opt-in (every preset in the table above except the production-shaped example is far below the table's smallest covered degree, `1024`, and would fail this check by design) and is a parameter-shape check only, not a substitute for the noise-management and review work still tracked in the roadmap above.

### A production-shaped example

Alpha Hardening Workstream 2 item 2 asked for one example of parameters actually sized for real security, separate from the toy presets above — not a general methodology, not a family of presets for different circuit depths, and not an independent security review of the choice (that remains genuinely open work). This is that one example, at ring degree `N = 8192` (218 bits of total ciphertext-modulus budget per the homomorphicencryption.org table at this degree):

| | Value |
| --- | --- |
| Ring degree | `8192` |
| Ciphertext moduli (`Q`) | 3 NTT-friendly ~55-bit primes: `36028797018652673`, `36028797017571329`, `36028797017456641` (~165 bits total, comfortably under the 218-bit cap) |
| Auxiliary key-switching / BFV extended-basis moduli (`P`) | 4 ~58-bit primes: `288230376151711717`, `288230376151711687`, `288230376151711681`, `288230376151711607` (~232 bits total) |
| Plaintext modulus (BGV/BFV) | `t = 65537` |
| Default scale (CKKS) | `2^55` — deliberately close to `Q`'s own prime size, since CKKS's rescale divides out exactly one `Q` modulus and precision is best when that modulus is close in size to the tracked scale |

**Security note.** `.require_128_bit_security()` passes for `Q` at this degree. Known limitation, stated explicitly rather than assumed away: that check only covers `Q` — it has no concept of `P` at all, since `P` is passed separately to `generate_hybrid_relinearization_key`/`mul_real` and is never part of `BgvParams`/`BfvParams`/`CkksParams` themselves. `P` here is sized to satisfy the *stricter* of two requirements it has to meet (BFV's own `mul_real`/`rescale_and_round` needs the combined `QP` to exceed `degree * (Q/2)^2` to reconstruct its raw tensor product without wraparound — a materially bigger requirement than hybrid key-switching's own "`P` comparable to `Q`'s largest single prime"), but the combined `QP` bit-length itself hasn't been checked against any published table for an extended-dimension RLWE instance. No independent cryptographic review of this specific choice has been performed.

This exact preset is proven correct end to end, not just asserted here — `crates/phantom-schemes/tests/production_preset.rs` (`#[ignore]`d by default: real computation at this scale takes minutes on today's unoptimized arithmetic, run explicitly with `cargo test -p phantom-schemes --test production_preset -- --ignored`) runs real keygen, encryption, one multiplication, relinearization, and (CKKS) rescaling at these parameters for BGV, BFV, and CKKS, decrypts, and checks the result against a directly-computed expected value, plus a positive noise-budget/precision check on top of plain correctness.

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
| `mpckks_interactive_bootstrap` | Multiparty CKKS interactive (collective) bootstrapping (real) |

## Where to go next

- Contributing code, testing conventions, or adding a new scheme: [`developer-guide.md`](developer-guide.md)
- The exact algorithm/format reference: [`technical-manual.md`](technical-manual.md)
- Current security status: [SECURITY.md](../SECURITY.md)
