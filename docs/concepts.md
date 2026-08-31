# Concepts

This is a from-first-principles tour of the cryptography Phantom-FHE implements: the math each layer is built on, and the terminology used throughout the rest of the docs. It assumes general programming background but not prior FHE experience. For where each concept lives in the code, see [`architecture.md`](architecture.md); for exactly how far the current implementation is from the textbook version described here, see [`technical-manual.md`](technical-manual.md) and [SECURITY.md](../SECURITY.md).

## Why FHE

Fully homomorphic encryption lets you compute on encrypted data without decrypting it: given `Enc(a)` and `Enc(b)`, you can produce `Enc(a + b)` or `Enc(a * b)` without ever seeing `a` or `b`. The party doing the computation never needs the secret key. This is the primitive behind encrypted analytics, privacy-preserving machine learning, and secure data collaboration — the data owner encrypts, a third party computes, and only the data owner (holding the secret key) can decrypt the result.

Phantom-FHE implements the **RLWE-based** family of schemes (BGV, BFV, CKKS), which is the dominant practical approach: security reduces to the Ring Learning With Errors problem, and ciphertexts are pairs (or tuples) of polynomials in a specific ring.

## Ring arithmetic

Every scheme in this family works over the polynomial ring:

```text
R_q = Z_q[X] / (X^N + 1)
```

- `N` is the **ring degree**, a power of two (e.g. 8, 4096, 65536). It bounds the polynomial degree — every polynomial in `R_q` has at most `N` coefficients — and, in batched schemes, determines the number of plaintext slots.
- `q` is the **ciphertext modulus**. Coefficients live in `Z_q = {0, 1, ..., q-1}`.
- `X^N + 1` makes this a **negacyclic** ring: multiplication wraps around with a sign flip (`X^N ≡ -1`), rather than the plain cyclic wraparound (`X^N ≡ 1`) you'd get from `X^N - 1`.

`phantom-ring::Ring` (`Degree` + `Vec<Modulus>`) models this, with `phantom-ring::Poly` storing polynomial coefficients.

### RNS: why the modulus is a list of moduli

Production FHE moduli `q` are large (hundreds of bits) — too large for a machine word. **RNS (Residue Number System)** represents `q` as a product of small coprime moduli, `q = q_1 * q_2 * ... * q_k`, each fitting in a `u64`. A value `x mod q` is then stored as the tuple of residues `(x mod q_1, x mod q_2, ..., x mod q_k)`, and arithmetic on `x` reduces to independent arithmetic on each residue (by CRT — the Chinese Remainder Theorem). This is why `phantom_ring::Poly` stores `coeffs: Vec<Vec<u64>>` indexed `[modulus_index][coefficient_index]` rather than one big-integer coefficient vector.

RNS also gives you **modulus switching / rescaling**: dropping the last modulus `q_k` from the basis divides the represented value by (approximately) `q_k`, which is how BGV modulus switching and CKKS rescaling manage noise growth and, for CKKS, the fixed-point scale. `phantom_ring::rns::rescale::drop_last_modulus` is the primitive; `phantom_ring::rns::extension::extend_basis` goes the other way (extending into a larger basis, needed for e.g. RGSW external products and multiplication).

### Modular reduction

Every ring operation needs fast reduction modulo each `q_i`. The standard techniques:

- **Barrett reduction** — precomputes an approximation of `1/q` to replace division with multiplication and shifts.
- **Montgomery reduction** — represents values in a transformed domain where reduction is cheap, at the cost of transforming in and out.
- **Lazy reduction** — defers full reduction across a chain of additions, only reducing once the accumulator risks overflow.

`phantom_ring::reduce` exposes `BarrettReducer`, `MontgomeryReducer`, and `reduce_once` (lazy) as the shape for these — see [`technical-manual.md`](technical-manual.md#ring-internals) for their current (placeholder) implementations.

### NTT: fast polynomial multiplication

Multiplying two degree-`N` polynomials directly (schoolbook) is O(N²). The **Number Theoretic Transform** — the finite-field analogue of the FFT — evaluates both polynomials at `N` roots of unity, multiplies pointwise (O(N)), and interpolates back, for O(N log N) total. This requires `q` to have a primitive `N`-th root of unity; for the *negacyclic* ring here, specifically a primitive `2N`-th root `ψ` with `ψ² = ω` (the `N`-th root), which is exactly what `Modulus::supports_ntt(n)` checks: `(q - 1) % 2n == 0`.

`phantom_ring::ntt::NttTable` computes `ψ`, `ω`, and their inverses for a given modulus/degree; `NttBackend` (`forward`/`inverse`) is the trait a concrete implementation satisfies, with `CpuNttBackend` as the current implementation — see the technical manual for its actual (non-butterfly) complexity today.

### Sampling

Key generation and encryption need randomness from specific distributions:

- **Uniform** — coefficients uniform in `[0, q)`. Used for the "random" half of RLWE public keys and fresh encryption randomness.
- **Ternary** — coefficients in `{-1, 0, 1}`. A common small-secret distribution: keeps secret keys small (which bounds noise growth) while remaining hard to guess.
- **Discrete Gaussian** — coefficients drawn from a narrow, centered distribution. Used for RLWE's error term `e`, whose smallness is what makes decryption work and whose randomness is what makes the scheme secure (the "learning with errors" in RLWE).

`phantom_ring::sampling` provides `sample_uniform`, `sample_ternary`, and `sample_discrete_gaussian`, all generic over `RngCore + CryptoRng`.

## RLWE: the shared foundation

**Ring Learning With Errors** is the hardness assumption every scheme here reduces to. An RLWE secret key is a small polynomial `s` (typically ternary). An RLWE encryption of a plaintext polynomial `m` is a pair `(c_0, c_1)` such that:

```text
c_0 + c_1 * s ≈ m   (mod q)
```

with the "≈" hiding a small error term that decryption's rounding absorbs. Concretely:

- **Secret-key encryption**: sample uniform `a`, error `e`; set `c_0 = m - a*s (+ e)`, `c_1 = a`. Decryption computes `c_0 + c_1*s = m (+ e)`.
- **Public-key encryption**: the public key is `(b, a) = (-a*s + e, a)` for a fresh uniform `a` and error `e` (this *is* a fresh RLWE encryption of zero). To encrypt `m`, sample a small `u` and errors, and compute `c_0 = m + b*u (+ e_1)`, `c_1 = a*u (+ e_2)`.

`phantom_lattice::rlwe` models exactly this shape: `SecretKey`, `PublicKey` (`(c0, c1)` = `(b, a)`), `Encryptor::{SecretKey, PublicKey}`, `Decryptor`. `Ciphertext` is a `Vec<Poly>` because **homomorphic multiplication grows the ciphertext degree**: multiplying a degree-1 ciphertext by another produces a degree-2 ciphertext (three components, needing `s²` at decryption) — hence `Decryptor::decrypt` accumulates `sum_i c_i * s^i`.

### Relinearization and key switching

A degree-2 (or higher) ciphertext works but grows with every multiplication, and needs increasing powers of the secret key to decrypt. **Relinearization** brings it back down to degree 1 using a public **relinearization key** (an encryption of `s²` under `s`, decomposed for noise control). **Key switching** is the general version: transform a ciphertext encrypted under one key into an encryption of the same message under a *different* key — relinearization is key switching from `s²` back to `s`; rotations use key switching from `s` under a Galois automorphism back to `s` under the identity.

### RGSW and the external product

**RGSW** (Ring-GSW) is a different ciphertext shape for the *same* RLWE secret key, built for one specific operation: the **external product**, `RGSW ⊠ RLWE → RLWE`, which multiplies an RLWE ciphertext by an RGSW-encrypted bit/value *without* the noise blowup a regular RLWE×RLWE product causes for that use case. This is the workhorse behind bootstrapping's internal `mux`-style operations in many schemes, and behind more advanced circuit gadgets.

The trick that makes RGSW's noise stay small is **gadget decomposition**: instead of one ciphertext, RGSW stores several rows of RLWE encryptions of `m * g_i` for a gadget vector `g = (1, B, B², ..., B^(l-1))` (a base-`B` digit decomposition). To multiply, the RLWE input is first decomposed into its own base-`B` digits, then each digit is matched against the corresponding RGSW row — keeping every intermediate value small. `phantom_lattice::rgsw::decomposition::GadgetDecomposition` implements exactly this: `decompose(poly, params)` splits each coefficient into `levels` base-`2^base_log` digits; `recompose` reconstructs.

## BGV, BFV, CKKS: the three schemes

All three build on RLWE ciphertexts but differ in what a "plaintext" means and how noise/precision is managed.

### BGV and BFV — exact integer arithmetic

BGV and BFV both encode integers **exactly**: the plaintext lives in `Z_t` for a small **plaintext modulus** `t`, and every homomorphic operation is exact modulo `t` (no approximation, no rounding error in the *result* — only in whether the ciphertext still decrypts correctly, which is a noise-budget question, not a precision one). They differ mainly in *when* scaling by `t/q` happens (BFV scales at multiplication time; BGV carries plaintext and ciphertext moduli separately and uses modulus switching) and in some engineering tradeoffs — for most application code the two are close to interchangeable, which is reflected in this codebase by BFV literally being a wrapper around BGV's mechanics (see [`architecture.md`](architecture.md#phantom-schemes)) with signed integer encoding layered on top.

**Batching**: rather than one integer per ciphertext, both schemes pack a vector of integers into the coefficient/slot positions of a single polynomial, so one homomorphic add/multiply operates on all slots (`slot_count()`) in parallel (SIMD-style). Rotating slots (`rotate_slots`) and summing across slots (`sum_slots`, by rotate-and-add) are standard building blocks for anything beyond pure elementwise arithmetic — reductions, dot products, matrix-style operations.

### CKKS — approximate real/complex arithmetic

CKKS encodes **approximate** real or complex numbers instead of exact integers. A plaintext value `v` is represented as `round(v * scale)` for a large fixed **scale** (e.g. `2^40`); every operation carries the scale along, and multiplication *multiplies* two ciphertexts' scales together (`scale_result = scale_lhs * scale_rhs`) — which is why CKKS needs an explicit **rescale** operation after each multiplication, dividing the scale back down (dropping one RNS modulus, à la BGV modulus switching) before it grows unmanageably. This is CKKS's defining tradeoff: you get real-number arithmetic and machine-learning-friendly operations, at the cost of accumulating floating-point-like approximation error instead of exact results.

Three numbers matter for reasoning about a CKKS ciphertext:

- **Scale** — the fixed-point scale factor, checked for compatibility (`Scale::compatible`) before binary operations.
- **Level** — how many RNS moduli remain in the ciphertext's modulus chain; `rescale_next` consumes one level. Once level reaches 0, no more multiplications (without bootstrapping) are possible.
- **Precision** — a running *estimate*, in bits, of how much approximation error has accumulated; every operation degrades it by some amount (rotation/add/sub degrade a little; multiply and rescale degrade more).

CKKS also supports a **conjugate-invariant** mode for encoding only real (not complex) values, which doubles the usable slot count for real-only workloads (`slot_count()` returns `N` instead of `N/2`) at the cost of rejecting non-zero imaginary parts.

## Homomorphic circuits

Batching gives you elementwise operations "for free," but most interesting computations need to move data *between* slots — matrix-vector products, convolutions, polynomial approximations of nonlinear functions. `phantom-circuits` provides the scheme-independent planning machinery for this:

### Linear transforms and the diagonal method

A linear transform on slots is a matrix `M` applied to the slot vector. Applying `M` densely costs `slot_count` rotations. The standard optimization (the **diagonal method**) rewrites `M` as a sum of `slot_count` cyclic diagonals (`M[i][(i+offset) % n]` for each `offset`), most of which are zero for structured transforms — you only pay for the *nonzero* diagonals. `LinearTransform::to_diagonal_matrix` / `DiagonalMatrix::from_linear_transform` performs this conversion.

**Baby-step giant-step (BSGS)** further reduces the rotation count for the diagonal method: instead of one rotation key per nonzero diagonal offset, offsets are split into "baby steps" (small, precomputed rotations) and "giant steps" (larger rotations applied to baby-step results), needing only `O(√(number of diagonals))` distinct rotation keys instead of `O(number of diagonals)`. `DiagonalMatrix::bsgs_plan` / `BabyStepGiantStepPlan` implements the schedule.

### Polynomial evaluation strategies

Evaluating a polynomial homomorphically means every multiplication consumes a CKKS level (or BGV/BFV noise budget), so the *strategy* for evaluating `c_0 + c_1*x + ... + c_d*x^d` matters:

- **Horner's method** — sequential, minimal code, but *depth* (levels consumed) equal to the degree.
- **Power basis** — precompute all powers `x, x², ..., x^d`, then a single weighted sum; more multiplications but shallower depth.
- **Paterson-Stockmeyer** — the BSGS idea applied to polynomials: split into `√d`-sized blocks (baby steps), compute `√d` giant powers, and combine — `O(√d)` multiplications instead of `O(d)`, at roughly `O(log d)` depth.

`PolynomialEvalPlan::for_degree` picks a strategy automatically (constant → Horner ≤3 → power-basis ≤7 → Paterson-Stockmeyer beyond that); `PolynomialEvalPlan::with_strategy` lets you override it.

### CKKS-specific circuits

Beyond generic linear transforms and polynomial evaluation, `phantom_circuits::ckks` provides the building blocks bootstrapping and approximate computation need:

- **DFT** (`DftEvaluator`) — a discrete Fourier transform over packed slots, used for the coefficients↔slots transforms in bootstrapping.
- **Comparison** (`ComparisonEvaluator`) — smooth approximations of `sign(x)` (via `tanh(αx)`), the unit step function, and `max(a, b)` (via a smoothed absolute value) — CKKS can't branch, so comparisons need continuous approximations.
- **Inverse** (`InverseEvaluator`) — reciprocal approximation.
- **Mod1** (`Mod1Evaluator`) — centered fractional part (`x - round(x)`), a building block for CKKS's `EvalMod` bootstrapping stage.
- **Minimax** (`MinimaxEvaluator`) — evaluates a *composite* of polynomial stages (each stage's output feeds the next), the general mechanism behind minimax-polynomial approximations of arbitrary functions.

## Bootstrapping

Every scheme above has a *noise budget* (BGV/BFV) or *level budget* (CKKS) that's consumed by multiplication and never replenished by normal operations — eventually a ciphertext can't be operated on further without becoming undecryptable. **Bootstrapping** refreshes a ciphertext to restore that budget, homomorphically evaluating the decryption circuit itself (so the result comes out re-encrypted at full budget, without ever exposing the plaintext).

CKKS bootstrapping is the one implemented here, as the standard four-stage pipeline:

1. **Coefficients → slots** — move the ciphertext's coefficient representation into its slot (evaluation) representation via a DFT-like transform, so slot-wise operations can act on it.
2. **EvalMod** — homomorphically evaluate the modular reduction that decryption implicitly performs, which is the step that actually "refreshes" the noise/level budget. This is the hardest step in real CKKS bootstrapping (it needs a good polynomial approximation of a periodic function) and is where this implementation is currently a stand-in — see the technical manual.
3. **Slots → coefficients** — the inverse DFT-like transform, back to coefficient representation.
4. **Sparse packing/unpacking** (`Packer`/`Unpacker`) — bootstrapping is often cheaper on a smaller sparsely-packed ring; packing concatenates several sparse ciphertexts into one dense batch before/after the pipeline (`bootstrap_batch`).

BGV and BFV bootstrapping are architecturally reserved (`phantom_bootstrapping::{bgv, bfv}` module locations exist) but not implemented — see [SECURITY.md](../SECURITY.md). Interactive (threshold, multi-party) bootstrapping — a different, protocol-based way to refresh a ciphertext using cooperating parties instead of the centralized pipeline above — lives in `phantom-multiparty` instead, described next.

## Multiparty / threshold protocols

Everything above assumes one secret-key holder. Multiparty protocols distribute the secret key across `n` participants such that any `threshold` of them can cooperate to decrypt or perform key-dependent operations, but no smaller coalition can. `phantom-multiparty` implements this shape for BGV, BFV, and CKKS uniformly:

- **Participants and sessions** — `ParticipantId`/`ParticipantSet` identify who's involved; `SessionState` binds a `ProtocolKind`, a `ParticipantSet`, a `threshold`, and a `round` counter, so shares can't be replayed into the wrong session, protocol, or round.
- **Shares** — `Share` is a signed-and-typed payload (`ShareKind` + session/round/participant binding) that one participant contributes; `ShareAggregator` collects shares for one session/kind and reports `is_ready()` once `threshold` shares have arrived, then `aggregate()` returns them in canonical order.
- **Transcripts** — `Transcript`/`TranscriptMessage` give a deterministic, appendable, hashable log of a protocol run (useful for auditing and for protocols needing a public transcript, e.g. Fiat-Shamir-style constructions).

On top of this, each of `mpbgv`/`mpbfv`/`mpckks` implements six protocols with the same names:

- **`CollectiveKeyGen` (ckg)** — participants jointly generate a public key for a secret key that's *shared* (no single party holds it).
- **`RelinearizationKeyGen` (rkg)** / **`GaloisKeyGen` (gkg)** — the threshold analogues of relinearization/rotation key generation.
- **`PartialDecryptor`** — each participant contributes a partial decryption share of a ciphertext (their share alone reveals nothing); aggregating `threshold` shares yields the plaintext.
- **`ReEncryptor`** — re-encrypts a ciphertext under a different collective key using threshold shares, without full decryption.
- **`InteractiveBootstrap`** — refreshes a ciphertext via cooperating participants rather than (or, for CKKS, in addition to) a centralized bootstrapping pipeline; `mpckks::InteractiveBootstrap` is the one that hands off to `phantom_bootstrapping::ckks::Bootstrapper` after aggregating shares.

## Serialization

Every public wire type (keys, parameters, plaintexts, ciphertexts, bootstrap parameters) is encoded with a fixed **domain tag** (an 8-byte ASCII identifier for the type) and a `u16` **version**, so decoding a payload against the wrong type or an old/new format fails immediately with a typed error rather than misparsing silently. See [`architecture.md#serialization`](architecture.md#serialization) for the pattern and [`technical-manual.md#serialization-format`](technical-manual.md#serialization-format) for the full byte-level reference.

## Where this stands today

Everything described above is the *target* shape of the API and the math it's meant to implement — and the API shapes, types, and planning logic (circuits, BSGS, RNS structure, protocol session/share handling) are real. What's **not** yet real, in the current alpha, is a lot of the actual cryptographic content behind those shapes: encryption is transparent in several places, some "keys" are placeholders, and bootstrapping's `EvalMod` stage is an identity function. None of this is hidden — [SECURITY.md](../SECURITY.md) lists the current gaps per crate, and [`technical-manual.md`](technical-manual.md) documents precisely what each operation does today versus what it's meant to do. Read both before building anything that assumes real security.
