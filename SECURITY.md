# Security Policy

## Current Status

Phantom-FHE is a research-stage implementation, roughly **TRL 2–3** (technology concept formulated; experimental proof of concept). The full architecture — ring arithmetic, RLWE/RGSW primitives, BGV/BFV/CKKS schemes, homomorphic circuits, CKKS bootstrapping, and multiparty threshold protocols — is implemented, tested end-to-end, and documented (see `docs/technical-manual.md` for the precise per-operation reference). Cryptographic hardening toward production strength is in progress under a tracked roadmap (`docs/internal/implementation-plan.md`).

The following components are not yet at production cryptographic strength:

- `phantom-ring::sampling::sample_discrete_gaussian` is a real discrete
  Gaussian (CDT-based) but is not constant-time.
- `phantom-lattice::rlwe` now samples real Gaussian encryption error
  (`phantom_lattice::security::STANDARD_ERROR_STD_DEV`, the
  homomorphicencryption.org community-standard σ≈3.2) into both key
  generation and encryption, with worst-case noise-growth bounds in
  `phantom_lattice::noise`. `phantom_lattice::rlwe::{generate_key_switch_key,
  key_switch}` are now a real RNS hybrid key-switch (the modern
  RNS-CKKS-era technique, not a textbook simplification), and both
  `Evaluator::relinearize` (given `KeyGenerator::generate_hybrid_relinearization_key`)
  and `Evaluator::apply_galois_automorphism` (given
  `KeyGenerator::generate_hybrid_galois_key`) do real work when given a real
  key - but every scheme crate above `phantom-lattice` (BGV, BFV, CKKS,
  multiparty) still only constructs the identity-preserving placeholder keys
  (`RelinearizationKey::placeholder()`, `GaloisKey::new`), since none of
  them yet have a concept of the auxiliary `P` moduli a real key needs, so
  both operations still behave as a no-op in practice for every scheme
  (`Evaluator::rotate_coefficients`, the raw-coefficient placeholder BGV's
  evaluator still calls directly, is unaffected). Noise tracking itself is a
  sound-but-loose worst-case bound, not a tight probabilistic one, and
  key-switching's own noise contribution doesn't yet have a
  formally-derived bound (only an empirically-set test threshold).
- `phantom-lattice::rgsw` now encrypts real gadget matrices (the standard
  GSW/RGSW construction) instead of the earlier plaintext-backed scaffold,
  with a real external product and its own noise bound in
  `phantom_lattice::noise::external_product_noise_bound` - but RGSW
  ciphertexts aren't yet consumed anywhere (no bootstrapping construction
  built on top), and, like the rest of `phantom-lattice::rlwe`, its noise
  tracking is a sound-but-loose worst-case bound.
- `phantom-schemes::bgv` and `phantom-schemes::bfv` each now have a real,
  noise-bearing encryption path
  (`Encryptor::with_secret_key_real`/`with_public_key_real`) alongside
  their original transparent one - every existing caller
  (`phantom-circuits`, `phantom-bootstrapping`, `phantom-multiparty`) still
  only constructs the transparent (non-encrypted) path, since their toy
  ring parameters have no headroom for real noise and haven't been
  migrated yet; `phantom-examples` additionally has two dedicated
  real-path workflows (`bgv_real_basic`/`bfv_real_basic`) at
  realistically-sized parameters, kept separate from its toy-preset
  examples rather than a migration of them. BGV's real path needs
  noise scaled by the plaintext modulus `t` and a matching real public key
  (`BgvKeyGenerator::generate_keypair_real`); BFV's real path scales the
  *message* by `Delta = floor(Q/t)` instead and reuses a standard public
  key unchanged - genuinely different math, not a relabeling (the
  pre-existing "BFV" scheme, before this, was actually just BGV's own
  exact scheme reused directly, with no Δ-scaling anywhere). Real BGV
  relinearization isn't wired up either (would need the key-switching
  key's own noise scaled by the plaintext modulus too, not just fresh
  encryption's). BFV now also has real multiplication
  (`Evaluator::mul_real`, alongside encrypt/decrypt and ciphertext-ciphertext
  add/sub/neg) - a full tensor-and-rescale procedure computed in an
  auxiliary basis large enough to avoid wraparound, using new general
  bignum/bignum division (`phantom_ring::bignum::BigUint::divmod`) for the
  rescale step's rounding. BFV's plaintext operations are also both real
  now: new `Evaluator::add_plain_real` scales its plaintext operand by
  `Delta` first (needed, since `add_plain`'s raw-add behavior is wrong for a
  real ciphertext), while `mul_plain` needed no separate real path at all -
  multiplying by a small unscaled plaintext doesn't have addition's
  problem, verified numerically. BFV can now also relinearize
  `mul_real`'s degree-2 output back to degree 1
  (`Evaluator::relinearize_real`, `BfvKeyGenerator::generate_hybrid_relinearization_key`)
  - a direct reuse of `phantom_lattice::rlwe`'s existing real key-switching
  machinery, safe for BFV since it has no `t`-scaled-noise requirement.
  **BGV's own relinearization is real now too**
  (`Evaluator::relinearize_real`, `BgvKeyGenerator::generate_relinearization_key_real`),
  but needed a genuinely different construction from BFV's: BFV's
  key-switching key would be unsafe for BGV's own real ciphertexts (its
  noise isn't a multiple of `t`, so using it - or even a version with its
  noise naively scaled by `t` - silently corrupts BGV's mod-`t` invariant,
  verified numerically before ruling it out). BGV's relinearization key
  (`phantom-schemes::bgv::relinearization::BgvRelinearizationKey`) instead
  uses classical (power-of-base) gadget decomposition, which has no
  division/rounding step to corrupt `t`-scaled noise the way the RNS hybrid
  technique's `mod_down` does - verified to recover the exact product (not
  just within a noise bound) across 30 randomized trials. BGV also has a
  real RNS modulus-switching path now (`ModulusSwitcher::switch_next_real`,
  alongside the original clone-only `switch_next`), with the same
  not-yet-migrated caller situation as everything else here. **Gap found
  while writing cross-operation tests (Workstream 5 item 7), root-caused
  and fixed since:** `Evaluator::modulus_switch_next_real`, applied to
  `Evaluator::relinearize_real`'s own output, used to produce an incorrect
  plaintext for a ring with more than one auxiliary modulus - switching a
  *fresh* (non-relinearized) real ciphertext, and relinearizing without a
  subsequent switch, were both already independently correct.

  **Root cause**: not a BGV-specific interaction bug, but a soundness gap
  in the *shared* `phantom_lattice::rgsw::GadgetDecomposition` primitive
  (used by both BGV's classical relinearization and RGSW's external
  product) whenever the ring has more than one RNS modulus.
  `GadgetDecomposition::decompose` extracted each digit via
  `(coeff >> shift) & mask` applied independently to *every RNS
  component's own residue* - for coefficient value `x` with residues
  `x mod q_0`, `x mod q_1`, ..., it bit-sliced `x mod q_0` and `x mod q_1`
  *separately*, producing a digit polynomial whose `q_0`-component and
  `q_1`-component were base-`B` digits of two *different* numbers (the two
  unrelated residues), not of a single common small value. `decompose`
  still `recompose`d correctly *per modulus* (`sum_i digit_i[j]*B^i ≡ c[j]
  (mod q_j)` holds independently for each `j`, verified directly), so a
  ciphertext's first-modulus component alone (all `BatchEncoder::decode_u64`
  ever reads) still decoded correctly after relinearization on its own -
  exactly why `real_relinearization_reduces_degree_and_preserves_the_product_exactly`
  passed even before the fix. But the digit polynomial carried no
  meaningful CRT-consistent value once more than one modulus was involved,
  so the ciphertext's *other* RNS components ended up holding noise
  uncorrelated with the first modulus's - invisible to `decode_u64` (which
  only ever reads the first component) until `modulus_switch_down`
  explicitly combined *all* components via CRT reconstruction to rescale,
  at which point the incoherent extra components corrupted the result.
  Confirmed directly: reconstructing `relinearize_real`'s own output
  across its full RNS basis
  (`phantom_ring::rns::extension::reconstruct_centered_values`, the same
  primitive `mod_down`/`modulus_switch_down` use internally) gave a value
  many orders of magnitude larger than the noise bound
  `bgv::noise::relinearize_noise_bound` predicted, while the first
  modulus's own component alone matched that bound closely - and neither
  `phantom-lattice`'s own `GadgetDecomposition` tests
  (`phase4_rgsw.rs`, `randomized.rs`) nor BGV's single-modulus
  relinearization test had ever exercised a multi-modulus ring, so this
  had never been caught before.

  **Fixed** with a CRT-coherent redesign of `GadgetDecomposition` itself:
  each RNS modulus is now its own gadget "level" (one digit block per
  modulus, base-`B` sub-split within it, matching how a production
  RNS-BGV/CKKS library structures the same construction), each block
  scaled by the new `phantom_ring::rns::extension::crt_lift_constant`
  (`(Q/q_j) * ((Q/q_j)^{-1} mod q_j)`) so the digits reconstruct via the
  standard CRT identity instead of independent per-component bit-slicing.
  For a single-modulus ring this reduces exactly to the previous
  construction (`crt_lift_constant == 1`), so every existing single-modulus
  BGV/RGSW test still passes unchanged. Verified: the derivation itself in
  Python first (100 randomized trials of the full decompose→key-material→
  recombine identity across 2-4 moduli, 200 trials of the plain
  decompose/recompose round trip), then in Rust - new `crt_lift_constant`
  tests, a new `phantom-lattice/tests/rgsw_multi_modulus.rs` proving RGSW's
  external product on a multi-modulus ring (never exercised before), and a
  new `cross_operations.rs::bgv_real_pipeline_encrypt_add_multiply_relinearize_switch_and_serialize`
  reproducing the exact originally-broken chain end to end. Both schemes
  now also have noise/error estimate functions (`bgv::noise`/`bfv::noise`,
  plus `BgvContext`/`BfvContext::noise_budget_bits` and
  `fresh_*_noise_budget_bits` convenience wrappers) - unlike CKKS's
  `Precision` (a real per-ciphertext field), these are standalone
  parameter-driven estimates, since neither scheme's real `Ciphertext` type
  carries any noise metadata of its own. They cover fresh encryption and
  raw multiplication for both schemes, plus relinearization for BGV
  specifically (whose classical gadget-decomposition key-switch has a
  derivable bound); BFV's (and CKKS's) relinearization/key-switching noise
  contribution remains unbounded, the same gap noted above for
  `phantom_lattice::rlwe`'s hybrid key-switching generally.
- `phantom-schemes::ckks` still has its original approximate encoding
  (`Encoder::encode_complex`/`decode_complex`) and transparent
  `Ciphertext`/`Encryptor`/`Decryptor` as its default path - the actual
  slot values are still carried in the clear - but its `Precision`
  bookkeeping is now derived from real noise analysis (new `ckks::noise`,
  the same triangle-inequality style `phantom_lattice::noise` already uses
  for BGV/BFV/RGSW, adapted to CKKS's canonical-embedding/scale setting)
  rather than the flat illustrative constants (`degrade(0.25)`,
  `degrade(1.0)`) every `Evaluator` operation used before - see
  `ckks::noise`'s own module doc comment for the per-operation formulas
  and what's deliberately still left unmodeled (relinearization's and
  Galois key-switching's own noise contribution, since
  `phantom_lattice::rlwe`'s hybrid key-switching doesn't have a
  formally-derived noise bound of its own yet either - the same gap noted
  above for BGV/BFV). `phantom-schemes::ckks` also now has a full real
  ciphertext/encryption/arithmetic path alongside the transparent one:
  `Encoder::encode_complex_real`/`decode_complex_real`
  round-trip slots through a `phantom_ring::Poly` rather than carrying them
  in the clear (`Plaintext`'s `Option`-typed `poly` field), and
  `Ciphertext` gained the same kind of `Option`-typed real RLWE
  representation. `Encryptor::encrypt_real`/`Decryptor::decrypt_real` do
  genuine RLWE encryption/decryption (structurally BFV's own real path,
  since CKKS's message is already `Delta`-scaled by the encoder rather than
  needing per-operation scaling), and `Evaluator::{add,sub,neg,add_plain,mul,relinearize,rotate,conjugate,rescale_next}_real`
  do genuine ring arithmetic - `add`/`sub`/`neg`/`add_plain`/`mul` (raw
  tensor, no relinearization) are direct pass-throughs to
  `phantom_lattice::rlwe::Evaluator`, `relinearize_real` reuses the same
  real hybrid key-switching machinery BFV's relinearization does,
  `rotate_real`/`conjugate_real` apply a real Galois automorphism (only
  correct because the encoder assigns slot `j` to embedding exponent `5^j
  mod 2N`, not simpler sequential indexing, which a brute-force check
  found cannot support single-Galois-element rotation at all), and
  `rescale_next_real` drops the ciphertext's last RNS component via the
  existing `phantom_ring::rns::rescale::mod_down` primitive and divides the
  tracked `Scale` to match - CKKS has no plaintext-modulus invariant to
  protect the way BGV's own rescale does, so a plain floor division
  suffices. Real CKKS multiplication needs no BFV-style extended-basis
  tensor-and-rescale procedure: its mod-`Q` tensor product is already
  exactly what the *next*, separate rescale step needs. `phantom-circuits`
  now has one real evaluator built on this path -
  `ckks::PolynomialEvaluator::evaluate_encrypted`, a Horner-method
  polynomial evaluator against an actual encrypted ciphertext (also needed
  a new `mul_plain_real` and a level-aware
  `CkksKeyGenerator::generate_hybrid_relinearization_key_at_level`,
  neither of which existed before) - `phantom-bootstrapping`/
  `phantom-multiparty` and every other `phantom-circuits` CKKS evaluator
  still only construct the transparent (non-encrypted) path, the same
  not-yet-migrated situation as BGV/BFV's own real paths above;
  `phantom-examples` additionally has a dedicated real-path workflow
  (`ckks_real_basic`), the same as BGV/BFV's own two. Conjugate-invariant
  real packing and an NTT/FFT fast path for encode/decode remain
  unimplemented.
- `phantom-bootstrapping::ckks`'s EvalMod stage now performs genuine scaled
  centered-modular reduction, both as a transparent scaffold
  (`EvalMod::reduce_mod_q`) and as a real, homomorphically-evaluable
  polynomial approximation over an adjustable, genuinely complex-valued
  domain (`EvalMod::reduce_mod_q_real`/`reduce_mod_q_real_wide`/
  `reduce_mod_q_real_complex_wide`, a degree-17 odd-polynomial fit to the
  standard sin-based technique, widened via angle-doubling and split into
  independent real/imaginary reduction via conjugation), each removing an
  unknown multiple of a configurable `raise_modulus` and verified to
  recover a message from a modulus-raised-looking input. `CoeffsToSlots`/
  `SlotsToCoeffs` also have real evaluators now, rebuilt from real CKKS
  bootstrapping's own CoeffToSlot/SlotToCoeff construction
  (Cheon-Han-Kim-Kim-Song, EUROCRYPT 2018) after an earlier, generic-DFT-based
  version was found not to correspond to that operation at all - the
  corrected version produces **two** ciphertexts holding a ciphertext's own
  raw ring coefficients directly, verified against real encryption, not
  just transparently. `Bootstrapper::bootstrap_real`/`bootstrap_real_wide`
  compose all three real stages end to end on an actual encrypted
  ciphertext, including real bootstrapping's own modulus-raise step
  (`ckks::Evaluator::raise_level_real`, bringing a nearly-exhausted
  ciphertext's modulus back up to a full top-level chain) - verified to
  recover a message through the full real pipeline starting from a
  **genuine** `raise_level_real` output, not just an engineered wraparound
  (`bootstrap_real_wide_recovers_a_message_through_a_genuine_raise_level_real`
  in `phantom-bootstrapping/tests/phase12_ckks_bootstrapping.rs`, robust
  across several independent RNG seeds). This is the digit-extraction half
  of bootstrapping, not the whole circuit: `bootstrap_real`/
  `bootstrap_real_wide` still require their input already be at the raised
  level this pipeline expects (the caller runs `raise_level_real` itself
  first), and the caller must derive `BootstrapParams::raise_modulus`
  correctly (`q0/Delta`, the raised ciphertext's own lowest modulus divided
  by its tracked scale - `q0` itself needs to sit several bits above `Delta`
  to leave room for a non-negligible message) rather than passing the raw
  `q0` - both `Evaluator::raise_level_real`'s and
  `EvalMod::reduce_mod_q_real_wide`'s own doc comments state this
  precisely. BGV/BFV bootstrapping modules are reserved but unimplemented.
- `phantom-multiparty` protocols have not had an adversarial security
  review. `mpbgv::CollectiveKeyGen`, `mpbgv::GaloisKeyGen`, and
  `mpbgv::ReEncryptor` are real: each participant generates an ordinary
  small RLWE secret independently (never transmitted or assembled by
  anyone, including the infrastructure aggregating shares), contributes a
  public, `t`-scaled share to a genuine collective BGV public key and to a
  genuine collective rotation key, and later contributes a real
  collaborative key-switching (PCKS) share to re-encrypt a ciphertext
  toward a separate recipient's own key - additive n-of-n throughout
  (every contributing participant, not a threshold subset; deliberately
  not a weaker t-of-n variant - see `docs/internal/implementation-plan.md`'s
  Workstream 7 item 5b for why). `RelinearizationKeyGen`, `PartialDecryptor`,
  and `mpbgv`'s own `InteractiveBootstrap` still use byte-equality
  aggregation (`ensure_equal_payloads`) or return placeholder key material
  regardless of shares, not real cryptographic combination; `mpbfv`/`mpckks`
  have not yet had their own `CollectiveKeyGen`/`GaloisKeyGen`/`ReEncryptor`
  wired to real key material at all. `ReEncryptor`'s own smudging noise
  (`mpbgv::reencryption::SMUDGING_ERROR_STD_DEV`) is a documented
  placeholder, not a rigorously calibrated statistical-hiding bound - that
  calibration is Workstream 7 item 5a's own job, still open.
  `phantom_multiparty::vss` is a real, tested Pedersen
  verifiable-secret-sharing distributed-key-generation primitive
  (Ristretto255-based; no party or aggregating infrastructure ever
  assembles the full secret, and a dealer sending inconsistent shares to
  different recipients is cryptographically detected) - composable with
  `CollectiveKeyGen`/`ReEncryptor` (all three draw on the same
  per-participant local secret, demonstrated together in
  `phantom-multiparty/tests/phase14_mpbgv.rs`) but not itself required for
  either's own correctness; it remains genuinely useful for a different,
  not-yet-attempted purpose (giving participants a verifiable backup of
  each other's own secrets, for future fault-tolerance work). The
  transcript hash used for protocol transcripts
  (`phantom_multiparty::common::transcript::stable_hash_256`) is now
  SHA-256 (`sha2`), not the hand-rolled mixer earlier versions of this
  document described.
- All example and test parameter presets (see
  `docs/user-guide.md#choosing-parameters`) are small development sizes
  chosen for fast iteration, not production security margins. Every
  `BgvParams`/`BfvParams`/`CkksParams` builder now has an opt-in
  `.require_128_bit_security()` that checks a ring degree/total
  ciphertext-modulus-bits combination against the
  homomorphicencryption.org security standard's own published table
  (`phantom_lattice::security::max_secure_total_modulus_bits_128`) - but
  it's opt-in, not the `build()` default, precisely because every preset
  above would otherwise fail to build at all (their ring degrees are far
  below the table's smallest covered entry). The builders do
  unconditionally reject a small set of always-wrong settings regardless
  of security level (duplicate ciphertext moduli; for BGV/BFV, a
  plaintext modulus not coprime to every ciphertext modulus) - genuine
  correctness bugs, not a security-margin judgment call.

For the precise, per-operation account of what each of the above means in
code, see `docs/technical-manual.md`. This status is expected to change
substantially as the hardening roadmap executes; **this implementation
should not be relied on for production security until these items are
resolved.**

## Reporting a Vulnerability

Because the project has not yet reached a security-reviewed state, most
cryptographic weaknesses are already known and tracked in
`docs/internal/implementation-plan.md` rather than being reportable surprises. Still, if
you find:

- a memory-safety or panic-safety issue reachable from public APIs,
- a logic bug that breaks correctness guarantees the current implementation
  does claim (for example, a documented round-trip or test that can be
  broken with valid inputs), or
- a supply-chain or build-process concern,

please open a GitHub issue with a minimal reproduction. If the issue is
sensitive (for example, it affects a downstream consumer who has already
deployed a preset from this repository), contact the maintainer directly
instead of filing a public issue.

## Scope Boundary

Reports about the *absence* of production hardening that is already listed
in `docs/internal/implementation-plan.md` (real noise management, optimized NTT/RNS,
secure parameter sets, protocol security review, etc.) are welcome as
general feedback but are not treated as new vulnerabilities - they are
tracked, expected gaps at this stage of the project.
