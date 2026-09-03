//! Pedersen VSS commitments and shares: what actually crosses the wire
//! between dealer and recipient, plus verification and accumulation.

use std::collections::BTreeSet;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use super::generators::PedersenGenerators;
use crate::common::ParticipantId;
use crate::{MultipartyError, Result};

/// One dealer's public commitments to their own [`super::VectorPolynomial`]:
/// `t` group elements, `C_0..C_{t-1}` (one per polynomial degree) - see
/// [`super::VectorPolynomial::commit`]'s own doc comment for how these are
/// computed. Broadcasting this (before any share goes out) is what makes
/// the scheme *verifiable*: every recipient checks their own share against
/// this same public value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VssCommitmentSet {
    dealer: ParticipantId,
    commitments: Vec<CompressedRistretto>,
}

impl VssCommitmentSet {
    pub(super) const fn new(dealer: ParticipantId, commitments: Vec<CompressedRistretto>) -> Self {
        Self {
            dealer,
            commitments,
        }
    }

    /// Returns the dealer this commitment set belongs to.
    pub const fn dealer(&self) -> ParticipantId {
        self.dealer
    }

    /// Returns the threshold `t` (one commitment per polynomial degree).
    pub fn threshold(&self) -> usize {
        self.commitments.len()
    }

    pub(super) fn commitments(&self) -> &[CompressedRistretto] {
        &self.commitments
    }

    /// Encodes deterministically: a tag, the dealer id, a length prefix,
    /// then each commitment's own 32 compressed bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PMVSC1");
        out.extend_from_slice(&self.dealer.get().to_le_bytes());
        out.extend_from_slice(&(self.commitments.len() as u64).to_le_bytes());
        for commitment in &self.commitments {
            out.extend_from_slice(commitment.as_bytes());
        }
        out
    }

    /// Decodes from [`Self::encode`]'s own format.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        reader.expect(b"PMVSC1")?;
        let dealer = ParticipantId::new(reader.u64()?)?;
        let count = reader.u64()? as usize;
        let mut commitments = Vec::with_capacity(count);
        for _ in 0..count {
            commitments.push(CompressedRistretto(reader.bytes32()?));
        }
        if !reader.is_finished() {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(Self {
            dealer,
            commitments,
        })
    }

    /// Combines several dealers' own commitment sets into a single set of
    /// `t` group elements, `sum_d C_d[k]` for each degree `k` - the public
    /// value a combiner checks a participant's own *combined* final share
    /// against (see [`verify_combined`]). Every input set must share the
    /// same threshold `t`; this combined result carries no single
    /// meaningful "dealer" (it is a sum over all of them), which is why it
    /// is returned as a plain `Vec<CompressedRistretto>`, not another
    /// [`VssCommitmentSet`].
    pub fn combine<'a>(
        sets: impl IntoIterator<Item = &'a VssCommitmentSet>,
    ) -> Result<Vec<CompressedRistretto>> {
        let mut iter = sets.into_iter();
        let first = iter.next().ok_or(MultipartyError::MissingShare)?;
        let mut combined: Vec<RistrettoPoint> = first
            .commitments
            .iter()
            .map(|c| c.decompress().ok_or(MultipartyError::MalformedMessage))
            .collect::<Result<_>>()?;
        for set in iter {
            if set.commitments.len() != combined.len() {
                return Err(MultipartyError::InvalidParameters(
                    "combine: threshold mismatch across commitment sets",
                ));
            }
            for (acc, c) in combined.iter_mut().zip(&set.commitments) {
                let point = c.decompress().ok_or(MultipartyError::MalformedMessage)?;
                *acc += point;
            }
        }
        Ok(combined.into_iter().map(|p| p.compress()).collect())
    }
}

/// The share one dealer sends to one recipient: `f_{dealer->recipient}`
/// (the vector-polynomial evaluated at `recipient`'s own id) plus the
/// aggregate blinding scalar needed to verify it against the dealer's own
/// [`VssCommitmentSet`] - see [`Self::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VssShare {
    dealer: ParticipantId,
    recipient: ParticipantId,
    values: Vec<Scalar>,
    blinding: Scalar,
}

impl VssShare {
    pub(super) const fn new(
        dealer: ParticipantId,
        recipient: ParticipantId,
        values: Vec<Scalar>,
        blinding: Scalar,
    ) -> Self {
        Self {
            dealer,
            recipient,
            values,
            blinding,
        }
    }

    /// Returns the dealer this share came from.
    pub const fn dealer(&self) -> ParticipantId {
        self.dealer
    }

    /// Returns the intended recipient.
    pub const fn recipient(&self) -> ParticipantId {
        self.recipient
    }

    /// Returns the share's own vector value.
    pub fn values(&self) -> &[Scalar] {
        &self.values
    }

    /// Returns the share's own aggregate blinding scalar.
    pub const fn blinding(&self) -> Scalar {
        self.blinding
    }

    /// Verifies this share against `commitments` - errs with
    /// [`MultipartyError::InvalidVssShare`] if `commitments` don't belong to
    /// this share's own claimed dealer (guards against checking a share
    /// against the wrong dealer's public commitments) or if the Pedersen
    /// verification equation itself doesn't hold (a malicious/faulty dealer,
    /// or transport corruption).
    pub fn verify(
        &self,
        commitments: &VssCommitmentSet,
        generators: &PedersenGenerators,
    ) -> Result<()> {
        if self.dealer != commitments.dealer() {
            return Err(MultipartyError::InvalidVssShare);
        }
        verify_equation(
            Scalar::from(self.recipient.get()),
            &self.values,
            self.blinding,
            commitments.commitments(),
            generators,
        )
    }

    /// Encodes deterministically: a tag, dealer id, recipient id, a length
    /// prefix, then each value's own 32 bytes, then the blinding scalar's
    /// own 32 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PMVSH1");
        out.extend_from_slice(&self.dealer.get().to_le_bytes());
        out.extend_from_slice(&self.recipient.get().to_le_bytes());
        out.extend_from_slice(&(self.values.len() as u64).to_le_bytes());
        for value in &self.values {
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(self.blinding.as_bytes());
        out
    }

    /// Decodes from [`Self::encode`]'s own format.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        reader.expect(b"PMVSH1")?;
        let dealer = ParticipantId::new(reader.u64()?)?;
        let recipient = ParticipantId::new(reader.u64()?)?;
        let count = reader.u64()? as usize;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(reader.scalar()?);
        }
        let blinding = reader.scalar()?;
        if !reader.is_finished() {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(Self {
            dealer,
            recipient,
            values,
            blinding,
        })
    }
}

/// Verifies a participant's own *combined* final share (the sum of every
/// dealer's own share to them - see [`super::ShareAccumulator::finalize`])
/// against `combined_commitments` (see [`VssCommitmentSet::combine`]).
/// Unlike [`VssShare::verify`], there is no single "dealer" to cross-check
/// (a combined commitment set is a sum over all of them) - a combiner uses
/// this to catch a participant lying about their own final share, with the
/// identical underlying equation [`VssShare::verify`] itself uses.
pub fn verify_combined(
    participant: ParticipantId,
    values: &[Scalar],
    blinding: Scalar,
    combined_commitments: &[CompressedRistretto],
    generators: &PedersenGenerators,
) -> Result<()> {
    verify_equation(
        Scalar::from(participant.get()),
        values,
        blinding,
        combined_commitments,
        generators,
    )
}

/// The Pedersen VSS verification identity: `(sum_j g_j * values[j]) + h *
/// blinding == sum_k commitments[k] * x^k`. Exact by construction (proven
/// by substituting the commitment definition and expanding - see
/// [`super::VectorPolynomial::commit`]'s own doc comment), verified
/// numerically (Python) before implementing. Uses variable-time
/// multiscalar multiplication deliberately: every input here is already
/// public (a broadcast commitment, and a share whose own secrecy this
/// verification step doesn't need to preserve - the constant-time
/// operations happened earlier, at commitment/evaluation time, over the
/// dealer's own still-secret polynomial coefficients).
fn verify_equation(
    x: Scalar,
    values: &[Scalar],
    blinding: Scalar,
    commitments: &[CompressedRistretto],
    generators: &PedersenGenerators,
) -> Result<()> {
    if values.len() != generators.vector_len() {
        return Err(MultipartyError::InvalidParameters(
            "verify: value/generator length mismatch",
        ));
    }
    if commitments.is_empty() {
        return Err(MultipartyError::InvalidParameters(
            "verify: commitment set must be nonempty",
        ));
    }

    let mut lhs_scalars: Vec<Scalar> = values.to_vec();
    lhs_scalars.push(blinding);
    let mut lhs_points: Vec<RistrettoPoint> = generators.g().to_vec();
    lhs_points.push(generators.h());
    let lhs = RistrettoPoint::vartime_multiscalar_mul(&lhs_scalars, &lhs_points);

    let mut rhs_scalars = Vec::with_capacity(commitments.len());
    let mut rhs_points = Vec::with_capacity(commitments.len());
    let mut power = Scalar::ONE;
    for commitment in commitments {
        rhs_scalars.push(power);
        rhs_points.push(
            commitment
                .decompress()
                .ok_or(MultipartyError::MalformedMessage)?,
        );
        power *= x;
    }
    let rhs = RistrettoPoint::vartime_multiscalar_mul(&rhs_scalars, &rhs_points);

    if lhs == rhs {
        Ok(())
    } else {
        Err(MultipartyError::InvalidVssShare)
    }
}

/// Accumulates verified shares (from potentially many dealers) into one
/// participant's own final combined share - `Y_i = sum_d f_{d->i}`, `rho_i
/// = sum_d rho_{d->i}` - without ever assembling, or needing to know, the
/// full collective secret. Rejects a duplicate dealer (guards against a
/// dealer's share being counted twice, whether by accident or by a
/// malicious combiner) and any share that fails [`VssShare::verify`].
pub struct ShareAccumulator {
    participant: ParticipantId,
    sum_values: Vec<Scalar>,
    sum_blinding: Scalar,
    dealers_seen: BTreeSet<ParticipantId>,
}

impl ShareAccumulator {
    /// Creates an accumulator for `participant`'s own shares, expecting
    /// each dealer's share to carry a `vector_len`-length value vector.
    pub fn new(participant: ParticipantId, vector_len: usize) -> Self {
        Self {
            participant,
            sum_values: vec![Scalar::ZERO; vector_len],
            sum_blinding: Scalar::ZERO,
            dealers_seen: BTreeSet::new(),
        }
    }

    /// Verifies `share` against `commitments`, then accumulates it.
    pub fn add_verified_share(
        &mut self,
        share: &VssShare,
        commitments: &VssCommitmentSet,
        generators: &PedersenGenerators,
    ) -> Result<()> {
        if share.recipient() != self.participant {
            return Err(MultipartyError::UnknownParticipant);
        }
        if share.values().len() != self.sum_values.len() {
            return Err(MultipartyError::InvalidParameters(
                "add_verified_share: vector length mismatch",
            ));
        }
        if !self.dealers_seen.insert(share.dealer()) {
            return Err(MultipartyError::DuplicateParticipant);
        }
        share.verify(commitments, generators)?;
        for (accumulated, value) in self.sum_values.iter_mut().zip(share.values()) {
            *accumulated += value;
        }
        self.sum_blinding += share.blinding();
        Ok(())
    }

    /// Returns the number of distinct dealers accumulated so far.
    pub fn dealer_count(&self) -> usize {
        self.dealers_seen.len()
    }

    /// Returns this participant's own final combined share, `(Y_i,
    /// rho_i)`.
    pub fn finalize(&self) -> (Vec<Scalar>, Scalar) {
        (self.sum_values.clone(), self.sum_blinding)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        if self.input.get(self.offset..self.offset + expected.len()) != Some(expected) {
            return Err(MultipartyError::MalformedMessage);
        }
        self.offset += expected.len();
        Ok(())
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn bytes32(&mut self) -> Result<[u8; 32]> {
        let bytes = self.take(32)?;
        Ok(bytes.try_into().unwrap())
    }

    fn scalar(&mut self) -> Result<Scalar> {
        let bytes = self.bytes32()?;
        Option::from(Scalar::from_canonical_bytes(bytes)).ok_or(MultipartyError::MalformedMessage)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MultipartyError::MalformedMessage)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(MultipartyError::MalformedMessage)?;
        self.offset = end;
        Ok(bytes)
    }
}
