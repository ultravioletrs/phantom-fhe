//! BFV partial decryption scaffold.

use phantom_schemes::bfv::{BfvParams, Ciphertext, Plaintext};
use phantom_schemes::bgv;

use super::wire::{decode_poly, encode_poly, ensure_equal_payloads};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Partial decryption helper for BFV threshold workflows.
#[derive(Clone, Debug)]
pub struct PartialDecryptor {
    params: BfvParams,
    session: SessionState,
}

impl PartialDecryptor {
    /// Creates a partial decryptor.
    pub const fn new(params: BfvParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates a transparent partial decryption share.
    pub fn create_share(
        &self,
        participant: ParticipantId,
        ciphertext: &Ciphertext,
    ) -> Result<Share> {
        self.session.check_participant(participant)?;
        let component = ciphertext
            .inner()
            .inner()
            .value()
            .first()
            .ok_or(MultipartyError::MalformedMessage)?;
        self.params
            .ring()
            .check_poly(component)
            .map_err(|_| MultipartyError::MalformedMessage)?;
        Share::new(
            &self.session,
            participant,
            ShareKind::PartialDecryption,
            encode_poly(component),
        )
    }

    /// Aggregates partial decryptions into a plaintext.
    pub fn aggregate_plaintext(&self, aggregator: &ShareAggregator) -> Result<Plaintext> {
        let shares = aggregator.aggregate()?;
        let payload = ensure_equal_payloads(&shares)?;
        let poly = decode_poly(payload, self.params.ring())?;
        Ok(Plaintext::new(bgv::Plaintext::new(
            phantom_lattice::rlwe::Plaintext::new(poly),
        )))
    }
}
