//! BFV re-encryption from threshold shares scaffold.

use phantom_schemes::bfv::{BfvParams, Ciphertext};
use phantom_schemes::bgv;

use super::wire::{decode_poly, encode_poly, ensure_equal_payloads};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Re-encryption helper for BFV threshold workflows.
#[derive(Clone, Debug)]
pub struct ReEncryptor {
    params: BfvParams,
    session: SessionState,
}

impl ReEncryptor {
    /// Creates a re-encryptor.
    pub const fn new(params: BfvParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates a transparent re-encryption share.
    pub fn create_share(
        &self,
        participant: ParticipantId,
        ciphertext: &Ciphertext,
    ) -> Result<Share> {
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
            ShareKind::ReEncryption,
            encode_poly(component),
        )
    }

    /// Aggregates re-encryption shares into a fresh transparent ciphertext.
    pub fn aggregate_ciphertext(&self, aggregator: &ShareAggregator) -> Result<Ciphertext> {
        let shares = aggregator.aggregate()?;
        let payload = ensure_equal_payloads(&shares)?;
        let poly = decode_poly(payload, self.params.ring())?;
        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![poly]),
        )))
    }
}
