//! BFV interactive bootstrapping scaffold.

use phantom_schemes::bfv::{BfvParams, Ciphertext};
use phantom_schemes::bgv;

use super::wire::{decode_poly, encode_poly, ensure_equal_payloads};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Interactive bootstrapping helper for BFV threshold workflows.
#[derive(Clone, Debug)]
pub struct InteractiveBootstrap {
    params: BfvParams,
    session: SessionState,
}

impl InteractiveBootstrap {
    /// Creates an interactive bootstrap helper.
    pub const fn new(params: BfvParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates a transparent interactive bootstrap share.
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
            ShareKind::InteractiveBootstrap,
            encode_poly(component),
        )
    }

    /// Aggregates interactive bootstrap shares into a refreshed transparent ciphertext.
    pub fn aggregate_refreshed(&self, aggregator: &ShareAggregator) -> Result<Ciphertext> {
        let shares = aggregator.aggregate()?;
        let payload = ensure_equal_payloads(&shares)?;
        let poly = decode_poly(payload, self.params.ring())?;
        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![poly]),
        )))
    }
}
