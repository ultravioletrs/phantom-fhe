//! BFV collective public-key generation scaffold.

use phantom_lattice::rlwe::PublicKey;
use phantom_schemes::bfv::BfvParams;

use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::Result;

/// Collective public-key generation helper.
#[derive(Clone, Debug)]
pub struct CollectiveKeyGen {
    params: BfvParams,
    session: SessionState,
}

impl CollectiveKeyGen {
    /// Creates a collective key-generation helper.
    pub const fn new(params: BfvParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates a public CKG share for `participant`.
    pub fn create_share(&self, participant: ParticipantId) -> Result<Share> {
        Share::new(
            &self.session,
            participant,
            ShareKind::CollectiveKeyGen,
            participant.get().to_le_bytes().to_vec(),
        )
    }

    /// Aggregates CKG shares into a placeholder public key.
    pub fn aggregate_public_key(&self, aggregator: &ShareAggregator) -> Result<PublicKey> {
        let _shares = aggregator.aggregate()?;
        let zero = self.params.ring().zero();
        Ok(PublicKey::new(zero.clone(), zero))
    }
}
