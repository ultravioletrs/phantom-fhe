//! CKKS collective relinearization-key generation scaffold.

use phantom_lattice::rlwe::RelinearizationKey;

use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::Result;

/// Collective relinearization-key generation helper.
#[derive(Clone, Debug)]
pub struct RelinearizationKeyGen {
    session: SessionState,
}

impl RelinearizationKeyGen {
    /// Creates a relinearization-key generation helper.
    pub const fn new(session: SessionState) -> Self {
        Self { session }
    }

    /// Creates an RKG share.
    pub fn create_share(&self, participant: ParticipantId) -> Result<Share> {
        Share::new(
            &self.session,
            participant,
            ShareKind::RelinearizationKeyGen,
            participant.get().to_le_bytes().to_vec(),
        )
    }

    /// Aggregates RKG shares into a placeholder relinearization key.
    pub fn aggregate_key(&self, aggregator: &ShareAggregator) -> Result<RelinearizationKey> {
        let _shares = aggregator.aggregate()?;
        Ok(RelinearizationKey)
    }
}
