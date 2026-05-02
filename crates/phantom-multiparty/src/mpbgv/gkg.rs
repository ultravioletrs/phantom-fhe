//! BGV collective Galois-key generation scaffold.

use phantom_lattice::rlwe::GaloisKey;

use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::Result;

/// Collective Galois-key generation helper.
#[derive(Clone, Debug)]
pub struct GaloisKeyGen {
    session: SessionState,
    elements: Vec<usize>,
}

impl GaloisKeyGen {
    /// Creates a GKG helper.
    pub fn new(session: SessionState, elements: Vec<usize>) -> Self {
        Self { session, elements }
    }

    /// Creates a GKG share.
    pub fn create_share(&self, participant: ParticipantId) -> Result<Share> {
        Share::new(
            &self.session,
            participant,
            ShareKind::GaloisKeyGen,
            participant.get().to_le_bytes().to_vec(),
        )
    }

    /// Aggregates GKG shares into placeholder Galois keys.
    pub fn aggregate_keys(&self, aggregator: &ShareAggregator) -> Result<Vec<GaloisKey>> {
        let _shares = aggregator.aggregate()?;
        Ok(self.elements.iter().copied().map(GaloisKey::new).collect())
    }
}
