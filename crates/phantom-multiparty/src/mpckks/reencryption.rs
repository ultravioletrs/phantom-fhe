//! CKKS re-encryption from threshold shares scaffold.

use phantom_schemes::ckks::{Ciphertext, CkksParams};

use super::wire::{decode_ciphertext, encode_ciphertext, ensure_equal_payloads};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Re-encryption helper for CKKS threshold workflows.
#[derive(Clone, Debug)]
pub struct ReEncryptor {
    params: CkksParams,
    session: SessionState,
}

impl ReEncryptor {
    /// Creates a re-encryptor.
    pub const fn new(params: CkksParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates a transparent re-encryption share.
    pub fn create_share(
        &self,
        participant: ParticipantId,
        ciphertext: &Ciphertext,
    ) -> Result<Share> {
        if ciphertext.slots().len() > self.params.slot_count() {
            return Err(MultipartyError::MalformedMessage);
        }
        Share::new(
            &self.session,
            participant,
            ShareKind::ReEncryption,
            encode_ciphertext(ciphertext),
        )
    }

    /// Aggregates re-encryption shares into a fresh transparent ciphertext.
    pub fn aggregate_ciphertext(&self, aggregator: &ShareAggregator) -> Result<Ciphertext> {
        let shares = aggregator.aggregate()?;
        let payload = ensure_equal_payloads(&shares)?;
        decode_ciphertext(payload, self.params.slot_count())
    }
}
