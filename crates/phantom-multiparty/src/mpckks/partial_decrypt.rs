//! CKKS partial decryption scaffold.

use phantom_schemes::ckks::{Ciphertext, CkksParams, Plaintext};

use super::wire::{decode_ciphertext, encode_ciphertext, ensure_equal_payloads};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Partial decryption helper for CKKS threshold workflows.
#[derive(Clone, Debug)]
pub struct PartialDecryptor {
    params: CkksParams,
    session: SessionState,
}

impl PartialDecryptor {
    /// Creates a partial decryptor.
    pub const fn new(params: CkksParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates a transparent partial decryption share.
    pub fn create_share(
        &self,
        participant: ParticipantId,
        ciphertext: &Ciphertext,
    ) -> Result<Share> {
        self.check_ciphertext(ciphertext)?;
        Share::new(
            &self.session,
            participant,
            ShareKind::PartialDecryption,
            encode_ciphertext(ciphertext),
        )
    }

    /// Aggregates partial decryptions into a CKKS plaintext.
    pub fn aggregate_plaintext(&self, aggregator: &ShareAggregator) -> Result<Plaintext> {
        let shares = aggregator.aggregate()?;
        let payload = ensure_equal_payloads(&shares)?;
        let ciphertext = decode_ciphertext(payload, self.params.slot_count())?;
        self.check_ciphertext(&ciphertext)?;
        Ok(Plaintext::new(
            ciphertext.slots().to_vec(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
        ))
    }

    fn check_ciphertext(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.slots().len() > self.params.slot_count() {
            return Err(MultipartyError::MalformedMessage);
        }
        if self.params.conjugate_invariant() && ciphertext.slots().iter().any(|slot| slot.im != 0.0)
        {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(())
    }
}
