//! CKKS interactive bootstrapping scaffold.

use phantom_bootstrapping::ckks::{
    BootstrapKeyGenerator, BootstrapParams, Bootstrapper as CentralBootstrapper,
};
use phantom_schemes::ckks::{Ciphertext, CkksParams};

use super::wire::{decode_ciphertext, encode_ciphertext, ensure_equal_payloads};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Interactive bootstrapping helper for CKKS threshold workflows.
#[derive(Clone, Debug)]
pub struct InteractiveBootstrap {
    params: CkksParams,
    bootstrap_params: BootstrapParams,
    session: SessionState,
}

impl InteractiveBootstrap {
    /// Creates an interactive bootstrap helper.
    pub const fn new(
        params: CkksParams,
        bootstrap_params: BootstrapParams,
        session: SessionState,
    ) -> Self {
        Self {
            params,
            bootstrap_params,
            session,
        }
    }

    /// Creates a transparent interactive bootstrap share.
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
            ShareKind::InteractiveBootstrap,
            encode_ciphertext(ciphertext),
        )
    }

    /// Aggregates interactive bootstrap shares and applies the CKKS bootstrap scaffold.
    pub fn aggregate_refreshed(&self, aggregator: &ShareAggregator) -> Result<Ciphertext> {
        let shares = aggregator.aggregate()?;
        let payload = ensure_equal_payloads(&shares)?;
        let ciphertext = decode_ciphertext(payload, self.params.slot_count())?;
        let key = BootstrapKeyGenerator::new(self.bootstrap_params.clone()).generate(&[]);
        CentralBootstrapper::new(self.bootstrap_params.clone(), key)
            .bootstrap(&ciphertext)
            .map_err(|_| MultipartyError::MalformedMessage)
    }
}
