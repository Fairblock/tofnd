//! This module handles the recover gRPC.
//! Request includes [proto::message_in::Data::KeygenInit] struct and encrypted recovery info.
//! The recovery info is decrypted by party's mnemonic seed and saved in the KvStore.

use super::{keygen::types::KeygenInitSanitized, proto, service::Gg20Service, types::PartyInfo};
use tofn::{
    collections::TypedUsize,
    gg20::keygen::{
     recover_party_keypair_unsafe, KeygenPartyId, SecretKeyShare,
        SecretRecoveryKey,
    },
    sdk::api::{deserialize, BytesVec, PartyShareCounts},
};

// logging
use tracing::{info, warn};

// error handling
use crate::TofndResult;
use anyhow::anyhow;

use std::convert::TryInto;

impl Gg20Service {

    /// attempt to write recovered secret key shares to the kv-store
    async fn update_share_kv_store(
        &self,
        keygen_init_sanitized: KeygenInitSanitized,
        secret_key_shares: Vec<SecretKeyShare>,
    ) -> TofndResult<()> {
        // try to make a reservation
        let reservation = self
            .kv_manager
            .kv()
            .reserve_key(keygen_init_sanitized.new_key_uid)
            .await
            .map_err(|err| anyhow!("failed to complete reservation: {}", err))?;
        // acquire kv-data
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init_sanitized.party_uids,
            keygen_init_sanitized.party_share_counts,
            keygen_init_sanitized.my_index,
        );
        // try writing the data to the kv-store
        self.kv_manager
            .kv()
            .put(reservation, kv_data.try_into()?)
            .await
            .map_err(|err| anyhow!("failed to update kv store: {}", err))
    }
}
