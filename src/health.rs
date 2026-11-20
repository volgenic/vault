//! Whether each credential of a kind with an entry in `kinds` works, has expired or was refused,
//! as the upstream's replies said (token upkeep, R39). Kept by secret id and version, so a
//! replaced or renewed value starts again at `unknown`. Names, states, times and statuses only:
//! never a value (R4). The daemon keeps the book in memory and writes it to `health.json` in the
//! vault folder when a state changes, so it survives a restart.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::kinds::{self, HealthState};
use crate::model::VaultDoc;
use crate::protocol::CredentialHealth;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    version: u64,
    state: HealthState,
    at: String,
    status: Option<u16>,
    /// Why, when the kind's reply said more than its status (`KindSpec::reason`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct HealthBook {
    entries: BTreeMap<String, Entry>,
}

impl HealthBook {
    pub fn from_json(bytes: &[u8]) -> HealthBook {
        serde_json::from_slice(bytes).unwrap_or_default()
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Records what a reply said about version `version` of secret `id`. Returns whether the
    /// state changed (the caller writes the book then).
    ///
    /// A refusal from the token server (`Refused`) stays for its version until a reply says the
    /// token works: a later 401 at the same version (`Expired`) doesn't hide that the login is
    /// gone, nor let the vault try its dead refresh token again.
    pub fn observe(
        &mut self,
        id: &str,
        version: u64,
        state: HealthState,
        status: Option<u16>,
        reason: Option<&str>,
        at: String,
    ) -> bool {
        let refused = self.entries.get(id).is_some_and(|old| old.version == version && old.state == HealthState::Refused);
        if refused && state != HealthState::Works {
            return false;
        }
        let reason = reason.map(str::to_string);
        let entry = Entry { version, state, at, status, reason: reason.clone() };
        match self.entries.insert(id.to_string(), entry) {
            Some(old) => old.version != version || old.state != state || old.reason != reason,
            None => true,
        }
    }

    /// What the book holds for version `version` of secret `id`, if anything.
    pub fn state_of(&self, id: &str, version: u64) -> Option<HealthState> {
        self.entries.get(id).filter(|entry| entry.version == version).map(|entry| entry.state)
    }

    /// Every credential of a kind with an entry in `kinds`, in the vault's order, with what the
    /// book knows of its current version. Entries of deleted secrets are left out. A credential
    /// past its expiry at `now` that no reply refused is `expired`: the vault couldn't renew it
    /// (or, unclaimed, may not), so the person signs in again unless a renewal still works.
    pub(crate) fn report(&self, doc: &VaultDoc, now: u64) -> Vec<CredentialHealth> {
        doc.records
            .iter()
            .filter_map(|record| kinds::spec(record.kind).map(|spec| (record, spec)))
            .map(|(record, spec)| {
                let known = self.entries.get(&record.id).filter(|entry| entry.version == record.version);
                let state = known.map_or(HealthState::Unknown, |entry| entry.state);
                let past_expiry = record.expires_at.is_some_and(|at| at <= now);
                let refresh = match (&spec.refresher, &record.handover) {
                    (None, _) => "never",
                    (Some(_), Some(handover)) if !handover.claimed => "awaiting_claim",
                    (Some(_), _) => "by_vault",
                };
                CredentialHealth {
                    id: record.id.clone(),
                    name: record.name.clone(),
                    kind: record.kind,
                    version: record.version,
                    state: if past_expiry && state != HealthState::Refused { HealthState::Expired } else { state },
                    checked_at: known.map(|entry| entry.at.clone()),
                    status: known.and_then(|entry| entry.status),
                    reason: known.and_then(|entry| entry.reason.clone()),
                    refresh: refresh.into(),
                    expires_at: record.expires_at,
                }
            })
            .collect()
    }

    /// Drops the entries of secrets no longer in the vault.
    pub(crate) fn prune(&mut self, doc: &VaultDoc) -> bool {
        let before = self.entries.len();
        self.entries.retain(|id, _| doc.records.iter().any(|record| &record.id == id));
        self.entries.len() != before
    }
}
