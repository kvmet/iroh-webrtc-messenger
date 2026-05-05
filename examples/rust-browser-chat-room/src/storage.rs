use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use crate::crypto::{decrypt_data, encrypt_data};
use crate::state::{RoomMode, RoomState};

const STORAGE_ENC: &str = "iroh.id.enc";
const STORAGE_SALT: &str = "iroh.id.salt";
const STORAGE_NAME: &str = "iroh.name";
const STORAGE_PROFILE: &str = "iroh.profile";

fn local_storage() -> std::result::Result<web_sys::Storage, JsValue> {
    web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .local_storage()
        .map_err(|_| JsValue::from_str("localStorage unavailable"))?
        .ok_or_else(|| JsValue::from_str("localStorage is null"))
}

pub(crate) fn load_stored() -> Option<(Vec<u8>, Vec<u8>)> {
    let s = local_storage().ok()?;
    let enc = BASE64.decode(s.get_item(STORAGE_ENC).ok()??).ok()?;
    let salt = BASE64.decode(s.get_item(STORAGE_SALT).ok()??).ok()?;
    Some((enc, salt))
}

pub(crate) fn persist(enc: &[u8], salt: &[u8]) -> std::result::Result<(), JsValue> {
    let s = local_storage()?;
    s.set_item(STORAGE_ENC, &BASE64.encode(enc))
        .map_err(|_| JsValue::from_str("write failed"))?;
    s.set_item(STORAGE_SALT, &BASE64.encode(salt))
        .map_err(|_| JsValue::from_str("write failed"))
}

pub(crate) fn forget_stored() {
    if let Ok(s) = local_storage() {
        let _ = s.remove_item(STORAGE_ENC);
        let _ = s.remove_item(STORAGE_SALT);
        let _ = s.remove_item(STORAGE_NAME);
        let _ = s.remove_item(STORAGE_PROFILE);
    }
}

pub(crate) fn stored_name() -> String {
    local_storage()
        .ok()
        .and_then(|s| s.get_item(STORAGE_NAME).ok().flatten())
        .unwrap_or_else(|| "AIM User".to_string())
}

pub(crate) fn save_name(name: &str) {
    if let Ok(s) = local_storage() {
        let _ = s.set_item(STORAGE_NAME, name);
    }
}

/// Bump when we restructure the [`Profile`] schema in a way that
/// can't be expressed by additive `#[serde(default)]` fields.
const PROFILE_VERSION_CURRENT: u32 = 1;

fn profile_version_default() -> u32 { 1 }

/// One persisted room. **Stability contract**: never remove or rename a
/// field. New fields must be added with `#[serde(default)]`.
#[derive(Serialize, Deserialize)]
struct RoomSave {
    #[serde(default)]
    topic_b64: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    hosting: bool,
    #[serde(default)]
    bootstrap_peers: Vec<String>,
}

/// The full encrypted-at-rest user profile.
///
/// **Stability contract**:
/// - Never remove or rename a field. Use `#[serde(default)]` for adds.
/// - Bump [`PROFILE_VERSION_CURRENT`] only for restructuring changes
///   that pure additive defaults can't handle.
/// - Old data missing the version field deserializes as version 1.
#[derive(Serialize, Deserialize)]
pub(crate) struct Profile {
    #[serde(default = "profile_version_default")]
    version: u32,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    rooms: Vec<RoomSave>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            version: PROFILE_VERSION_CURRENT,
            name: String::new(),
            rooms: Vec::new(),
        }
    }
}

impl Profile {
    /// Reconstruct `RoomState`s from the stored snapshot. Bad base64 entries
    /// are dropped rather than promoted to the all-zero ghost topic.
    pub(crate) fn into_rooms(self) -> (String, Vec<RoomState>) {
        let rooms = self.rooms
            .into_iter()
            .filter_map(|s| {
                let topic_bytes: [u8; 32] = BASE64.decode(&s.topic_b64).ok()?.try_into().ok()?;
                Some(RoomState {
                    topic_id: iroh_gossip::TopicId::from_bytes(topic_bytes).to_string(),
                    topic_bytes,
                    name: s.name,
                    mode: if s.hosting { RoomMode::Hosting } else { RoomMode::Joined },
                    messages: vec![],
                    participants: vec![],
                    names: std::collections::HashMap::new(),
                    joined: false,
                    bootstrap_peers: s.bootstrap_peers,
                })
            })
            .collect();
        (self.name, rooms)
    }
}

pub(crate) async fn save_profile(name: &str, rooms: &[RoomState], key_bytes: &[u8; 32]) {
    let saves: Vec<RoomSave> = rooms.iter().map(|r| RoomSave {
        topic_b64: BASE64.encode(r.topic_bytes),
        name: r.name.clone(),
        hosting: r.mode == RoomMode::Hosting,
        bootstrap_peers: r.bootstrap_peers.clone(),
    }).collect();
    let profile = Profile {
        version: PROFILE_VERSION_CURRENT,
        name: name.to_string(),
        rooms: saves,
    };
    let Ok(json) = serde_json::to_vec(&profile) else { return };
    let Ok(enc) = encrypt_data(&json, key_bytes).await else { return };
    if let Ok(s) = local_storage() {
        let _ = s.set_item(STORAGE_PROFILE, &BASE64.encode(&enc));
        let _ = s.remove_item(STORAGE_NAME); // clean plaintext leftover
    }
}

pub(crate) async fn load_profile(key_bytes: &[u8; 32]) -> Profile {
    let Ok(s) = local_storage() else { return Profile::default() };
    let Some(b64) = s.get_item(STORAGE_PROFILE).ok().flatten() else { return Profile::default() };
    let Ok(enc) = BASE64.decode(&b64) else { return Profile::default() };
    let Ok(json) = decrypt_data(&enc, key_bytes).await else { return Profile::default() };
    serde_json::from_slice(&json).unwrap_or_default()
}

// ── Backup export / import ────────────────────────────────────────────────────

/// On-disk backup file format. **Stability contract**: same as Profile —
/// never remove or rename a field, add new ones with `#[serde(default)]`,
/// bump version only for restructures.
#[derive(Serialize, Deserialize)]
struct Backup {
    #[serde(default)]
    format: String,
    #[serde(default = "backup_version_default")]
    version: u32,
    /// base64 of the raw `iroh.id.enc` localStorage value (already
    /// versioned + encrypted by the crypto layer).
    #[serde(default)]
    id_enc: String,
    #[serde(default)]
    id_salt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}

fn backup_version_default() -> u32 { 1 }

const BACKUP_FORMAT_TAG: &str = "iroh-messenger-backup";

/// Pull the encrypted identity (and profile, if any) out of localStorage
/// as a self-contained JSON document. Returns None if there's nothing
/// persisted to back up.
pub(crate) fn export_backup() -> Option<String> {
    let s = local_storage().ok()?;
    let id_enc = s.get_item(STORAGE_ENC).ok().flatten()?;
    let id_salt = s.get_item(STORAGE_SALT).ok().flatten()?;
    let profile = s.get_item(STORAGE_PROFILE).ok().flatten();
    let backup = Backup {
        format: BACKUP_FORMAT_TAG.into(),
        version: 1,
        id_enc,
        id_salt,
        profile,
    };
    serde_json::to_string_pretty(&backup).ok()
}

/// Write a backup JSON document into localStorage. The user still needs
/// their original passphrase to actually unlock the imported identity.
pub(crate) fn import_backup(json: &str) -> Result<(), String> {
    let backup: Backup = serde_json::from_str(json).map_err(|e| format!("invalid backup: {e}"))?;
    if backup.format != BACKUP_FORMAT_TAG {
        return Err("not a recognized backup file".into());
    }
    if backup.version > 1 {
        return Err(format!("unsupported backup version {}", backup.version));
    }
    if backup.id_enc.is_empty() || backup.id_salt.is_empty() {
        return Err("backup is missing identity data".into());
    }
    let s = local_storage().map_err(|_| "localStorage unavailable".to_string())?;
    s.set_item(STORAGE_ENC, &backup.id_enc).map_err(|_| "write failed".to_string())?;
    s.set_item(STORAGE_SALT, &backup.id_salt).map_err(|_| "write failed".to_string())?;
    if let Some(p) = backup.profile {
        s.set_item(STORAGE_PROFILE, &p).map_err(|_| "write failed".to_string())?;
    } else {
        let _ = s.remove_item(STORAGE_PROFILE);
    }
    Ok(())
}
