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

#[derive(Serialize, Deserialize)]
struct RoomSave {
    topic_b64: String,
    name: String,
    hosting: bool,
    #[serde(default)]
    bootstrap_peers: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct Profile {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    rooms: Vec<RoomSave>,
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
    let profile = Profile { name: name.to_string(), rooms: saves };
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
