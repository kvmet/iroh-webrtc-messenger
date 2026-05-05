use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use js_sys::{Array, Function, Promise, Reflect};
use qrcode::{QrCode, render::svg};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, spawn_local};

pub(crate) const MAX_BOOTSTRAP_PEERS: usize = 20;

pub(crate) fn add_known_peer(peers: &mut Vec<String>, ep: &str) {
    if peers.iter().any(|p| p == ep) {
        return;
    }
    if peers.len() >= MAX_BOOTSTRAP_PEERS {
        peers.remove(0);
    }
    peers.push(ep.to_string());
}

pub(crate) fn truncate_chars(s: &mut String, max: usize) {
    if s.chars().count() > max {
        let cutoff = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
        s.truncate(cutoff);
    }
}

pub(crate) fn decode_topic_b64(s: &str) -> Option<[u8; 32]> {
    BASE64.decode(s).ok()?.try_into().ok()
}

/// Parse an invite into (topic_bytes, host_endpoint). Accepts either the bare
/// `topic_b64|endpoint` payload or a full URL ending in that hash.
pub(crate) fn parse_invite(invite: &str) -> Option<([u8; 32], String)> {
    let payload = invite.find('#').map_or(invite, |i| &invite[i + 1..]).trim();
    let (topic_b64, host) = payload.split_once('|')?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some((decode_topic_b64(topic_b64)?, host.to_string()))
}

pub(crate) fn make_invite_url(topic_bytes: [u8; 32], endpoint_id: &str) -> Option<String> {
    let loc = web_sys::window()?.location();
    let origin = loc.origin().ok()?;
    let path = loc.pathname().ok()?;
    Some(format!("{}{}#{}|{}", origin, path, BASE64.encode(topic_bytes), endpoint_id))
}

pub(crate) fn make_qr_svg(text: &str) -> Option<String> {
    let code = QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .build(),
    )
}

pub(crate) fn copy_to_clipboard(text: &str) {
    let text = text.to_string();
    spawn_local(async move {
        let Some(window) = web_sys::window() else { return };
        let Ok(nav) = Reflect::get(&window, &"navigator".into()) else { return };
        let Ok(clipboard) = Reflect::get(&nav, &"clipboard".into()) else { return };
        let Ok(write_text) = Reflect::get(&clipboard, &"writeText".into()) else { return };
        let func: Function = write_text.unchecked_into();
        let Ok(promise) = Reflect::apply(&func, &clipboard, &Array::of1(&text.into())) else { return };
        let _ = JsFuture::from(promise.unchecked_into::<Promise>()).await;
    });
}
