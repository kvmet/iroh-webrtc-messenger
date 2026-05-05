use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use iroh::PublicKey;
use js_sys::{Array, Function, Promise, Reflect};
use qrcode::{QrCode, render::svg};
use std::str::FromStr;
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

fn url_encode(s: &str) -> String {
    js_sys::encode_uri_component(s).as_string().unwrap_or_default()
}

fn url_decode(s: &str) -> String {
    js_sys::decode_uri_component(s)
        .ok()
        .and_then(|j| j.as_string())
        .unwrap_or_else(|| s.to_string())
}

/// Parsed invite: (topic_bytes, host_endpoint, optional proposed room name).
/// Accepts either the bare `topic_b64|endpoint[|name]` payload or a full URL
/// ending in that hash.
///
/// **Stability contract**: the format is positional pipe-separated. Adding
/// a 4th positional field would silently break older parsers (the trailing
/// segment would be appended to `name`). If a future version needs more
/// fields, prefix the whole thing with a version tag (e.g. `v2:...`) so
/// this parser fails cleanly on the topic decode and surfaces a clear
/// "Invalid invite link" error instead of a quiet misparse.
///
/// Trailing segments beyond the third are explicitly ignored so that a
/// future v1+ extension can append optional data without breaking us.
pub(crate) fn parse_invite(invite: &str) -> Option<([u8; 32], String, Option<String>)> {
    let payload = invite.find('#').map_or(invite, |i| &invite[i + 1..]).trim();
    let mut parts = payload.split('|');
    let topic_b64 = parts.next()?;
    let host = parts.next()?.trim();
    if host.is_empty() {
        return None;
    }
    let name = parts.next().map(url_decode).filter(|s| !s.is_empty());
    Some((decode_topic_b64(topic_b64)?, host.to_string(), name))
}

pub(crate) fn make_invite_url(
    topic_bytes: [u8; 32],
    endpoint_id: &str,
    room_name: &str,
) -> Option<String> {
    let loc = web_sys::window()?.location();
    let origin = loc.origin().ok()?;
    let path = loc.pathname().ok()?;
    let name_part = if room_name.is_empty() {
        String::new()
    } else {
        format!("|{}", url_encode(room_name))
    };
    Some(format!("{}{}#{}|{}{}", origin, path, BASE64.encode(topic_bytes), endpoint_id, name_part))
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

/// Trigger a browser download of `content` as `filename`. Uses a data URL
/// + synthetic anchor click — no extra web-sys features needed.
pub(crate) fn download_text(filename: &str, content: &str) {
    let Some(window) = web_sys::window() else { return };
    let Some(doc) = window.document() else { return };
    let Ok(el) = doc.create_element("a") else { return };
    let encoded = js_sys::encode_uri_component(content)
        .as_string()
        .unwrap_or_default();
    let data_url = format!("data:application/json;charset=utf-8,{}", encoded);
    let _ = el.set_attribute("href", &data_url);
    let _ = el.set_attribute("download", filename);
    let a: web_sys::HtmlElement = el.unchecked_into();
    a.click();
}

/// Generates a small SVG identity icon for an endpoint using a bishop-walk
/// ("drunken bishop") algorithm: the same technique OpenSSH uses for key art.
/// The walk path produces a unique glyph; the hue and saturation come from
/// the key bytes so each identity gets a consistent color family.
///
/// Safe to render via `Html::from_html_unchecked`: only integer coordinates
/// and HSL values derived from `u8` arithmetic appear in the output.
pub(crate) fn endpoint_icon_svg(endpoint: &str) -> String {
    let bytes: [u8; 32] = PublicKey::from_str(endpoint)
        .map(|pk| *pk.as_bytes())
        .unwrap_or_else(|_| {
            let mut h = [0u8; 32];
            for (i, b) in endpoint.bytes().enumerate() {
                h[i % 32] ^= b;
            }
            h
        });

    // Bishop walk on a 9×9 grid.
    let mut field = [[0u8; 9]; 9];
    let (mut cx, mut cy) = (4usize, 4usize);
    for &byte in bytes.iter() {
        for shift in [0u8, 2, 4, 6] {
            let dx: isize = if (byte >> shift) & 1 == 0 { -1 } else { 1 };
            let dy: isize = if (byte >> (shift + 1)) & 1 == 0 { -1 } else { 1 };
            cx = (cx as isize + dx).clamp(0, 8) as usize;
            cy = (cy as isize + dy).clamp(0, 8) as usize;
            if field[cy][cx] < 14 {
                field[cy][cx] += 1;
            }
        }
    }

    // Color from key bytes: hue spans full circle, saturation in 55–80%.
    let hue = (bytes[0] as f32) * 360.0 / 256.0;
    let sat = 55 + (bytes[1] % 26) as u32;

    // viewBox 0 0 9 9, rendered at 18×18 px via width/height attributes.
    let mut s = format!(
        r#"<svg width="18" height="18" viewBox="0 0 9 9" xmlns="http://www.w3.org/2000/svg" style="display:block;image-rendering:pixelated">"#
    );
    s.push_str(&format!(
        r#"<rect width="9" height="9" fill="hsl({hue:.0},{sat}%,92%)"/>"#
    ));
    for row in 0..9usize {
        for col in 0..9usize {
            let v = field[row][col];
            if v > 0 {
                // More visits → darker cell (lightness 75% down to 25%).
                let l = 75u32.saturating_sub(v as u32 * 5);
                s.push_str(&format!(
                    r#"<rect x="{col}" y="{row}" width="1" height="1" fill="hsl({hue:.0},{sat}%,{l}%)"/>"#
                ));
            }
        }
    }
    s.push_str("</svg>");
    s
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
