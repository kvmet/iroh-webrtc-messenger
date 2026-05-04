use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use bytes::Bytes;
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_gossip::{
    TopicId,
    api::{Event as GossipEvent, GossipSender},
    net::{GOSSIP_ALPN, Gossip},
};
use iroh_webrtc_transport::{
    Error, Result,
    browser::{
        BrowserDialTransportPreference, BrowserProtocol, BrowserProtocolHandle, BrowserWebRtcNode,
        BrowserWebRtcNodeConfig,
    },
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use qrcode::{QrCode, render::svg};
use n0_future::{StreamExt, task};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{HtmlElement, HtmlInputElement, HtmlTextAreaElement, TextEncoder};
use yew::prelude::*;

const STORAGE_ENC: &str = "iroh.id.enc";
const STORAGE_SALT: &str = "iroh.id.salt";
const STORAGE_NAME: &str = "iroh.name";
const STORAGE_PROFILE: &str = "iroh.profile";

// ── Entry point ───────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn start_app() {
    console_error_panic_hook::set_once();
    iroh_webrtc_transport::browser::install_browser_console_tracing();
    let root = web_sys::window()
        .expect("no window")
        .document()
        .expect("no document")
        .get_element_by_id("app")
        .expect("missing #app element");
    yew::Renderer::<App>::with_root(root).render();
}

// ── localStorage helpers ──────────────────────────────────────────────────────

fn local_storage() -> std::result::Result<web_sys::Storage, JsValue> {
    web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .local_storage()
        .map_err(|_| JsValue::from_str("localStorage unavailable"))?
        .ok_or_else(|| JsValue::from_str("localStorage is null"))
}

fn load_stored() -> Option<(Vec<u8>, Vec<u8>)> {
    let s = local_storage().ok()?;
    let enc = BASE64.decode(s.get_item(STORAGE_ENC).ok()??).ok()?;
    let salt = BASE64.decode(s.get_item(STORAGE_SALT).ok()??).ok()?;
    Some((enc, salt))
}

fn persist(enc: &[u8], salt: &[u8]) -> std::result::Result<(), JsValue> {
    let s = local_storage()?;
    s.set_item(STORAGE_ENC, &BASE64.encode(enc))
        .map_err(|_| JsValue::from_str("write failed"))?;
    s.set_item(STORAGE_SALT, &BASE64.encode(salt))
        .map_err(|_| JsValue::from_str("write failed"))
}

fn forget_stored() {
    if let Ok(s) = local_storage() {
        let _ = s.remove_item(STORAGE_ENC);
        let _ = s.remove_item(STORAGE_SALT);
    }
}

fn stored_name() -> String {
    local_storage()
        .ok()
        .and_then(|s| s.get_item(STORAGE_NAME).ok().flatten())
        .unwrap_or_else(|| "AIM User".to_string())
}

fn save_name(name: &str) {
    if let Ok(s) = local_storage() {
        let _ = s.set_item(STORAGE_NAME, name);
    }
}

// ── Web Crypto ────────────────────────────────────────────────────────────────

async fn aes_key(
    passphrase: &str,
    salt: &[u8],
    usage: &str,
) -> std::result::Result<web_sys::CryptoKey, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let subtle = window.crypto()?.subtle();

    let pass_bytes = Uint8Array::from(TextEncoder::new()?.encode_with_input(passphrase).as_slice());
    let derive_usages = Array::of1(&JsValue::from_str("deriveKey"));
    let key_material: web_sys::CryptoKey = JsFuture::from(subtle.import_key_with_str(
        "raw",
        pass_bytes.unchecked_ref::<Object>(),
        "PBKDF2",
        false,
        &derive_usages,
    )?)
    .await?
    .dyn_into()?;

    let pbkdf2 = Object::new();
    Reflect::set(&pbkdf2, &"name".into(), &"PBKDF2".into())?;
    Reflect::set(&pbkdf2, &"salt".into(), &Uint8Array::from(salt))?;
    Reflect::set(&pbkdf2, &"iterations".into(), &JsValue::from(600_000u32))?;
    Reflect::set(&pbkdf2, &"hash".into(), &"SHA-256".into())?;

    let aes_spec = Object::new();
    Reflect::set(&aes_spec, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&aes_spec, &"length".into(), &JsValue::from(256u32))?;

    let key_usages = Array::of1(&JsValue::from_str(usage));
    JsFuture::from(subtle.derive_key_with_object_and_object(
        &pbkdf2,
        &key_material,
        &aes_spec,
        false,
        &key_usages,
    )?)
    .await?
    .dyn_into()
}

async fn encrypt_key(
    key_bytes: &[u8; 32],
    passphrase: &str,
) -> std::result::Result<(Vec<u8>, Vec<u8>), JsValue> {
    let crypto = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?;

    let salt_arr = Uint8Array::new_with_length(16);
    crypto.get_random_values_with_array_buffer_view(&salt_arr)?;
    let salt = salt_arr.to_vec();

    let iv_arr = Uint8Array::new_with_length(12);
    crypto.get_random_values_with_array_buffer_view(&iv_arr)?;
    let iv = iv_arr.to_vec();

    let cipher_key = aes_key(passphrase, &salt, "encrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv.as_slice()))?;

    let subtle = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?
        .subtle();
    let ct = JsFuture::from(subtle.encrypt_with_object_and_buffer_source(
        &params,
        &cipher_key,
        &Uint8Array::from(key_bytes.as_slice()),
    )?)
    .await?;

    let mut encrypted = iv;
    encrypted.extend_from_slice(&Uint8Array::new(&ct).to_vec());
    Ok((encrypted, salt))
}

async fn decrypt_key(
    encrypted: &[u8],
    salt: &[u8],
    passphrase: &str,
) -> std::result::Result<[u8; 32], JsValue> {
    if encrypted.len() < 13 {
        return Err(JsValue::from_str("ciphertext too short"));
    }
    let iv = &encrypted[..12];
    let ct = &encrypted[12..];

    let cipher_key = aes_key(passphrase, salt, "decrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv))?;

    let subtle = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?
        .subtle();
    let pt = JsFuture::from(subtle.decrypt_with_object_and_buffer_source(
        &params,
        &cipher_key,
        &Uint8Array::from(ct),
    )?)
    .await?;

    Uint8Array::new(&pt)
        .to_vec()
        .try_into()
        .map_err(|_| JsValue::from_str("decrypted key has wrong length"))
}

async fn raw_aes_key(key_bytes: &[u8; 32], usage: &str) -> std::result::Result<web_sys::CryptoKey, JsValue> {
    let subtle = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .crypto()?
        .subtle();
    let arr = Uint8Array::from(key_bytes.as_slice());
    let usages = Array::of1(&JsValue::from_str(usage));
    JsFuture::from(subtle.import_key_with_str("raw", arr.unchecked_ref::<Object>(), "AES-GCM", false, &usages)?)
        .await?
        .dyn_into()
}

async fn encrypt_data(data: &[u8], key_bytes: &[u8; 32]) -> std::result::Result<Vec<u8>, JsValue> {
    let crypto = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?.crypto()?;
    let iv_arr = Uint8Array::new_with_length(12);
    crypto.get_random_values_with_array_buffer_view(&iv_arr)?;
    let iv = iv_arr.to_vec();
    let cipher_key = raw_aes_key(key_bytes, "encrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv.as_slice()))?;
    let subtle = crypto.subtle();
    let ct = JsFuture::from(subtle.encrypt_with_object_and_buffer_source(
        &params, &cipher_key, &Uint8Array::from(data),
    )?).await?;
    let mut result = iv;
    result.extend_from_slice(&Uint8Array::new(&ct).to_vec());
    Ok(result)
}

async fn decrypt_data(encrypted: &[u8], key_bytes: &[u8; 32]) -> std::result::Result<Vec<u8>, JsValue> {
    if encrypted.len() < 13 {
        return Err(JsValue::from_str("ciphertext too short"));
    }
    let iv = &encrypted[..12];
    let ct = &encrypted[12..];
    let cipher_key = raw_aes_key(key_bytes, "decrypt").await?;
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv))?;
    let subtle = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?.crypto()?.subtle();
    let pt = JsFuture::from(subtle.decrypt_with_object_and_buffer_source(
        &params, &cipher_key, &Uint8Array::from(ct),
    )?).await?;
    Ok(Uint8Array::new(&pt).to_vec())
}

#[derive(Serialize, Deserialize)]
struct RoomSave {
    topic_b64: String,
    name: String,
    hosting: bool,
    #[serde(default)]
    bootstrap_peers: Vec<String>,
}

fn decode_topic_b64(s: &str) -> Option<[u8; 32]> {
    BASE64.decode(s).ok()?.try_into().ok()
}

/// Parse an invite into (topic_bytes, host_endpoint). Accepts either the bare
/// `topic_b64|endpoint` payload or a full URL ending in that hash.
fn parse_invite(invite: &str) -> Option<([u8; 32], String)> {
    let payload = invite.find('#').map_or(invite, |i| &invite[i + 1..]).trim();
    let (topic_b64, host) = payload.split_once('|')?;
    let host = host.trim();
    if host.is_empty() { return None; }
    Some((decode_topic_b64(topic_b64)?, host.to_string()))
}

fn make_invite_url(topic_bytes: [u8; 32], endpoint_id: &str) -> Option<String> {
    let loc = web_sys::window()?.location();
    let origin = loc.origin().ok()?;
    let path = loc.pathname().ok()?;
    Some(format!("{}{}#{}|{}", origin, path, BASE64.encode(topic_bytes), endpoint_id))
}

fn make_qr_svg(text: &str) -> Option<String> {
    let code = QrCode::new(text.as_bytes()).ok()?;
    Some(code.render::<svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build())
}

fn copy_to_clipboard(text: &str) {
    let text = text.to_string();
    spawn_local(async move {
        let Some(window) = web_sys::window() else { return };
        let Ok(nav) = js_sys::Reflect::get(&window, &"navigator".into()) else { return };
        let Ok(clipboard) = js_sys::Reflect::get(&nav, &"clipboard".into()) else { return };
        let Ok(write_text) = js_sys::Reflect::get(&clipboard, &"writeText".into()) else { return };
        let func: js_sys::Function = write_text.unchecked_into();
        let Ok(promise) = js_sys::Reflect::apply(&func, &clipboard, &js_sys::Array::of1(&text.into())) else { return };
        let _ = JsFuture::from(promise.unchecked_into::<js_sys::Promise>()).await;
    });
}

#[derive(Serialize, Deserialize, Default)]
struct Profile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    rooms: Vec<RoomSave>,
}

async fn save_profile(name: &str, rooms: &[RoomState], key_bytes: &[u8; 32]) {
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
        let _ = s.remove_item(STORAGE_NAME);  // clean plaintext leftover
    }
}

async fn load_profile(key_bytes: &[u8; 32]) -> Profile {
    let Ok(s) = local_storage() else { return Profile::default() };
    let Some(b64) = s.get_item(STORAGE_PROFILE).ok().flatten() else { return Profile::default() };
    let Ok(enc) = BASE64.decode(&b64) else { return Profile::default() };
    let Ok(json) = decrypt_data(&enc, key_bytes).await else { return Profile::default() };
    serde_json::from_slice(&json).unwrap_or_default()
}

// ── Wire limits ───────────────────────────────────────────────────────────────

const MAX_WIRE_BYTES: usize = 8192;
const MAX_NAME_CHARS: usize = 32;
const MAX_TEXT_CHARS: usize = 4000;
const MAX_BOOTSTRAP_PEERS: usize = 20;

fn add_known_peer(peers: &mut Vec<String>, ep: &str) {
    if peers.iter().any(|p| p == ep) { return; }
    if peers.len() >= MAX_BOOTSTRAP_PEERS {
        peers.remove(0);
    }
    peers.push(ep.to_string());
}

fn truncate_chars(s: &mut String, max: usize) {
    if s.chars().count() > max {
        let cutoff = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
        s.truncate(cutoff);
    }
}

// ── Gossip protocol ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ChatGossipCommand {
    Join {
        topic: String,
        peers: Vec<String>,
        endpoint: String,
        name: String,
    },
    Send {
        topic: String,
        from_endpoint: String,
        from_name: String,
        text: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ChatGossipEvent {
    Joined { topic: String },
    NeighborUp { topic: String, endpoint: String },
    NeighborDown { topic: String, endpoint: String },
    Chat { topic: String, from_endpoint: String, from_name: String, text: String },
    System { topic: String, text: String },
    Identify { topic: String, endpoint: String, name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ChatWireMessage {
    AboutMe { endpoint: String, name: String },
    Chat { from_endpoint: String, from_name: String, text: String },
}

#[derive(Debug, Clone)]
struct ChatGossipProtocol {
    gossip: Arc<StdMutex<Option<Gossip>>>,
    topics: Arc<StdMutex<HashMap<String, GossipSender>>>,
    events_tx: mpsc::UnboundedSender<ChatGossipEvent>,
    events_rx: Arc<AsyncMutex<mpsc::UnboundedReceiver<ChatGossipEvent>>>,
}

impl Default for ChatGossipProtocol {
    fn default() -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            gossip: Arc::new(StdMutex::new(None)),
            topics: Arc::new(StdMutex::new(HashMap::new())),
            events_tx,
            events_rx: Arc::new(AsyncMutex::new(events_rx)),
        }
    }
}

impl BrowserProtocol for ChatGossipProtocol {
    const ALPN: &'static [u8] = GOSSIP_ALPN;
    type Command = ChatGossipCommand;
    type Event = ChatGossipEvent;
    type Handler = Gossip;

    fn handler(&self, endpoint: Endpoint) -> Self::Handler {
        self.gossip(endpoint)
    }

    async fn handle_command(&self, command: Self::Command) -> Result<()> {
        match command {
            ChatGossipCommand::Join { topic, peers, endpoint, name } => {
                let topic_id = parse_topic(&topic)?;
                let peers = parse_peers(&peers)?;
                let gossip = self.existing_gossip()?;
                let topic_handle = gossip
                    .subscribe(topic_id, peers)
                    .await
                    .map_err(error_from_display)?;
                let (sender, mut receiver) = topic_handle.split();
                self.topics
                    .lock()
                    .expect("topics mutex poisoned")
                    .insert(topic.clone(), sender.clone());
                let events = self.events_tx.clone();
                let topic_for_task = topic.clone();
                let sender_for_task = sender.clone();
                let endpoint_for_task = endpoint.clone();
                let name_for_task = name.clone();
                task::spawn(async move {
                    while let Some(event) = receiver.next().await {
                        match event {
                            Ok(GossipEvent::NeighborUp(ep)) => {
                                let _ = events.send(ChatGossipEvent::NeighborUp {
                                    topic: topic_for_task.clone(),
                                    endpoint: ep.to_string(),
                                });
                                if let Err(e) = broadcast_wire(
                                    &sender_for_task,
                                    ChatWireMessage::AboutMe {
                                        endpoint: endpoint_for_task.clone(),
                                        name: name_for_task.clone(),
                                    },
                                )
                                .await
                                {
                                    let _ = events.send(ChatGossipEvent::System {
                                        topic: topic_for_task.clone(),
                                        text: format!("failed to announce: {e}"),
                                    });
                                }
                            }
                            Ok(GossipEvent::NeighborDown(ep)) => {
                                let _ = events.send(ChatGossipEvent::NeighborDown {
                                    topic: topic_for_task.clone(),
                                    endpoint: ep.to_string(),
                                });
                            }
                            Ok(GossipEvent::Received(msg)) => {
                                if msg.content.len() > MAX_WIRE_BYTES { continue; }
                                if let Ok(wire) =
                                    serde_json::from_slice::<ChatWireMessage>(&msg.content)
                                {
                                    match wire {
                                        ChatWireMessage::AboutMe { endpoint, mut name } => {
                                            truncate_chars(&mut name, MAX_NAME_CHARS);
                                            let _ = events.send(ChatGossipEvent::Identify {
                                                topic: topic_for_task.clone(),
                                                endpoint,
                                                name,
                                            });
                                        }
                                        ChatWireMessage::Chat { from_endpoint, mut from_name, mut text } => {
                                            truncate_chars(&mut from_name, MAX_NAME_CHARS);
                                            truncate_chars(&mut text, MAX_TEXT_CHARS);
                                            let _ = events.send(ChatGossipEvent::Chat {
                                                topic: topic_for_task.clone(),
                                                from_endpoint,
                                                from_name,
                                                text,
                                            });
                                        }
                                    }
                                }
                            }
                            Ok(GossipEvent::Lagged) => {
                                let _ = events.send(ChatGossipEvent::System {
                                    topic: topic_for_task.clone(),
                                    text: "missed gossip messages".into(),
                                });
                            }
                            Err(e) => {
                                let _ = events.send(ChatGossipEvent::System {
                                    topic: topic_for_task.clone(),
                                    text: format!("gossip error: {e}"),
                                });
                                break;
                            }
                        }
                    }
                    let _ = events.send(ChatGossipEvent::System {
                        topic: topic_for_task.clone(),
                        text: format!("left topic {topic_for_task}"),
                    });
                });
                let _ = self.events_tx.send(ChatGossipEvent::Joined { topic: topic.clone() });
                broadcast_wire(&sender, ChatWireMessage::AboutMe { endpoint, name }).await?;
            }
            ChatGossipCommand::Send { topic, from_endpoint, from_name, text } => {
                let sender = self
                    .topics
                    .lock()
                    .expect("topics mutex poisoned")
                    .get(&topic)
                    .cloned()
                    .ok_or_else(|| Error::WebRtc(format!("not joined to {topic}")))?;
                broadcast_wire(&sender, ChatWireMessage::Chat { from_endpoint, from_name, text })
                    .await?;
            }
        }
        Ok(())
    }

    async fn next_event(&self) -> Result<Option<Self::Event>> {
        Ok(self.events_rx.lock().await.recv().await)
    }
}

impl ChatGossipProtocol {
    fn gossip(&self, endpoint: Endpoint) -> Gossip {
        let mut g = self.gossip.lock().expect("gossip mutex poisoned");
        if let Some(g) = g.as_ref() {
            return g.clone();
        }
        let spawned = Gossip::builder().spawn(endpoint);
        *g = Some(spawned.clone());
        spawned
    }

    fn existing_gossip(&self) -> Result<Gossip> {
        self.gossip
            .lock()
            .expect("gossip mutex poisoned")
            .clone()
            .ok_or_else(|| Error::WebRtc("gossip not yet registered".into()))
    }
}

async fn broadcast_wire(sender: &GossipSender, msg: ChatWireMessage) -> Result<()> {
    let encoded = serde_json::to_vec(&msg)
        .map_err(|e| Error::WebRtc(format!("encode error: {e}")))?;
    sender.broadcast(Bytes::from(encoded)).await.map_err(error_from_display)
}

fn parse_topic(topic: &str) -> Result<TopicId> {
    TopicId::from_str(topic).map_err(error_from_display)
}

fn parse_peers(peers: &[String]) -> Result<Vec<EndpointId>> {
    peers
        .iter()
        .map(|p| EndpointId::from_str(p).map_err(error_from_display))
        .collect()
}

fn error_from_display(e: impl std::fmt::Display) -> Error {
    Error::WebRtc(e.to_string())
}

// ── App state types ───────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum AppPhase {
    Checking,
    NeedPassphrase,
    NewUser,
    SpawningNode([u8; 32]),
    Ready,
    Failed(String),
}

struct NodeHandle {
    _node: BrowserWebRtcNode,
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    endpoint_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RoomMode {
    Hosting,
    Joined,
}

#[derive(Clone, PartialEq)]
struct RoomState {
    topic_id: String,
    topic_bytes: [u8; 32],
    name: String,
    mode: RoomMode,
    messages: Vec<ChatMsg>,
    participants: Vec<String>,
    names: HashMap<String, String>,
    joined: bool,
    bootstrap_peers: Vec<String>,
}

#[derive(Clone, PartialEq, Default)]
struct AppState {
    rooms: Vec<RoomState>,
    active_topic: Option<String>,
    /// Bootstrap value from the encrypted profile; ChatRoom owns the live name state.
    name: String,
    join_error: Option<String>,
}

enum Action {
    SetInitial(AppState),
    AddRoom(RoomState),
    SetActive(String),
    LocalSend { topic: String, msg: ChatMsg },
    Joined(String),
    NeighborUp { topic: String, endpoint: String },
    NeighborDown { topic: String, endpoint: String },
    RecvChat { topic: String, from_endpoint: String, from_name: String, text: String },
    System { topic: String, text: String },
    Identify { topic: String, endpoint: String, name: String },
    SetJoinError(Option<String>),
}

impl Reducible for AppState {
    type Action = Action;
    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        let mut s = (*self).clone();
        match action {
            Action::SetInitial(new_state) => return Rc::new(new_state),
            Action::AddRoom(r) => {
                s.join_error = None;
                if s.rooms.iter().any(|x| x.topic_id == r.topic_id) {
                    s.active_topic = Some(r.topic_id);
                } else {
                    s.active_topic = Some(r.topic_id.clone());
                    s.rooms.push(r);
                }
            }
            Action::SetActive(topic) => {
                s.active_topic = Some(topic);
            }
            Action::LocalSend { topic, msg } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    r.messages.push(msg);
                }
            }
            Action::Joined(topic) => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    r.joined = true;
                }
            }
            Action::NeighborUp { topic, endpoint } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    if !r.participants.contains(&endpoint) {
                        r.participants.push(endpoint.clone());
                    }
                    add_known_peer(&mut r.bootstrap_peers, &endpoint);
                }
            }
            Action::NeighborDown { topic, endpoint } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    r.participants.retain(|p| p != &endpoint);
                    let display = r.names.get(&endpoint).cloned()
                        .unwrap_or_else(|| {
                            let short: String = endpoint.chars().take(12).collect();
                            format!("{short}…")
                        });
                    r.messages.push(sys_msg(&format!("*** {display} left")));
                }
            }
            Action::RecvChat { topic, from_endpoint, from_name, text } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    // Pin name on first sighting; later messages can't rename a peer
                    r.names.entry(from_endpoint.clone()).or_insert_with(|| from_name.clone());
                    r.messages.push(ChatMsg { from_endpoint, from_name, text, is_system: false });
                }
            }
            Action::System { topic, text } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    r.messages.push(sys_msg(&text));
                }
            }
            Action::Identify { topic, endpoint, name } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    add_known_peer(&mut r.bootstrap_peers, &endpoint);
                    // First Identify wins; ignore later renames to prevent impersonation
                    if !r.names.contains_key(&endpoint) {
                        r.names.insert(endpoint, name.clone());
                        r.messages.push(sys_msg(&format!("*** {name} joined")));
                    }
                }
            }
            Action::SetJoinError(err) => {
                s.join_error = err;
            }
        }
        Rc::new(s)
    }
}

#[derive(Clone, PartialEq)]
struct ChatMsg {
    from_endpoint: String,
    from_name: String,
    text: String,
    is_system: bool,
}

// ── App component ─────────────────────────────────────────────────────────────

#[function_component(App)]
fn app() -> Html {
    let phase = use_state(|| AppPhase::Checking);
    let node_ref: Rc<RefCell<Option<NodeHandle>>> = use_mut_ref(|| None);
    let chat_state = use_reducer(AppState::default);
    let identity_key = use_state(|| [0u8; 32]);
    let passphrase_error: UseStateHandle<Option<String>> = use_state(|| None);
    let ephemeral = use_state(|| false);

    // Check localStorage on mount
    {
        let phase = phase.clone();
        use_effect_with((), move |_| {
            if load_stored().is_some() {
                phase.set(AppPhase::NeedPassphrase);
            } else {
                phase.set(AppPhase::NewUser);
            }
            || ()
        });
    }

    // Spawn node when phase becomes SpawningNode
    {
        let phase_val = (*phase).clone();
        let phase = phase.clone();
        let node_ref = node_ref.clone();
        let chat_state = chat_state.clone();
        let identity_key = identity_key.clone();
        let ephemeral_eff = ephemeral.clone();
        use_effect_with(phase_val, move |p| {
            if let AppPhase::SpawningNode(key_bytes) = p {
                let key_bytes = *key_bytes;
                let phase = phase.clone();
                let node_ref = node_ref.clone();
                let chat_state = chat_state.clone();
                let identity_key = identity_key.clone();
                let is_ephemeral = *ephemeral_eff;
                spawn_local(async move {
                    identity_key.set(key_bytes);
                    let profile = if is_ephemeral { Profile::default() } else { load_profile(&key_bytes).await };
                    match init_node(key_bytes).await {
                        Ok(handle) => {
                            let gossip = handle.gossip.clone();
                            let ep = handle.endpoint_id.clone();
                            let local_name = if profile.name.is_empty() { stored_name() } else { profile.name.clone() };
                            *node_ref.borrow_mut() = Some(handle);
                            let restored: Vec<RoomState> = profile.rooms.into_iter().map(|s| {
                                let topic_bytes: [u8; 32] = BASE64.decode(&s.topic_b64)
                                    .ok().and_then(|b| b.try_into().ok()).unwrap_or([0u8; 32]);
                                RoomState {
                                    topic_id: TopicId::from_bytes(topic_bytes).to_string(),
                                    topic_bytes,
                                    name: s.name,
                                    mode: if s.hosting { RoomMode::Hosting } else { RoomMode::Joined },
                                    messages: vec![],
                                    participants: vec![],
                                    names: HashMap::new(),
                                    joined: false,
                                    bootstrap_peers: s.bootstrap_peers,
                                }
                            }).collect();
                            let mut initial = AppState::default();
                            initial.active_topic = restored.first().map(|r| r.topic_id.clone());
                            initial.rooms = restored.clone();
                            initial.name = local_name.clone();
                            chat_state.dispatch(Action::SetInitial(initial));

                            // Auto-rejoin restored rooms
                            for r in &restored {
                                let _ = gossip.send(ChatGossipCommand::Join {
                                    topic: r.topic_id.clone(),
                                    peers: r.bootstrap_peers.clone(),
                                    endpoint: ep.clone(),
                                    name: local_name.clone(),
                                }).await;
                            }

                            let state = chat_state.clone();
                            spawn_local(async move {
                                gossip_event_loop(gossip, ep, state).await;
                            });
                            phase.set(AppPhase::Ready);
                        }
                        Err(e) => {
                            phase.set(AppPhase::Failed(format!("{e:?}")));
                        }
                    }
                });
            }
            || ()
        });
    }

    match (*phase).clone() {
        AppPhase::Checking | AppPhase::SpawningNode(_) => html! {
            <div class="flex h-full items-center justify-center">
                <div class="aim-window p-6 text-center text-sm font-bold">{"Signing on…"}</div>
            </div>
        },
        AppPhase::NeedPassphrase => {
            let on_submit = {
                let phase = phase.clone();
                let passphrase_error = passphrase_error.clone();
                Callback::from(move |pass: String| {
                    let phase = phase.clone();
                    let passphrase_error = passphrase_error.clone();
                    spawn_local(async move {
                        match load_stored() {
                            Some((enc, salt)) => match decrypt_key(&enc, &salt, &pass).await {
                                Ok(kb) => {
                                    passphrase_error.set(None);
                                    phase.set(AppPhase::SpawningNode(kb));
                                }
                                Err(_) => passphrase_error.set(Some("Wrong passphrase.".into())),
                            },
                            None => phase.set(AppPhase::NewUser),
                        }
                    });
                })
            };
            let on_forget = {
                let phase = phase.clone();
                Callback::from(move |_: ()| {
                    forget_stored();
                    phase.set(AppPhase::NewUser);
                })
            };
            let on_ephemeral = {
                let phase = phase.clone();
                let ephemeral = ephemeral.clone();
                Callback::from(move |_: ()| {
                    let kb = SecretKey::generate().to_bytes();
                    ephemeral.set(true);
                    phase.set(AppPhase::SpawningNode(kb));
                })
            };
            let error = (*passphrase_error).clone();
            html! { <PassphraseGate {on_submit} {on_forget} {on_ephemeral} {error} /> }
        }
        AppPhase::NewUser => {
            let on_ready = {
                let phase = phase.clone();
                Callback::from(move |(kb, pass): ([u8; 32], Option<String>)| {
                    let phase = phase.clone();
                    spawn_local(async move {
                        if let Some(p) = pass {
                            if !p.is_empty() {
                                if let Ok((enc, salt)) = encrypt_key(&kb, &p).await {
                                    let _ = persist(&enc, &salt);
                                }
                            }
                        }
                        phase.set(AppPhase::SpawningNode(kb));
                    });
                })
            };
            html! { <NewUserSetup {on_ready} /> }
        }
        AppPhase::Ready => {
            let handle_data = node_ref
                .borrow()
                .as_ref()
                .map(|h| (h.endpoint_id.clone(), h.gossip.clone()));
            if let Some((endpoint_id, gossip)) = handle_data {
                let state = (*chat_state).clone();
                let key_bytes = *identity_key;
                let is_ephemeral = *ephemeral;
                let persistent = !is_ephemeral && load_stored().is_some();
                let initial_name = if state.name.is_empty() { stored_name() } else { state.name.clone() };
                let on_host = {
                    let gossip = gossip.clone();
                    let chat_state = chat_state.clone();
                    let ep = endpoint_id.clone();
                    Callback::from(move |(topic_b64, room_name, name): (String, String, String)| {
                        let (g, cs, ep) = (gossip.clone(), chat_state.clone(), ep.clone());
                        spawn_local(async move { do_host(g, ep, topic_b64, room_name, name, cs).await; });
                    })
                };
                let on_join = {
                    let gossip = gossip.clone();
                    let chat_state = chat_state.clone();
                    let ep = endpoint_id.clone();
                    Callback::from(move |(invite, room_name, name): (String, String, String)| {
                        let (g, cs, ep) = (gossip.clone(), chat_state.clone(), ep.clone());
                        spawn_local(async move {
                            if let Err(msg) = do_join(g, ep, invite, room_name, name, cs.clone()).await {
                                cs.dispatch(Action::SetJoinError(Some(msg)));
                            }
                        });
                    })
                };
                let on_clear_error = {
                    let chat_state = chat_state.clone();
                    Callback::from(move |_: ()| chat_state.dispatch(Action::SetJoinError(None)))
                };
                let on_send = {
                    let gossip = gossip.clone();
                    let chat_state = chat_state.clone();
                    let ep = endpoint_id.clone();
                    Callback::from(move |(text, name, topic_id): (String, String, String)| {
                        let (g, cs, ep) = (gossip.clone(), chat_state.clone(), ep.clone());
                        spawn_local(async move { do_send(g, ep, name, text, topic_id, cs).await; });
                    })
                };
                let on_switch_room = {
                    let chat_state = chat_state.clone();
                    Callback::from(move |topic_id: String| {
                        chat_state.dispatch(Action::SetActive(topic_id));
                    })
                };
                html! {
                    <ChatRoom {endpoint_id} {state} {key_bytes} {persistent} ephemeral={is_ephemeral} {initial_name} {on_host} {on_join} {on_send} {on_switch_room} {on_clear_error} />
                }
            } else {
                html! { <div class="p-4 text-red-600">{"Error: node handle missing"}</div> }
            }
        }
        AppPhase::Failed(msg) => html! {
            <div class="flex h-full items-center justify-center">
                <div class="aim-window w-80">
                    <div class="aim-titlebar">{"Error"}</div>
                    <div class="p-4 text-sm text-red-700">{msg}</div>
                </div>
            </div>
        },
    }
}

// ── PassphraseGate ────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct PassphraseGateProps {
    on_submit: Callback<String>,
    on_forget: Callback<()>,
    on_ephemeral: Callback<()>,
    error: Option<String>,
}

#[function_component(PassphraseGate)]
fn passphrase_gate(props: &PassphraseGateProps) -> Html {
    let pass = use_state(String::new);
    let confirm_forget = use_state(|| false);

    let on_input = {
        let pass = pass.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            pass.set(el.value());
        })
    };
    let on_sign_on = {
        let pass = pass.clone();
        let cb = props.on_submit.clone();
        Callback::from(move |_: MouseEvent| cb.emit((*pass).clone()))
    };
    let on_forget_click = {
        let confirm_forget = confirm_forget.clone();
        Callback::from(move |_: MouseEvent| confirm_forget.set(true))
    };
    let on_forget_confirmed = {
        let cb = props.on_forget.clone();
        let confirm_forget = confirm_forget.clone();
        Callback::from(move |_: MouseEvent| { confirm_forget.set(false); cb.emit(()); })
    };
    let on_forget_cancel = {
        let confirm_forget = confirm_forget.clone();
        Callback::from(move |_: MouseEvent| confirm_forget.set(false))
    };
    let on_ephemeral = {
        let cb = props.on_ephemeral.clone();
        Callback::from(move |_: MouseEvent| cb.emit(()))
    };
    let on_keydown = {
        let pass = pass.clone();
        let cb = props.on_submit.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" {
                cb.emit((*pass).clone());
            }
        })
    };

    html! {
        <div class="flex h-full items-center justify-center">
            if *confirm_forget {
                <div class="fixed inset-0 flex items-center justify-center" style="z-index:50">
                    <div class="absolute inset-0 bg-black opacity-30" onclick={on_forget_cancel.clone()} />
                    <div class="aim-window w-80 relative">
                        <div class="aim-titlebar">{"Delete saved data?"}</div>
                        <div class="p-3">
                            <p class="text-xs mb-3">
                                {"This will permanently erase your identity, screen name, and all saved chats from this device. This cannot be undone."}
                            </p>
                            <div class="flex gap-1 justify-end">
                                <button class="aim-btn" onclick={on_forget_cancel}>{"Cancel"}</button>
                                <button class="aim-btn" onclick={on_forget_confirmed}>{"Yes, delete"}</button>
                            </div>
                        </div>
                    </div>
                </div>
            }
            <div class="aim-window w-80">
                <div class="aim-titlebar">{"🔵 Iroh Messenger"}</div>
                <div class="p-4">
                    <p class="text-sm font-bold mb-1">{"Welcome back!"}</p>
                    <p class="text-xs text-gray-600 mb-4">{"Enter your passphrase to sign on."}</p>
                    <div class="mb-1 text-xs font-bold">{"Passphrase:"}</div>
                    <input
                        type="password"
                        class="aim-input mb-3"
                        oninput={on_input}
                        onkeydown={on_keydown}
                        autofocus=true
                    />
                    if let Some(err) = props.error.clone() {
                        <div class="text-[11px] text-red-700 mb-2">{err}</div>
                    }
                    <button class="aim-btn w-full" onclick={on_sign_on}>{"Sign On"}</button>
                    <button
                        class="mt-3 block w-full text-xs text-gray-700 cursor-pointer bg-transparent border-0 p-0 underline"
                        onclick={on_ephemeral}
                    >
                        {"Sign in for this session only (ephemeral)"}
                    </button>
                    <button
                        class="mt-2 block text-xs text-red-700 underline cursor-pointer bg-transparent border-0 p-0"
                        onclick={on_forget_click}
                    >
                        {"Not you? Start fresh"}
                    </button>
                </div>
            </div>
        </div>
    }
}

// ── NewUserSetup ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct NewUserSetupProps {
    on_ready: Callback<([u8; 32], Option<String>)>,
}

#[function_component(NewUserSetup)]
fn new_user_setup(props: &NewUserSetupProps) -> Html {
    let name = use_state(stored_name);
    let pass = use_state(String::new);

    let on_name = {
        let name = name.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            name.set(el.value());
        })
    };
    let on_pass = {
        let pass = pass.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            pass.set(el.value());
        })
    };
    let submit = {
        let name = name.clone();
        let pass = pass.clone();
        let cb = props.on_ready.clone();
        std::rc::Rc::new(move || {
            let n = (*name).clone();
            save_name(&n);
            let key_bytes = SecretKey::generate().to_bytes();
            let p = if (*pass).is_empty() { None } else { Some((*pass).clone()) };
            cb.emit((key_bytes, p));
        })
    };
    let on_go = {
        let f = submit.clone();
        Callback::from(move |_: MouseEvent| f())
    };
    let on_keydown = {
        let f = submit.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" { f(); }
        })
    };

    html! {
        <div class="flex h-full items-center justify-center">
            <div class="aim-window w-80">
                <div class="aim-titlebar">{"🔵 Iroh Messenger — New Account"}</div>
                <div class="p-4">
                    <p class="text-xs text-gray-600 mb-4">
                        {"Choose a screen name. Add a passphrase to remember your identity between sessions (optional)."}
                    </p>
                    <div class="mb-1 text-xs font-bold">{"Screen Name:"}</div>
                    <input
                        type="text"
                        class="aim-input mb-3"
                        value={(*name).clone()}
                        oninput={on_name}
                        onkeydown={on_keydown.clone()}
                        maxlength="32"
                        autofocus=true
                    />
                    <div class="mb-1 text-xs font-bold">
                        {"Passphrase: "}
                        <span class="font-normal text-gray-500">{"(leave blank for none)"}</span>
                    </div>
                    <input
                        type="password"
                        class="aim-input mb-2"
                        oninput={on_pass}
                        onkeydown={on_keydown}
                    />
                    <p class="text-[10px] text-gray-500 mb-4">
                        {"Without a passphrase your identity and chats are not saved. You will get a new handle every session."}
                    </p>
                    <button class="aim-btn w-full" onclick={on_go}>{"Create & Sign On"}</button>
                </div>
            </div>
        </div>
    }
}

// ── ChatRoom ──────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct ChatRoomProps {
    endpoint_id: String,
    state: AppState,
    key_bytes: [u8; 32],
    /// Encrypted profile (rooms + name) is being saved
    persistent: bool,
    /// One-shot session: nothing saves anywhere
    ephemeral: bool,
    initial_name: String,
    on_host: Callback<(String, String, String)>,     // (topic_b64, room_name, screen_name)
    on_join: Callback<(String, String, String)>,     // (invite, room_name, screen_name)
    on_send: Callback<(String, String, String)>,     // (text, name, topic_id)
    on_switch_room: Callback<String>,               // topic_id
    on_clear_error: Callback<()>,
}

#[function_component(ChatRoom)]
fn chat_room(props: &ChatRoomProps) -> Html {
    let name = use_state({
        let n = props.initial_name.clone();
        move || n
    });
    let host_input = use_state(|| {
        web_sys::window()
            .and_then(|w| w.location().hash().ok())
            .map(|h| h.trim_start_matches('#').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
    });
    let room_name_input = use_state(|| String::from("general"));
    let msg_input = use_state(String::new);
    let messages_ref = use_node_ref();
    let show_host_modal = use_state(|| false);
    let show_join_modal = use_state(|| false);
    let open_menu: UseStateHandle<Option<String>> = use_state(|| None);
    let qr_url: UseStateHandle<Option<String>> = use_state(|| None);
    let sidebar_open = use_state(|| false);

    // Auto-open join modal when arriving via invite link
    use_effect_with((), {
        let host_input = host_input.clone();
        let show_join_modal = show_join_modal.clone();
        move |_| {
            if !(*host_input).is_empty() {
                show_join_modal.set(true);
            }
            || ()
        }
    });

    let active_room = props.state.active_topic.as_ref()
        .and_then(|tid| props.state.rooms.iter().find(|r| &r.topic_id == tid));
    let active_topic_id = props.state.active_topic.clone().unwrap_or_default();
    let can_send = active_room.is_some_and(|r| r.joined);


    // Save profile (name + rooms) whenever they change, if persistent
    let bootstrap_total: usize = props.state.rooms.iter().map(|r| r.bootstrap_peers.len()).sum();
    use_effect_with(((*name).clone(), props.state.rooms.len(), bootstrap_total), {
        let key_bytes = props.key_bytes;
        let rooms = props.state.rooms.clone();
        let n = (*name).clone();
        let persistent = props.persistent;
        move |_| {
            if persistent {
                spawn_local(async move { save_profile(&n, &rooms, &key_bytes).await; });
            }
            || ()
        }
    });

    // Auto-scroll on new messages or when switching active room
    let active_msg_count = active_room.map_or(0, |r| r.messages.len());
    let scroll_dep = (active_topic_id.clone(), active_msg_count);
    use_effect_with(scroll_dep, {
        let r = messages_ref.clone();
        move |_| {
            if let Some(el) = r.cast::<HtmlElement>() {
                el.set_scroll_top(el.scroll_height());
            }
            || ()
        }
    });

    let on_name_input = {
        let name = name.clone();
        let persistent = props.persistent;
        let ephemeral = props.ephemeral;
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            let v = el.value();
            // Plaintext name save only for unauthenticated (non-ephemeral) sessions;
            // encrypted save happens via the profile effect when persistent.
            if !persistent && !ephemeral { save_name(&v); }
            name.set(v);
        })
    };
    let on_host_input = {
        let host_input = host_input.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            host_input.set(el.value());
        })
    };
    let on_room_name_input = {
        let room_name_input = room_name_input.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            room_name_input.set(el.value());
        })
    };
    let on_msg_input = {
        let msg_input = msg_input.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlTextAreaElement = e.target_unchecked_into();
            msg_input.set(el.value());
        })
    };

    let submit_host = {
        let name = name.clone();
        let room_name_input = room_name_input.clone();
        let show_host_modal = show_host_modal.clone();
        let cb = props.on_host.clone();
        std::rc::Rc::new(move || {
            let mut topic_bytes = [0u8; 32];
            if let Some(window) = web_sys::window() {
                if let Ok(crypto) = window.crypto() {
                    let arr = Uint8Array::new_with_length(32);
                    let _ = crypto.get_random_values_with_array_buffer_view(&arr);
                    arr.copy_to(&mut topic_bytes);
                }
            }
            let topic_b64 = BASE64.encode(topic_bytes);
            cb.emit((topic_b64, (*room_name_input).clone(), (*name).clone()));
            show_host_modal.set(false);
        })
    };
    let submit_join = {
        let name = name.clone();
        let host_input = host_input.clone();
        let room_name_input = room_name_input.clone();
        let show_join_modal = show_join_modal.clone();
        let cb = props.on_join.clone();
        std::rc::Rc::new(move || {
            let h = (*host_input).trim().to_string();
            if !h.is_empty() {
                cb.emit((h, (*room_name_input).clone(), (*name).clone()));
                show_join_modal.set(false);
            }
        })
    };

    let on_host_click = {
        let f = submit_host.clone();
        Callback::from(move |_: MouseEvent| f())
    };
    let on_host_keydown = {
        let f = submit_host.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" { e.prevent_default(); f(); }
        })
    };
    let on_join_click = {
        let f = submit_join.clone();
        Callback::from(move |_: MouseEvent| f())
    };
    let on_join_keydown = {
        let f = submit_join.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" { e.prevent_default(); f(); }
        })
    };

    let send = {
        let name = name.clone();
        let msg_input = msg_input.clone();
        let cb = props.on_send.clone();
        let tid = active_topic_id.clone();
        move || {
            if !can_send { return; }
            let text = (*msg_input).trim().to_string();
            if !text.is_empty() {
                msg_input.set(String::new());
                cb.emit((text, (*name).clone(), tid.clone()));
            }
        }
    };
    let on_send_click = {
        let send = send.clone();
        Callback::from(move |_: MouseEvent| send())
    };
    let on_send_keydown = {
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" && !e.shift_key() {
                e.prevent_default();
                send();
            }
        })
    };

    html! {
        <div class="aim-window flex flex-col h-full">
            <div class="aim-titlebar">
                <button class="md:hidden aim-btn px-1 py-0 text-xs mr-1"
                    onclick={Callback::from({let s = sidebar_open.clone(); move |_: MouseEvent| s.set(!*s)})}>
                    {"☰"}
                </button>
                {"🔵 Iroh Messenger"}
                <span class="ml-auto font-normal opacity-75 text-[10px] truncate">
                    { active_room.map_or_else(|| "WebRTC P2P".into(), |r| format!("#{}", r.name)) }
                </span>
            </div>

            // ── Modals ────────────────────────────────────────────────────────
            if let Some(url) = (*qr_url).clone() {
                <div class="fixed inset-0 flex items-center justify-center" style="z-index:50">
                    <div class="absolute inset-0 bg-black opacity-30"
                        onclick={Callback::from({let s = qr_url.clone(); move |_: MouseEvent| s.set(None)})} />
                    <div class="aim-window relative max-w-[90vw]">
                        <div class="aim-titlebar">
                            {"Invite QR Code"}
                            <button class="ml-auto aim-btn px-1 py-0 text-xs"
                                onclick={Callback::from({let s = qr_url.clone(); move |_: MouseEvent| s.set(None)})}>
                                {"x"}
                            </button>
                        </div>
                        <div class="p-3 flex flex-col items-center">
                            <div class="bg-white p-2">
                                { make_qr_svg(&url).map(|svg| Html::from_html_unchecked(svg.into()))
                                    .unwrap_or(html!{<p class="text-xs">{"QR generation failed"}</p>}) }
                            </div>
                            <div class="text-[10px] font-mono mt-2 break-all max-w-[240px] text-center">{url}</div>
                        </div>
                    </div>
                </div>
            }

            if *show_host_modal {
                <div class="fixed inset-0 flex items-center justify-center" style="z-index:50">
                    <div class="absolute inset-0 bg-black opacity-30"
                        onclick={Callback::from({let s = show_host_modal.clone(); move |_: MouseEvent| s.set(false)})} />
                    <div class="aim-window w-72 relative">
                        <div class="aim-titlebar">
                            {"New Room"}
                            <button class="ml-auto aim-btn px-1 py-0 text-xs"
                                onclick={Callback::from({let s = show_host_modal.clone(); move |_: MouseEvent| s.set(false)})}>
                                {"x"}
                            </button>
                        </div>
                        <div class="p-3">
                            <div class="text-xs font-bold mb-1">{"Room name"}</div>
                            <input type="text" class="aim-input mb-3" autofocus=true
                                value={(*room_name_input).clone()} oninput={on_room_name_input.clone()}
                                onkeydown={on_host_keydown}
                                placeholder="general" />
                            <div class="flex gap-1 justify-end">
                                <button class="aim-btn"
                                    onclick={Callback::from({let s = show_host_modal.clone(); move |_: MouseEvent| s.set(false)})}>
                                    {"Cancel"}
                                </button>
                                <button class="aim-btn" onclick={on_host_click}>{"Create"}</button>
                            </div>
                        </div>
                    </div>
                </div>
            }

            if *show_join_modal {
                <div class="fixed inset-0 flex items-center justify-center" style="z-index:50">
                    <div class="absolute inset-0 bg-black opacity-30"
                        onclick={Callback::from({let s = show_join_modal.clone(); move |_: MouseEvent| s.set(false)})} />
                    <div class="aim-window w-72 relative">
                        <div class="aim-titlebar">
                            {"Join Room"}
                            <button class="ml-auto aim-btn px-1 py-0 text-xs"
                                onclick={Callback::from({let s = show_join_modal.clone(); move |_: MouseEvent| s.set(false)})}>
                                {"x"}
                            </button>
                        </div>
                        <div class="p-3">
                            <div class="text-xs font-bold mb-1">{"Invite link"}</div>
                            <input type="text" class="aim-input text-[10px] font-mono mb-3" autofocus=true
                                value={(*host_input).clone()} oninput={on_host_input}
                                onkeydown={on_join_keydown.clone()}
                                placeholder="paste invite link" spellcheck="false" />
                            <div class="text-xs font-bold mb-1">
                                {"Room name "}
                                <span class="font-normal text-gray-500">{"(optional)"}</span>
                            </div>
                            <input type="text" class="aim-input mb-3"
                                value={(*room_name_input).clone()} oninput={on_room_name_input.clone()}
                                onkeydown={on_join_keydown}
                                placeholder="general" />
                            if let Some(err) = props.state.join_error.clone() {
                                <div class="text-[11px] text-red-700 mb-2">{err}</div>
                            }
                            <div class="flex gap-1 justify-end">
                                <button class="aim-btn"
                                    onclick={Callback::from({let s = show_join_modal.clone(); move |_: MouseEvent| s.set(false)})}>
                                    {"Cancel"}
                                </button>
                                <button class="aim-btn" onclick={on_join_click}>{"Join"}</button>
                            </div>
                        </div>
                    </div>
                </div>
            }

            // Outside-click catcher for meatball menu
            if open_menu.is_some() {
                <div class="fixed inset-0" style="z-index:25"
                    onclick={Callback::from({let om = open_menu.clone(); move |_: MouseEvent| om.set(None)})} />
            }

            <div class="flex flex-1 min-h-0 relative">
                // Mobile drawer backdrop
                if *sidebar_open {
                    <div class="md:hidden absolute inset-0 bg-black opacity-30 z-10"
                        onclick={Callback::from({let s = sidebar_open.clone(); move |_: MouseEvent| s.set(false)})} />
                }
                // ── Left sidebar ──────────────────────────────────────────────
                <div class={classes!(
                    "w-52", "shrink-0", "border-r-2", "border-r-[#808080]",
                    "flex-col", "overflow-hidden", "bg-[#c0c0c0]",
                    "absolute", "md:relative", "inset-y-0", "left-0", "z-20",
                    if *sidebar_open { "flex" } else { "hidden" },
                    "md:!flex"
                )}>

                    if !props.persistent {
                        <div class="p-1 px-2 bg-[#ffff80] border-b border-[#808080] text-[10px] leading-tight">
                            {"Ephemeral session — nothing is being saved."}
                        </div>
                    }

                    <div class="p-2 border-b border-[#808080]">
                        <div class="aim-section-label">{"Screen Name"}</div>
                        <input type="text" class="aim-input" value={(*name).clone()}
                            oninput={on_name_input} maxlength="32" />
                    </div>

                    <div class="p-2 border-b border-[#808080] flex gap-1">
                        <button class="aim-btn flex-1 px-1"
                            onclick={Callback::from({
                                let s = show_host_modal.clone();
                                let rn = room_name_input.clone();
                                move |_: MouseEvent| { rn.set("general".into()); s.set(true); }
                            })}>
                            {"New Room"}
                        </button>
                        <button class="aim-btn flex-1 px-1"
                            onclick={Callback::from({
                                let s = show_join_modal.clone();
                                let rn = room_name_input.clone();
                                let clear = props.on_clear_error.clone();
                                move |_: MouseEvent| { rn.set("general".into()); clear.emit(()); s.set(true); }
                            })}>
                            {"Join Room"}
                        </button>
                    </div>

                    <div class="flex-1 overflow-auto p-2 flex flex-col gap-2">
                        if !props.state.rooms.is_empty() {
                            <div>
                                <div class="aim-section-label">{"Chats"}</div>
                                <ul>
                                    { for props.state.rooms.iter().map(|room| {
                                        let is_active = props.state.active_topic.as_deref() == Some(room.topic_id.as_str());
                                        let tid = room.topic_id.clone();
                                        let switch_cb = props.on_switch_room.clone();
                                        let sidebar_close = sidebar_open.clone();
                                        let menu_tid = tid.clone();
                                        let open_menu_h = open_menu.clone();
                                        let is_menu_open = open_menu.as_deref() == Some(room.topic_id.as_str());
                                        let invite_url = make_invite_url(room.topic_bytes, &props.endpoint_id)
                                            .unwrap_or_default();
                                        html! {
                                            <li class="relative">
                                                <div class={if is_active { "flex items-center bg-[#000080] text-white" } else { "flex items-center" }}>
                                                    <span class="flex-1 aim-buddy truncate"
                                                        onclick={Callback::from(move |_: MouseEvent| {
                                                            switch_cb.emit(tid.clone());
                                                            sidebar_close.set(false);
                                                        })}>
                                                        {format!("#{}", room.name)}
                                                        if !room.participants.is_empty() {
                                                            <span class="ml-1 opacity-70 text-[10px]">
                                                                {format!("({})", room.participants.len())}
                                                            </span>
                                                        }
                                                    </span>
                                                    <button class="px-1 text-[11px] opacity-50 hover:opacity-100 shrink-0"
                                                        onclick={Callback::from(move |e: MouseEvent| {
                                                            e.stop_propagation();
                                                            open_menu_h.set(if is_menu_open { None } else { Some(menu_tid.clone()) });
                                                        })}>
                                                        {"..."}
                                                    </button>
                                                </div>
                                                if open_menu.as_deref() == Some(room.topic_id.as_str()) {
                                                    <div class="aim-window absolute right-0 min-w-[140px]" style="top:100%;z-index:30">
                                                        <button class="block w-full text-left aim-buddy text-[11px]"
                                                            onclick={Callback::from({
                                                                let url = invite_url.clone();
                                                                let om = open_menu.clone();
                                                                move |_: MouseEvent| { copy_to_clipboard(&url); om.set(None); }
                                                            })}>
                                                            {"Copy invite link"}
                                                        </button>
                                                        <button class="block w-full text-left aim-buddy text-[11px]"
                                                            onclick={Callback::from({
                                                                let url = invite_url.clone();
                                                                let om = open_menu.clone();
                                                                let qr = qr_url.clone();
                                                                move |_: MouseEvent| { qr.set(Some(url.clone())); om.set(None); }
                                                            })}>
                                                            {"Show QR code"}
                                                        </button>
                                                    </div>
                                                }
                                            </li>
                                        }
                                    })}
                                </ul>
                            </div>
                        }

                        if let Some(room) = active_room {
                            <div>
                                <div class="aim-section-label">{"Online"}</div>
                                <ul>
                                    <li class="aim-buddy font-bold text-[#000080]">
                                        {(*name).clone()}{" (me)"}
                                    </li>
                                    { for room.participants.iter().map(|ep| {
                                        let display = room.names.get(ep).cloned().unwrap_or_else(|| {
                                            let short: String = ep.chars().take(20).collect();
                                            format!("{short}…")
                                        });
                                        html! { <li class="aim-buddy">{display}</li> }
                                    })}
                                </ul>
                            </div>
                        }
                    </div>

                    <div class="p-1 border-t border-[#808080] text-[10px] text-gray-600 min-h-5 leading-tight">
                        { active_room.map_or_else(
                            || String::from("No active chat"),
                            |r| match (r.joined, r.mode, r.participants.len()) {
                                (false, _, _) => format!("Connecting to #{}…", r.name),
                                (true, RoomMode::Hosting, 0) => format!("Hosting #{} · waiting for guests", r.name),
                                (true, RoomMode::Joined, 0) => format!("In #{} · no peers connected", r.name),
                                (true, _, n) => format!("In #{} · {} online", r.name, n + 1),
                            }
                        )}
                    </div>
                </div>

                // ── Chat area ─────────────────────────────────────────────────
                <div class="flex flex-1 flex-col min-h-0">
                    <div
                        ref={messages_ref}
                        class="aim-inset flex-1 overflow-auto p-2 aim-chat-log"
                    >
                        { if let Some(room) = active_room {
                            room.messages.iter().map(|msg| {
                                if msg.is_system {
                                    html! { <p class="aim-system-msg">{msg.text.clone()}</p> }
                                } else {
                                    let is_me = msg.from_endpoint == props.endpoint_id;
                                    let sender_class = if is_me { "sender-me" } else { "sender-them" };
                                    let display_name = if is_me {
                                        msg.from_name.clone()
                                    } else {
                                        room.names.get(&msg.from_endpoint).cloned()
                                            .unwrap_or_else(|| msg.from_name.clone())
                                    };
                                    html! {
                                        <p>
                                            <span class={sender_class}>{display_name}{": "}</span>
                                            {msg.text.clone()}
                                        </p>
                                    }
                                }
                            }).collect::<Html>()
                        } else {
                            html! { <p class="aim-system-msg">{"Host or join a chat to get started."}</p> }
                        }}
                    </div>

                    if let Some(room) = active_room {
                        if !room.joined {
                            <div class="px-2 py-1 bg-[#ffffc0] border-t border-[#808080] text-[10px] text-gray-700">
                                {format!("Connecting to #{}…", room.name)}
                            </div>
                        }
                    }
                    <div class="border-t-2 border-t-[#808080] p-2 flex gap-2 items-end bg-[#c0c0c0]">
                        <textarea
                            class={classes!(
                                "aim-inset", "flex-1", "p-1", "text-sm", "h-10", "md:h-16", "resize-none",
                                "font-[Arial,sans-serif]",
                                if !can_send { "opacity-60" } else { "" }
                            )}
                            placeholder={
                                if active_room.is_none() { "Host or join a chat to start typing" }
                                else if !can_send { "Connecting…" }
                                else { "Type a message… (Enter to send, Shift+Enter for newline)" }
                            }
                            value={(*msg_input).clone()}
                            oninput={on_msg_input}
                            onkeydown={on_send_keydown}
                            disabled={!can_send}
                        />
                        <button
                            class="aim-btn self-end"
                            onclick={on_send_click}
                            disabled={!can_send}
                        >{"Send"}</button>
                    </div>
                </div>
            </div>
        </div>
    }
}

// ── Async handlers ────────────────────────────────────────────────────────────

async fn init_node(key_bytes: [u8; 32]) -> std::result::Result<NodeHandle, JsValue> {
    let secret_key = SecretKey::from_bytes(&key_bytes);
    let node = BrowserWebRtcNode::builder(
        BrowserWebRtcNodeConfig::default()
            .with_protocol_transport_preference(BrowserDialTransportPreference::WebRtcOnly),
        secret_key,
    )
    .protocol(ChatGossipProtocol::default())
    .map_err(|e| JsValue::from_str(&e.to_string()))?
    .spawn()
    .await?;

    let gossip = node.protocol::<ChatGossipProtocol>().await?;
    let endpoint_id = node.endpoint_id().to_owned();
    Ok(NodeHandle { _node: node, gossip, endpoint_id })
}

async fn gossip_event_loop(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    local_ep: String,
    state: UseReducerHandle<AppState>,
) {
    loop {
        let Ok(Some(event)) = gossip.next_event().await else { break; };
        match event {
            ChatGossipEvent::Joined { topic } => state.dispatch(Action::Joined(topic)),
            ChatGossipEvent::NeighborUp { topic, endpoint } => {
                state.dispatch(Action::NeighborUp { topic, endpoint })
            }
            ChatGossipEvent::NeighborDown { topic, endpoint } => {
                state.dispatch(Action::NeighborDown { topic, endpoint })
            }
            ChatGossipEvent::Chat { topic, from_endpoint, from_name, text } => {
                if from_endpoint != local_ep {
                    state.dispatch(Action::RecvChat { topic, from_endpoint, from_name, text });
                }
            }
            ChatGossipEvent::System { topic, text } => {
                state.dispatch(Action::System { topic, text })
            }
            ChatGossipEvent::Identify { topic, endpoint, name } => {
                if endpoint != local_ep {
                    state.dispatch(Action::Identify { topic, endpoint, name });
                }
            }
        }
    }
}

async fn do_host(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    endpoint: String,
    topic_b64: String,
    room_name: String,
    name: String,
    state: UseReducerHandle<AppState>,
) {
    let Some(topic_bytes) = decode_topic_b64(&topic_b64) else { return };
    let topic_id = TopicId::from_bytes(topic_bytes).to_string();

    state.dispatch(Action::AddRoom(RoomState {
        topic_id: topic_id.clone(),
        topic_bytes,
        name: room_name.clone(),
        mode: RoomMode::Hosting,
        messages: vec![sys_msg(&format!("*** Hosting #{room_name}. Share the invite link."))],
        participants: vec![],
        joined: false,
        names: HashMap::new(),
        bootstrap_peers: vec![],
    }));

    let _ = gossip
        .send(ChatGossipCommand::Join { topic: topic_id, peers: vec![], endpoint, name })
        .await;
}

async fn do_join(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    endpoint: String,
    invite: String,
    room_name: String,
    name: String,
    state: UseReducerHandle<AppState>,
) -> std::result::Result<(), String> {
    let (topic_bytes, host) = parse_invite(&invite)
        .ok_or_else(|| String::from("Invalid invite link"))?;
    if host == endpoint {
        return Err("That's your own invite link.".into());
    }
    let topic_id = TopicId::from_bytes(topic_bytes).to_string();

    state.dispatch(Action::AddRoom(RoomState {
        topic_id: topic_id.clone(),
        topic_bytes,
        name: room_name.clone(),
        mode: RoomMode::Joined,
        messages: vec![sys_msg(&format!("*** Joining #{room_name}…"))],
        participants: vec![],
        joined: false,
        names: HashMap::new(),
        bootstrap_peers: vec![host.clone()],
    }));

    let _ = gossip
        .send(ChatGossipCommand::Join { topic: topic_id, peers: vec![host], endpoint, name })
        .await;
    Ok(())
}

async fn do_send(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    endpoint: String,
    mut name: String,
    mut text: String,
    topic_id: String,
    state: UseReducerHandle<AppState>,
) {
    truncate_chars(&mut name, MAX_NAME_CHARS);
    truncate_chars(&mut text, MAX_TEXT_CHARS);
    state.dispatch(Action::LocalSend {
        topic: topic_id.clone(),
        msg: ChatMsg {
            from_endpoint: endpoint.clone(),
            from_name: name.clone(),
            text: text.clone(),
            is_system: false,
        },
    });
    let _ = gossip
        .send(ChatGossipCommand::Send { topic: topic_id, from_endpoint: endpoint, from_name: name, text })
        .await;
}

fn sys_msg(text: &str) -> ChatMsg {
    ChatMsg { from_endpoint: String::new(), from_name: String::new(), text: text.into(), is_system: true }
}
