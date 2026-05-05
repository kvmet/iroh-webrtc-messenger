use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use iroh::{Endpoint, EndpointId};
use iroh_gossip::{
    TopicId,
    api::{Event as GossipEvent, GossipSender},
    net::{GOSSIP_ALPN, Gossip},
};
use iroh_webrtc_transport::{Error, Result, browser::BrowserProtocol};
use n0_future::{StreamExt, task, task::AbortOnDropHandle};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::crypto::{
    RoomKeys, decrypt_data, derive_room_keys, encrypt_data, public_key_bytes, public_key_string,
    random_nonce, sign_msg, signer_pk_bytes, verify_msg,
};
use crate::util::truncate_chars;

pub(crate) const MAX_WIRE_BYTES: usize = 8192;
pub(crate) const MAX_NAME_CHARS: usize = 32;
pub(crate) const MAX_TEXT_CHARS: usize = 4000;
/// Per-(topic, signer) cap on remembered nonces. Bounds memory: at this
/// cap a single signer in a single room costs ~4 KiB of nonce storage.
const REPLAY_CAP_PER_SIGNER: usize = 256;

// ── Domain-separation tags for signed payloads ─────────────────────────────
//
// Each variant signs a payload prefixed with its own tag so a signature
// produced for one variant can never be reinterpreted as another variant.
// The trailing NUL terminates the tag unambiguously.
const SIG_DOMAIN_ABOUT_ME: &[u8] = b"iroh-msgr/about-me/v1\0";
const SIG_DOMAIN_CHAT: &[u8] = b"iroh-msgr/chat/v1\0";
const SIG_DOMAIN_LEAVE: &[u8] = b"iroh-msgr/leave/v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum ChatGossipCommand {
    Join {
        topic: String,
        /// 32-byte room secret. The protocol derives (topic_id, aes_key)
        /// via HKDF-SHA256 with disjoint info strings.
        #[serde(with = "serde_bytes_array")]
        room_secret: [u8; 32],
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
    /// Send a signed Leave wire message (best-effort) and tear down the
    /// subscription. The signed Leave lets remote peers distinguish a
    /// deliberate departure from a transient transport disconnect.
    Leave {
        topic: String,
    },
}

/// serde helper: serialize/deserialize [u8; 32] as a base64 string.
mod serde_bytes_array {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// serde helper: serialize/deserialize [u8; 16] as a base64 string.
mod serde_nonce {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum ChatGossipEvent {
    Joined { topic: String },
    NeighborUp { topic: String, endpoint: String },
    NeighborDown { topic: String, endpoint: String },
    Chat { topic: String, from_endpoint: String, from_name: String, text: String },
    System { topic: String, text: String },
    Identify { topic: String, endpoint: String, name: String },
    /// A peer broadcast a signed Leave for this topic. `endpoint` is the
    /// verified signer pubkey. Distinct from NeighborDown (which is a
    /// transport-level disconnect signal that an attacker could induce).
    PeerLeft { topic: String, endpoint: String },
}

/// Over-the-wire message between peers. **Wire format v2.**
///
/// Compared with v1: the self-claimed `endpoint`/`from_endpoint` field is
/// replaced by `signer` (still an Ed25519 pubkey string), but the receiver
/// derives identity exclusively from the verified signature, so the field
/// name reflects that the value is what was signed by, not what was
/// claimed. Each authenticated variant carries a 16-byte random `nonce`
/// for replay protection. Signed payloads are domain-separated by a
/// per-variant tag and bound to the room's HKDF-derived `topic_id` (not
/// the room secret, so `topic_id` may safely appear in logs without
/// revealing the AES key).
///
/// **Stability contract**:
/// - Never remove or rename an existing variant or field within v2.
/// - New fields must be added with `#[serde(default)]` so older v2 peers
///   sending the old shape still deserialize.
/// - New variants are safe to add — old peers receive them as
///   [`ChatWireMessage::Unknown`] and silently no-op.
/// - Breaking changes need a new wire-format version (and a coordinated
///   protocol bump elsewhere); v1 is not supported.
///
/// ## Discovery protocol
///
/// Peer-name discovery is event-driven, not periodic. On joining a topic,
/// a peer broadcasts its own [`AboutMe`] followed by [`Sync`]. Receivers
/// of `Sync` schedule a jittered (0–3s) re-broadcast of their own
/// `AboutMe`, with a per-topic coalescing flag so multiple Syncs in quick
/// succession produce at most one response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ChatWireMessage {
    AboutMe {
        #[serde(default)]
        signer: String,
        #[serde(default)]
        name: String,
        #[serde(default, with = "serde_nonce")]
        nonce: [u8; 16],
        /// Ed25519 sig over SIG_DOMAIN_ABOUT_ME || topic_id || signer_pk || nonce || name_utf8.
        #[serde(default)]
        sig: Vec<u8>,
    },
    Chat {
        #[serde(default)]
        signer: String,
        #[serde(default)]
        from_name: String,
        #[serde(default)]
        text: String,
        #[serde(default, with = "serde_nonce")]
        nonce: [u8; 16],
        /// Ed25519 sig over SIG_DOMAIN_CHAT || topic_id || signer_pk || nonce || text_utf8.
        #[serde(default)]
        sig: Vec<u8>,
    },
    /// Signed deliberate departure. Receivers should treat this as
    /// authoritative ("X left") and may suppress the transport-level
    /// "disconnected" message that follows shortly after.
    Leave {
        #[serde(default)]
        signer: String,
        #[serde(default, with = "serde_nonce")]
        nonce: [u8; 16],
        /// Ed25519 sig over SIG_DOMAIN_LEAVE || topic_id || signer_pk || nonce.
        #[serde(default)]
        sig: Vec<u8>,
    },
    /// Request: "everyone in this topic, please re-announce yourselves."
    Sync,
    /// Catch-all for variants this client doesn't know about.
    #[serde(other)]
    Unknown,
}

/// Per-(topic, signer) bounded LRU of seen nonces. Drops messages whose
/// (signer, nonce) pair has been seen within the cap.
#[derive(Default)]
struct ReplayLru {
    map: HashMap<String, VecDeque<[u8; 16]>>,
}

impl ReplayLru {
    fn check_and_insert(&mut self, signer: &str, nonce: [u8; 16]) -> bool {
        let entry = self.map.entry(signer.to_string()).or_default();
        if entry.iter().any(|n| *n == nonce) {
            return false;
        }
        if entry.len() >= REPLAY_CAP_PER_SIGNER {
            entry.pop_front();
        }
        entry.push_back(nonce);
        true
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChatGossipProtocol {
    /// The local user's Ed25519 signing key, fixed at construction.
    /// Stored as a raw field rather than going through the command channel
    /// so the key bytes don't traverse serde_json + base64 string heap.
    secret_key: Arc<[u8; 32]>,
    gossip: Arc<StdMutex<Option<Gossip>>>,
    topics: Arc<StdMutex<HashMap<String, GossipSender>>>,
    /// Per-topic derived (topic_id, aes_key). Both are HKDF outputs from
    /// the room secret, which the protocol does not retain.
    keys: Arc<StdMutex<HashMap<String, RoomKeys>>>,
    /// Per-topic receiver task handle. Dropping the entry aborts the task,
    /// which drops its GossipSender clone and the receiver, releasing the
    /// iroh-gossip subscription.
    tasks: Arc<StdMutex<HashMap<String, AbortOnDropHandle<()>>>>,
    events_tx: mpsc::UnboundedSender<ChatGossipEvent>,
    events_rx: Arc<AsyncMutex<mpsc::UnboundedReceiver<ChatGossipEvent>>>,
}

impl ChatGossipProtocol {
    pub(crate) fn new(secret_key: [u8; 32]) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            secret_key: Arc::new(secret_key),
            gossip: Arc::new(StdMutex::new(None)),
            topics: Arc::new(StdMutex::new(HashMap::new())),
            keys: Arc::new(StdMutex::new(HashMap::new())),
            tasks: Arc::new(StdMutex::new(HashMap::new())),
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
            ChatGossipCommand::Join { topic, room_secret, peers, endpoint, name } => {
                let secret_key = *self.secret_key;
                let signer = public_key_string(&secret_key);
                let room_keys = derive_room_keys(&room_secret);
                self.keys
                    .lock()
                    .expect("keys mutex poisoned")
                    .insert(topic.clone(), room_keys);

                // If we already have a subscription to this topic in this
                // session, re-use it. Subscribing twice to the same topic
                // in iroh-gossip leads to undefined mesh state.
                let already = self
                    .topics
                    .lock()
                    .expect("topics mutex poisoned")
                    .get(&topic)
                    .cloned();
                if let Some(existing_sender) = already {
                    let _ = self.events_tx.send(ChatGossipEvent::Joined { topic: topic.clone() });
                    let signer_pk = public_key_bytes(&secret_key);
                    let nonce = random_nonce();
                    let sig = sign_about_me(&secret_key, &room_keys.topic_id, &signer_pk, &nonce, &name);
                    let events = self.events_tx.clone();
                    let topic_for_err = topic.clone();
                    let signer_for_msg = signer.clone();
                    let aes_key = room_keys.aes_key;
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Err(e) = broadcast_encrypted(
                            &existing_sender,
                            ChatWireMessage::AboutMe { signer: signer_for_msg, name, nonce, sig },
                            &aes_key,
                        )
                        .await
                        {
                            let _ = events.send(ChatGossipEvent::System {
                                topic: topic_for_err.clone(),
                                text: format!("rejoin announce failed: {e}"),
                            });
                        }
                        if let Err(e) = broadcast_encrypted(&existing_sender, ChatWireMessage::Sync, &aes_key).await {
                            let _ = events.send(ChatGossipEvent::System {
                                topic: topic_for_err,
                                text: format!("rejoin sync failed: {e}"),
                            });
                        }
                    });
                    return Ok(());
                }

                let topic_handle_id = TopicId::from_bytes(room_keys.topic_id);
                let peers = parse_peers(&peers)?;
                let gossip = self.existing_gossip()?;
                let topic_handle = gossip
                    .subscribe(topic_handle_id, peers)
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
                let endpoint_for_task = endpoint;
                let name_for_task = name.clone();
                let signer_for_task = signer.clone();
                let signer_pk = public_key_bytes(&secret_key);
                // Coalesces Sync responses: at most one pending re-announce
                // per topic at a time, no matter how many Syncs arrive.
                let pending_announce = Arc::new(AtomicBool::new(false));
                let replay = Arc::new(StdMutex::new(ReplayLru::default()));
                let aes_key = room_keys.aes_key;
                let topic_id_bytes = room_keys.topic_id;
                let task_handle = task::spawn(async move {
                    while let Some(event) = receiver.next().await {
                        match event {
                            Ok(GossipEvent::NeighborUp(ep)) => {
                                let _ = events.send(ChatGossipEvent::NeighborUp {
                                    topic: topic_for_task.clone(),
                                    endpoint: ep.to_string(),
                                });
                                let nonce = random_nonce();
                                let sig = sign_about_me(&secret_key, &topic_id_bytes, &signer_pk, &nonce, &name_for_task);
                                if let Err(e) = broadcast_encrypted(
                                    &sender_for_task,
                                    ChatWireMessage::AboutMe {
                                        signer: signer_for_task.clone(),
                                        name: name_for_task.clone(),
                                        nonce,
                                        sig,
                                    },
                                    &aes_key,
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
                                let Ok(plaintext) = decrypt_data(&msg.content, &aes_key).await else { continue };
                                let Ok(wire) = serde_json::from_slice::<ChatWireMessage>(&plaintext) else { continue };
                                match wire {
                                    ChatWireMessage::AboutMe { signer, mut name, nonce, sig } => {
                                        let Some(signer_pk) = signer_pk_bytes(&signer) else { continue };
                                        let payload = about_me_payload(&topic_id_bytes, &signer_pk, &nonce, &name);
                                        if !verify_msg(&signer, &payload, &sig) { continue; }
                                        if !replay.lock().expect("replay mutex poisoned").check_and_insert(&signer, nonce) {
                                            continue;
                                        }
                                        truncate_chars(&mut name, MAX_NAME_CHARS);
                                        let _ = events.send(ChatGossipEvent::Identify {
                                            topic: topic_for_task.clone(),
                                            endpoint: signer,
                                            name,
                                        });
                                    }
                                    ChatWireMessage::Chat { signer, mut from_name, mut text, nonce, sig } => {
                                        let Some(signer_pk) = signer_pk_bytes(&signer) else { continue };
                                        let payload = chat_payload(&topic_id_bytes, &signer_pk, &nonce, &text);
                                        if !verify_msg(&signer, &payload, &sig) { continue; }
                                        if !replay.lock().expect("replay mutex poisoned").check_and_insert(&signer, nonce) {
                                            continue;
                                        }
                                        truncate_chars(&mut from_name, MAX_NAME_CHARS);
                                        truncate_chars(&mut text, MAX_TEXT_CHARS);
                                        let _ = events.send(ChatGossipEvent::Chat {
                                            topic: topic_for_task.clone(),
                                            from_endpoint: signer,
                                            from_name,
                                            text,
                                        });
                                    }
                                    ChatWireMessage::Leave { signer, nonce, sig } => {
                                        let Some(signer_pk) = signer_pk_bytes(&signer) else { continue };
                                        let payload = leave_payload(&topic_id_bytes, &signer_pk, &nonce);
                                        if !verify_msg(&signer, &payload, &sig) { continue; }
                                        if !replay.lock().expect("replay mutex poisoned").check_and_insert(&signer, nonce) {
                                            continue;
                                        }
                                        let _ = events.send(ChatGossipEvent::PeerLeft {
                                            topic: topic_for_task.clone(),
                                            endpoint: signer,
                                        });
                                    }
                                    ChatWireMessage::Sync => {
                                        // Schedule a jittered re-announce. The
                                        // pending flag coalesces multiple Syncs
                                        // into one response.
                                        if pending_announce
                                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                                            .is_ok()
                                        {
                                            let ep = endpoint_for_task.clone();
                                            let nm = name_for_task.clone();
                                            let snd = sender_for_task.clone();
                                            let pending = pending_announce.clone();
                                            let signer_inner = signer_for_task.clone();
                                            task::spawn(async move {
                                                let jitter_ms = jitter_for(&ep);
                                                n0_future::time::sleep(Duration::from_millis(jitter_ms)).await;
                                                let nonce = random_nonce();
                                                let sig = sign_about_me(&secret_key, &topic_id_bytes, &signer_pk, &nonce, &nm);
                                                let _ = broadcast_encrypted(
                                                    &snd,
                                                    ChatWireMessage::AboutMe { signer: signer_inner, name: nm, nonce, sig },
                                                    &aes_key,
                                                ).await;
                                                pending.store(false, Ordering::SeqCst);
                                            });
                                        }
                                    }
                                    ChatWireMessage::Unknown => {}
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
                });
                self.tasks
                    .lock()
                    .expect("tasks mutex poisoned")
                    .insert(topic.clone(), AbortOnDropHandle::new(task_handle));
                let _ = self.events_tx.send(ChatGossipEvent::Joined { topic: topic.clone() });

                // Initial AboutMe + Sync after Join.
                let nonce = random_nonce();
                let sig = sign_about_me(&secret_key, &room_keys.topic_id, &signer_pk, &nonce, &name);
                let events = self.events_tx.clone();
                let topic_for_err = topic.clone();
                let signer_for_msg = signer.clone();
                let aes_key = room_keys.aes_key;
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = broadcast_encrypted(&sender, ChatWireMessage::AboutMe { signer: signer_for_msg, name, nonce, sig }, &aes_key).await {
                        let _ = events.send(ChatGossipEvent::System {
                            topic: topic_for_err.clone(),
                            text: format!("initial announce failed: {e}"),
                        });
                    }
                    if let Err(e) = broadcast_encrypted(&sender, ChatWireMessage::Sync, &aes_key).await {
                        let _ = events.send(ChatGossipEvent::System {
                            topic: topic_for_err,
                            text: format!("initial sync failed: {e}"),
                        });
                    }
                });
            }
            ChatGossipCommand::Send { topic, from_endpoint: _, from_name, text } => {
                let (sender, room_keys) = {
                    let topics = self.topics.lock().expect("topics mutex poisoned");
                    let keys = self.keys.lock().expect("keys mutex poisoned");
                    let sender = topics
                        .get(&topic)
                        .cloned()
                        .ok_or_else(|| Error::WebRtc(format!("not joined to {topic}")))?;
                    let room_keys = *keys
                        .get(&topic)
                        .ok_or_else(|| Error::WebRtc(format!("no key for {topic}")))?;
                    (sender, room_keys)
                };
                let secret_key = *self.secret_key;
                let signer = public_key_string(&secret_key);
                let signer_pk = public_key_bytes(&secret_key);
                let nonce = random_nonce();
                let sig = sign_chat(&secret_key, &room_keys.topic_id, &signer_pk, &nonce, &text);
                let events = self.events_tx.clone();
                let topic_for_err = topic.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = broadcast_encrypted(
                        &sender,
                        ChatWireMessage::Chat { signer, from_name, text, nonce, sig },
                        &room_keys.aes_key,
                    )
                    .await
                    {
                        let _ = events.send(ChatGossipEvent::System {
                            topic: topic_for_err,
                            text: format!("delivery failed: {e}"),
                        });
                    }
                });
            }
            ChatGossipCommand::Leave { topic } => {
                // Snapshot the per-topic state for the signed broadcast,
                // then tear down. The spawned broadcast task holds its own
                // sender clone, so it can still flush after we drop ours.
                let snapshot = {
                    let topics = self.topics.lock().expect("topics mutex poisoned");
                    let keys = self.keys.lock().expect("keys mutex poisoned");
                    match (topics.get(&topic), keys.get(&topic)) {
                        (Some(s), Some(k)) => Some((s.clone(), *k)),
                        _ => None,
                    }
                };

                if let Some((sender, room_keys)) = snapshot {
                    let secret_key = *self.secret_key;
                    let signer = public_key_string(&secret_key);
                    let signer_pk = public_key_bytes(&secret_key);
                    let nonce = random_nonce();
                    let sig = sign_leave(&secret_key, &room_keys.topic_id, &signer_pk, &nonce);
                    let events = self.events_tx.clone();
                    let topic_for_err = topic.clone();
                    let aes_key = room_keys.aes_key;
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Err(e) = broadcast_encrypted(
                            &sender,
                            ChatWireMessage::Leave { signer, nonce, sig },
                            &aes_key,
                        ).await {
                            let _ = events.send(ChatGossipEvent::System {
                                topic: topic_for_err,
                                text: format!("leave announce failed: {e}"),
                            });
                        }
                    });
                }

                // Drop per-topic state. AbortOnDropHandle aborts the receiver
                // task; iroh-gossip releases the subscription once all
                // GossipSender clones have been dropped (the spawned broadcast
                // task above holds the last clone until it completes).
                self.topics
                    .lock()
                    .expect("topics mutex poisoned")
                    .remove(&topic);
                self.keys
                    .lock()
                    .expect("keys mutex poisoned")
                    .remove(&topic);
                self.tasks
                    .lock()
                    .expect("tasks mutex poisoned")
                    .remove(&topic);
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

/// Deterministic per-endpoint jitter in milliseconds, in [0, 3000).
/// Spreads Sync responses out so peers don't all reply at the same instant.
fn jitter_for(endpoint: &str) -> u64 {
    let mut h: u32 = 0;
    for b in endpoint.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    (h as u64) % 3000
}

/// Serialize, encrypt with the topic key, and broadcast.
async fn broadcast_encrypted(sender: &GossipSender, msg: ChatWireMessage, key: &[u8; 32]) -> Result<()> {
    let encoded = serde_json::to_vec(&msg)
        .map_err(|e| Error::WebRtc(format!("encode error: {e}")))?;
    let encrypted = encrypt_data(&encoded, key)
        .await
        .map_err(|e| Error::WebRtc(format!("encrypt error: {e:?}")))?;
    sender.broadcast(Bytes::from(encrypted)).await.map_err(error_from_display)
}

fn about_me_payload(topic_id: &[u8; 32], signer_pk: &[u8; 32], nonce: &[u8; 16], name: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN_ABOUT_ME.len() + 32 + 32 + 16 + name.len());
    v.extend_from_slice(SIG_DOMAIN_ABOUT_ME);
    v.extend_from_slice(topic_id);
    v.extend_from_slice(signer_pk);
    v.extend_from_slice(nonce);
    v.extend_from_slice(name.as_bytes());
    v
}

fn sign_about_me(secret_key: &[u8; 32], topic_id: &[u8; 32], signer_pk: &[u8; 32], nonce: &[u8; 16], name: &str) -> Vec<u8> {
    sign_msg(secret_key, &about_me_payload(topic_id, signer_pk, nonce, name))
}

fn chat_payload(topic_id: &[u8; 32], signer_pk: &[u8; 32], nonce: &[u8; 16], text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN_CHAT.len() + 32 + 32 + 16 + text.len());
    v.extend_from_slice(SIG_DOMAIN_CHAT);
    v.extend_from_slice(topic_id);
    v.extend_from_slice(signer_pk);
    v.extend_from_slice(nonce);
    v.extend_from_slice(text.as_bytes());
    v
}

fn sign_chat(secret_key: &[u8; 32], topic_id: &[u8; 32], signer_pk: &[u8; 32], nonce: &[u8; 16], text: &str) -> Vec<u8> {
    sign_msg(secret_key, &chat_payload(topic_id, signer_pk, nonce, text))
}

fn leave_payload(topic_id: &[u8; 32], signer_pk: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN_LEAVE.len() + 32 + 32 + 16);
    v.extend_from_slice(SIG_DOMAIN_LEAVE);
    v.extend_from_slice(topic_id);
    v.extend_from_slice(signer_pk);
    v.extend_from_slice(nonce);
    v
}

fn sign_leave(secret_key: &[u8; 32], topic_id: &[u8; 32], signer_pk: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    sign_msg(secret_key, &leave_payload(topic_id, signer_pk, nonce))
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
