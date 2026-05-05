use std::collections::HashMap;
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
use iroh_webrtc_transport::{
    Error, Result,
    browser::BrowserProtocol,
};
use n0_future::{StreamExt, task};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::crypto::{decrypt_data, encrypt_data, sign_msg, verify_msg};
use crate::util::truncate_chars;

pub(crate) const MAX_WIRE_BYTES: usize = 8192;
pub(crate) const MAX_NAME_CHARS: usize = 32;
pub(crate) const MAX_TEXT_CHARS: usize = 4000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum ChatGossipCommand {
    Join {
        topic: String,
        /// Raw topic bytes used as the AES-256-GCM encryption key for this room.
        #[serde(with = "serde_bytes_array")]
        topic_bytes: [u8; 32],
        /// Caller's Ed25519 secret key bytes, used to sign outbound messages.
        #[serde(with = "serde_bytes_array")]
        secret_key: [u8; 32],
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

/// serde helper: serialize/deserialize [u8; 32] as a base64 string.
mod serde_bytes_array {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
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
}

/// Over-the-wire message between peers.
///
/// **Stability contract** (read this before changing anything here):
/// - Never remove or rename an existing variant or field.
/// - New fields must be added with `#[serde(default)]` so older peers
///   sending the old shape still deserialize.
/// - New variants are safe to add — old peers receive them as
///   [`ChatWireMessage::Unknown`] and silently no-op.
/// - There is no version field by design. Forward compatibility is
///   maintained by convention, not negotiation.
///
/// ## Discovery protocol
///
/// Peer-name discovery is event-driven, not periodic. On joining a
/// topic, a peer broadcasts its own [`AboutMe`] followed by [`Sync`].
/// Receivers of `Sync` schedule a jittered (0–3s) re-broadcast of
/// their own `AboutMe`, with a per-topic coalescing flag so multiple
/// Syncs in quick succession produce at most one response. Steady-
/// state idle traffic is zero. New joiners learn the room within
/// ~3 seconds without periodic heartbeats from everyone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ChatWireMessage {
    AboutMe {
        #[serde(default)]
        endpoint: String,
        #[serde(default)]
        name: String,
        /// Ed25519 signature over topic_bytes || endpoint.as_bytes() || name_utf8.
        /// Required; messages with an absent or invalid signature are dropped.
        #[serde(default)]
        sig: Vec<u8>,
    },
    Chat {
        #[serde(default)]
        from_endpoint: String,
        #[serde(default)]
        from_name: String,
        #[serde(default)]
        text: String,
        /// Ed25519 signature over topic_bytes || from_endpoint.as_bytes() || text_utf8.
        /// Required; messages with an absent or invalid signature are dropped.
        #[serde(default)]
        sig: Vec<u8>,
    },
    /// Request: "everyone in this topic, please re-announce yourselves."
    /// Sent on join (and on rejoin) so the requester populates their
    /// name map without the network having to keepalive periodically.
    Sync,
    /// Catch-all for variants this client doesn't know about.
    /// Treated as a no-op by the receiver.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct ChatGossipProtocol {
    gossip: Arc<StdMutex<Option<Gossip>>>,
    topics: Arc<StdMutex<HashMap<String, GossipSender>>>,
    /// Per-topic AES-256-GCM key (= the topic bytes).
    keys: Arc<StdMutex<HashMap<String, [u8; 32]>>>,
    /// The local user's Ed25519 signing key, set once on the first Join.
    signing_key: Arc<StdMutex<Option<[u8; 32]>>>,
    events_tx: mpsc::UnboundedSender<ChatGossipEvent>,
    events_rx: Arc<AsyncMutex<mpsc::UnboundedReceiver<ChatGossipEvent>>>,
}

impl Default for ChatGossipProtocol {
    fn default() -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            gossip: Arc::new(StdMutex::new(None)),
            topics: Arc::new(StdMutex::new(HashMap::new())),
            keys: Arc::new(StdMutex::new(HashMap::new())),
            signing_key: Arc::new(StdMutex::new(None)),
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
            ChatGossipCommand::Join { topic, topic_bytes, secret_key, peers, endpoint, name } => {
                // Store the signing key on first join (same key for all topics).
                {
                    let mut sk = self.signing_key.lock().expect("signing_key mutex poisoned");
                    if sk.is_none() {
                        *sk = Some(secret_key);
                    }
                }
                // Store the per-topic encryption key.
                self.keys
                    .lock()
                    .expect("keys mutex poisoned")
                    .insert(topic.clone(), topic_bytes);

                // If we already have a subscription to this topic in this
                // session (e.g. user clicked Leave Room and then rejoined),
                // re-use it. Subscribing twice to the same topic in iroh-
                // gossip leads to undefined mesh state and asymmetric
                // delivery. We just re-emit Joined and re-broadcast our
                // identity so the existing mesh learns we're back.
                let already = self
                    .topics
                    .lock()
                    .expect("topics mutex poisoned")
                    .get(&topic)
                    .cloned();
                if let Some(existing_sender) = already {
                    let _ = self.events_tx.send(ChatGossipEvent::Joined { topic: topic.clone() });
                    let sig = sign_about_me(&secret_key, &topic_bytes, &endpoint, &name);
                    // spawn_local: encrypt_data uses JsFuture (!Send), can't be awaited
                    // directly in handle_command which must return a Send future.
                    wasm_bindgen_futures::spawn_local(async move {
                        let _ = broadcast_encrypted(
                            &existing_sender,
                            ChatWireMessage::AboutMe { endpoint, name, sig },
                            &topic_bytes,
                        )
                        .await;
                        let _ = broadcast_encrypted(&existing_sender, ChatWireMessage::Sync, &topic_bytes).await;
                    });
                    return Ok(());
                }
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
                // Coalesces Sync responses: at most one pending re-announce
                // per topic at a time, no matter how many Syncs arrive.
                let pending_announce = Arc::new(AtomicBool::new(false));
                task::spawn(async move {
                    while let Some(event) = receiver.next().await {
                        match event {
                            Ok(GossipEvent::NeighborUp(ep)) => {
                                let _ = events.send(ChatGossipEvent::NeighborUp {
                                    topic: topic_for_task.clone(),
                                    endpoint: ep.to_string(),
                                });
                                let sig = sign_about_me(&secret_key, &topic_bytes, &endpoint_for_task, &name_for_task);
                                if let Err(e) = broadcast_encrypted(
                                    &sender_for_task,
                                    ChatWireMessage::AboutMe {
                                        endpoint: endpoint_for_task.clone(),
                                        name: name_for_task.clone(),
                                        sig,
                                    },
                                    &topic_bytes,
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
                                // Decrypt before parsing. Drop silently if decryption fails
                                // (wrong key = not in this room, or corrupted packet).
                                let Ok(plaintext) = decrypt_data(&msg.content, &topic_bytes).await else { continue };
                                if let Ok(wire) =
                                    serde_json::from_slice::<ChatWireMessage>(&plaintext)
                                {
                                    match wire {
                                        ChatWireMessage::AboutMe { endpoint, mut name, sig } => {
                                            // Verify sig before accepting identity claim.
                                            let payload = about_me_payload(&topic_bytes, &endpoint, &name);
                                            if !verify_msg(&endpoint, &payload, &sig) { continue; }
                                            truncate_chars(&mut name, MAX_NAME_CHARS);
                                            let _ = events.send(ChatGossipEvent::Identify {
                                                topic: topic_for_task.clone(),
                                                endpoint,
                                                name,
                                            });
                                        }
                                        ChatWireMessage::Chat { from_endpoint, mut from_name, mut text, sig } => {
                                            // Verify sig before delivering the message.
                                            let payload = chat_payload(&topic_bytes, &from_endpoint, &text);
                                            if !verify_msg(&from_endpoint, &payload, &sig) { continue; }
                                            truncate_chars(&mut from_name, MAX_NAME_CHARS);
                                            truncate_chars(&mut text, MAX_TEXT_CHARS);
                                            let _ = events.send(ChatGossipEvent::Chat {
                                                topic: topic_for_task.clone(),
                                                from_endpoint,
                                                from_name,
                                                text,
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
                                                task::spawn(async move {
                                                    let jitter_ms = jitter_for(&ep);
                                                    n0_future::time::sleep(Duration::from_millis(jitter_ms)).await;
                                                    let sig = sign_about_me(&secret_key, &topic_bytes, &ep, &nm);
                                                    let _ = broadcast_encrypted(
                                                        &snd,
                                                        ChatWireMessage::AboutMe { endpoint: ep, name: nm, sig },
                                                        &topic_bytes,
                                                    ).await;
                                                    pending.store(false, Ordering::SeqCst);
                                                });
                                            }
                                        }
                                        ChatWireMessage::Unknown => {} // forward-compat no-op
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
                let sig = sign_about_me(&secret_key, &topic_bytes, &endpoint, &name);
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = broadcast_encrypted(&sender, ChatWireMessage::AboutMe { endpoint, name, sig }, &topic_bytes).await;
                    // Ask everyone in the topic to re-announce themselves so we
                    // populate our name map without periodic keepalive traffic.
                    let _ = broadcast_encrypted(&sender, ChatWireMessage::Sync, &topic_bytes).await;
                });
            }
            ChatGossipCommand::Send { topic, from_endpoint, from_name, text } => {
                let (sender, topic_bytes, secret_key) = {
                    let topics = self.topics.lock().expect("topics mutex poisoned");
                    let keys = self.keys.lock().expect("keys mutex poisoned");
                    let sk = self.signing_key.lock().expect("signing_key mutex poisoned");
                    let sender = topics
                        .get(&topic)
                        .cloned()
                        .ok_or_else(|| Error::WebRtc(format!("not joined to {topic}")))?;
                    let topic_bytes = *keys
                        .get(&topic)
                        .ok_or_else(|| Error::WebRtc(format!("no key for {topic}")))?;
                    let secret_key = sk
                        .ok_or_else(|| Error::WebRtc("signing key not initialized".into()))?;
                    (sender, topic_bytes, secret_key)
                };
                let sig = sign_chat(&secret_key, &topic_bytes, &from_endpoint, &text);
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = broadcast_encrypted(
                        &sender,
                        ChatWireMessage::Chat { from_endpoint, from_name, text, sig },
                        &topic_bytes,
                    )
                    .await;
                });
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

/// Signed payload for an AboutMe: topic_bytes || endpoint_bytes_as_public_key || name_utf8.
/// Including topic_bytes prevents cross-room replay of identity claims.
fn about_me_payload(topic_bytes: &[u8; 32], endpoint: &str, name: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + endpoint.len() + name.len());
    v.extend_from_slice(topic_bytes);
    v.extend_from_slice(endpoint.as_bytes());
    v.extend_from_slice(name.as_bytes());
    v
}

fn sign_about_me(secret_key: &[u8; 32], topic_bytes: &[u8; 32], endpoint: &str, name: &str) -> Vec<u8> {
    sign_msg(secret_key, &about_me_payload(topic_bytes, endpoint, name))
}

/// Signed payload for a Chat: topic_bytes || from_endpoint_bytes || text_utf8.
fn chat_payload(topic_bytes: &[u8; 32], from_endpoint: &str, text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + from_endpoint.len() + text.len());
    v.extend_from_slice(topic_bytes);
    v.extend_from_slice(from_endpoint.as_bytes());
    v.extend_from_slice(text.as_bytes());
    v
}

fn sign_chat(secret_key: &[u8; 32], topic_bytes: &[u8; 32], from_endpoint: &str, text: &str) -> Vec<u8> {
    sign_msg(secret_key, &chat_payload(topic_bytes, from_endpoint, text))
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
