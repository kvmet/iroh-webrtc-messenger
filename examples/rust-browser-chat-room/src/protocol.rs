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

use crate::util::truncate_chars;

pub(crate) const MAX_WIRE_BYTES: usize = 8192;
pub(crate) const MAX_NAME_CHARS: usize = 32;
pub(crate) const MAX_TEXT_CHARS: usize = 4000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum ChatGossipCommand {
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
    },
    Chat {
        #[serde(default)]
        from_endpoint: String,
        #[serde(default)]
        from_name: String,
        #[serde(default)]
        text: String,
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
                    broadcast_wire(
                        &existing_sender,
                        ChatWireMessage::AboutMe { endpoint, name },
                    )
                    .await?;
                    // Re-Sync so we repopulate any state we lost on Leave.
                    let _ = broadcast_wire(&existing_sender, ChatWireMessage::Sync).await;
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
                                                    let _ = broadcast_wire(
                                                        &snd,
                                                        ChatWireMessage::AboutMe { endpoint: ep, name: nm },
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
                broadcast_wire(&sender, ChatWireMessage::AboutMe { endpoint, name }).await?;
                // Ask everyone in the topic to re-announce themselves so we
                // populate our name map without periodic keepalive traffic.
                let _ = broadcast_wire(&sender, ChatWireMessage::Sync).await;
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

/// Deterministic per-endpoint jitter in milliseconds, in [0, 3000).
/// Spreads Sync responses out so peers don't all reply at the same instant.
fn jitter_for(endpoint: &str) -> u64 {
    let mut h: u32 = 0;
    for b in endpoint.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    (h as u64) % 3000
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
