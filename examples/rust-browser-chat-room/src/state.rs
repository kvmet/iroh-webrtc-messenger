use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use yew::prelude::*;

use crate::util::add_known_peer;

#[derive(Clone, PartialEq)]
pub(crate) struct ChatMsg {
    pub(crate) from_endpoint: String,
    pub(crate) from_name: String,
    pub(crate) text: String,
    pub(crate) is_system: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoomMode {
    Hosting,
    Joined,
}

#[derive(Clone, PartialEq)]
pub(crate) struct RoomState {
    /// Stringified iroh-gossip TopicId (HKDF-derived from room_secret).
    pub(crate) topic_id: String,
    /// 32-byte room secret. The HKDF-derived topic_id (above) and AES key
    /// are kept separate from this so anything logging topic_id cannot
    /// leak the encryption key.
    pub(crate) room_secret: [u8; 32],
    pub(crate) name: String,
    pub(crate) mode: RoomMode,
    pub(crate) messages: Vec<ChatMsg>,
    pub(crate) participants: Vec<String>,
    pub(crate) names: HashMap<String, String>,
    pub(crate) joined: bool,
    pub(crate) bootstrap_peers: Vec<String>,
    /// Signers we've seen a verified Leave from. Used to suppress the
    /// follow-up NeighborDown "disconnected" message for an intentional
    /// departure. Cleared when the same signer rejoins.
    pub(crate) left_signers: HashSet<String>,
}

#[derive(Clone, PartialEq, Default)]
pub(crate) struct AppState {
    pub(crate) rooms: Vec<RoomState>,
    pub(crate) active_topic: Option<String>,
    /// Bootstrap value from the encrypted profile; ChatRoom owns the live name state.
    pub(crate) name: String,
    pub(crate) join_error: Option<String>,
}

pub(crate) enum Action {
    SetInitial(AppState),
    AddRoom(RoomState),
    RemoveRoom(String),
    SetActive(String),
    LocalSend { topic: String, msg: ChatMsg },
    Joined(String),
    NeighborUp { topic: String, endpoint: String },
    NeighborDown { topic: String, endpoint: String },
    RecvChat { topic: String, from_endpoint: String, from_name: String, text: String },
    System { topic: String, text: String },
    Identify { topic: String, endpoint: String, name: String },
    /// Verified signed Leave from a peer. Different from NeighborDown
    /// (transport-level disconnect, which can be transient or induced).
    PeerLeft { topic: String, endpoint: String },
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
            Action::RemoveRoom(topic) => {
                // Removes the room from the UI and the persisted profile.
                // The protocol-level subscription teardown is driven by
                // ChatGossipCommand::Leave, which the caller (do_leave)
                // dispatches before/around this state action.
                s.rooms.retain(|r| r.topic_id != topic);
                if s.active_topic.as_deref() == Some(topic.as_str()) {
                    s.active_topic = s.rooms.first().map(|r| r.topic_id.clone());
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
                    // A peer that previously signed Leave is now back. Clear
                    // the suppression so a future disconnect renders again.
                    r.left_signers.remove(&endpoint);
                }
            }
            Action::NeighborDown { topic, endpoint } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    r.participants.retain(|p| p != &endpoint);
                    // If we already showed "X left" (from a verified Leave),
                    // suppress the redundant transport-level "disconnected"
                    // message for the same peer.
                    if r.left_signers.contains(&endpoint) {
                        return Rc::new(s);
                    }
                    let display = r.names.get(&endpoint).cloned().unwrap_or_else(|| {
                        let short: String = endpoint.chars().take(12).collect();
                        format!("{short}…")
                    });
                    r.messages.push(sys_msg(&format!("*** {display} disconnected")));
                }
            }
            Action::PeerLeft { topic, endpoint } => {
                if let Some(r) = s.rooms.iter_mut().find(|r| r.topic_id == topic) {
                    r.participants.retain(|p| p != &endpoint);
                    let display = r.names.get(&endpoint).cloned().unwrap_or_else(|| {
                        let short: String = endpoint.chars().take(12).collect();
                        format!("{short}…")
                    });
                    r.messages.push(sys_msg(&format!("*** {display} left the room")));
                    r.left_signers.insert(endpoint);
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

pub(crate) fn sys_msg(text: &str) -> ChatMsg {
    ChatMsg {
        from_endpoint: String::new(),
        from_name: String::new(),
        text: text.into(),
        is_system: true,
    }
}
