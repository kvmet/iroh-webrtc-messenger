use std::collections::{HashMap, HashSet};

use iroh::SecretKey;
use iroh_gossip::TopicId;
use iroh_webrtc_transport::browser::{
    BrowserDialTransportPreference, BrowserProtocolHandle, BrowserWebRtcNode,
    BrowserWebRtcNodeConfig,
};
use wasm_bindgen::JsValue;
use yew::prelude::*;

use crate::crypto::derive_room_keys;
use crate::protocol::{
    ChatGossipCommand, ChatGossipEvent, ChatGossipProtocol, MAX_NAME_CHARS, MAX_TEXT_CHARS,
};
use crate::state::{Action, AppState, ChatMsg, RoomMode, RoomState, sys_msg};
use crate::util::{decode_topic_b64, parse_invite, truncate_chars};

pub(crate) struct NodeHandle {
    pub(crate) _node: BrowserWebRtcNode,
    pub(crate) gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    pub(crate) endpoint_id: String,
}

pub(crate) async fn init_node(key_bytes: [u8; 32]) -> std::result::Result<NodeHandle, JsValue> {
    let secret_key = SecretKey::from_bytes(&key_bytes);
    let node = BrowserWebRtcNode::builder(
        BrowserWebRtcNodeConfig::default()
            .with_protocol_transport_preference(BrowserDialTransportPreference::WebRtcOnly),
        secret_key,
    )
    .protocol(ChatGossipProtocol::new(key_bytes))
    .map_err(|e| JsValue::from_str(&e.to_string()))?
    .spawn()
    .await?;

    let gossip = node.protocol::<ChatGossipProtocol>().await?;
    let endpoint_id = node.endpoint_id().to_owned();
    Ok(NodeHandle { _node: node, gossip, endpoint_id })
}

pub(crate) async fn gossip_event_loop(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    local_ep: String,
    state: UseReducerHandle<AppState>,
) {
    loop {
        let Ok(Some(event)) = gossip.next_event().await else { break };
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
            ChatGossipEvent::PeerLeft { topic, endpoint } => {
                if endpoint != local_ep {
                    state.dispatch(Action::PeerLeft { topic, endpoint });
                }
            }
        }
    }
}

pub(crate) async fn do_host(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    endpoint: String,
    secret_b64: String,
    room_name: String,
    name: String,
    state: UseReducerHandle<AppState>,
) {
    let Some(room_secret) = decode_topic_b64(&secret_b64) else { return };
    let room_keys = derive_room_keys(&room_secret);
    let topic_id = TopicId::from_bytes(room_keys.topic_id).to_string();

    state.dispatch(Action::AddRoom(RoomState {
        topic_id: topic_id.clone(),
        room_secret,
        name: room_name.clone(),
        mode: RoomMode::Hosting,
        messages: vec![sys_msg(&format!("*** Hosting #{room_name}. Share the invite link."))],
        participants: vec![],
        joined: false,
        names: HashMap::new(),
        bootstrap_peers: vec![],
        left_signers: HashSet::new(),
    }));

    let _ = gossip
        .send(ChatGossipCommand::Join {
            topic: topic_id,
            room_secret,
            peers: vec![],
            endpoint,
            name,
        })
        .await;
}

pub(crate) async fn do_join(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    endpoint: String,
    invite: String,
    room_name: String,
    name: String,
    state: UseReducerHandle<AppState>,
) -> std::result::Result<(), String> {
    let (room_secret, host, _proposed_name) = parse_invite(&invite)
        .ok_or_else(|| String::from("Invalid invite link"))?;
    if host == endpoint {
        return Err("That's your own invite link.".into());
    }
    let room_keys = derive_room_keys(&room_secret);
    let topic_id = TopicId::from_bytes(room_keys.topic_id).to_string();

    state.dispatch(Action::AddRoom(RoomState {
        topic_id: topic_id.clone(),
        room_secret,
        name: room_name.clone(),
        mode: RoomMode::Joined,
        messages: vec![sys_msg(&format!("*** Joining #{room_name}…"))],
        participants: vec![],
        joined: false,
        names: HashMap::new(),
        bootstrap_peers: vec![host.clone()],
        left_signers: HashSet::new(),
    }));

    let _ = gossip
        .send(ChatGossipCommand::Join {
            topic: topic_id,
            room_secret,
            peers: vec![host],
            endpoint,
            name,
        })
        .await;
    Ok(())
}

/// Send Leave to the gossip protocol (tears down the subscription) and
/// remove the room from local UI state.
pub(crate) async fn do_leave(
    gossip: BrowserProtocolHandle<ChatGossipProtocol>,
    topic_id: String,
    state: UseReducerHandle<AppState>,
) {
    let _ = gossip.send(ChatGossipCommand::Leave { topic: topic_id.clone() }).await;
    state.dispatch(Action::RemoveRoom(topic_id));
}

pub(crate) async fn do_send(
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
        .send(ChatGossipCommand::Send {
            topic: topic_id,
            from_endpoint: endpoint,
            from_name: name,
            text,
        })
        .await;
}
