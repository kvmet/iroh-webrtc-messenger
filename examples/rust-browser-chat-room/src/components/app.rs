use std::cell::RefCell;
use std::rc::Rc;

use iroh::SecretKey;
use wasm_bindgen::{JsCast, closure::Closure};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::commands::{NodeHandle, do_host, do_join, do_leave, do_send, gossip_event_loop, init_node};
use crate::crypto::{decrypt_key, encrypt_key};
use crate::protocol::ChatGossipCommand;
use crate::state::{Action, AppState};
use crate::storage::{Profile, forget_stored, load_profile, load_stored, persist, stored_name};

use super::auth::{NewUserSetup, PassphraseGate};
use super::chat_room::ChatRoom;

#[derive(Clone, PartialEq)]
enum AppPhase {
    Checking,
    NeedPassphrase,
    NewUser,
    SpawningNode([u8; 32]),
    Ready,
    Failed(String),
}

#[function_component(App)]
pub(crate) fn app() -> Html {
    let phase = use_state(|| AppPhase::Checking);
    let node_ref: Rc<RefCell<Option<NodeHandle>>> = use_mut_ref(|| None);
    let chat_state = use_reducer(AppState::default);
    let identity_key = use_state(|| [0u8; 32]);
    let passphrase_error: UseStateHandle<Option<String>> = use_state(|| None);
    let ephemeral = use_state(|| false);
    // Name typed during NewUserSetup, kept only in memory until the chat room
    // mounts. We never persist plaintext names to localStorage.
    let pending_name: UseStateHandle<Option<String>> = use_state(|| None);
    // Live snapshot of currently-joined topic ids. Read by the pagehide
    // handler at fire time so it can dispatch a best-effort signed Leave for
    // each room when the user closes the tab.
    let live_topics: Rc<RefCell<Vec<String>>> = use_mut_ref(Vec::new);

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
        let pending_name_eff = pending_name.clone();
        use_effect_with(phase_val, move |p| {
            if let AppPhase::SpawningNode(key_bytes) = p {
                let key_bytes = *key_bytes;
                let phase = phase.clone();
                let node_ref = node_ref.clone();
                let chat_state = chat_state.clone();
                let identity_key = identity_key.clone();
                let is_ephemeral = *ephemeral_eff;
                let pending = (*pending_name_eff).clone();
                spawn_local(async move {
                    identity_key.set(key_bytes);
                    let profile = if is_ephemeral { Profile::default() } else { load_profile(&key_bytes).await };
                    match init_node(key_bytes).await {
                        Ok(handle) => {
                            let gossip = handle.gossip.clone();
                            let ep = handle.endpoint_id.clone();
                            let (profile_name, restored) = profile.into_rooms();
                            // Precedence: pending typed name > encrypted profile > stored fallback.
                            let local_name = pending
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| if profile_name.is_empty() { stored_name() } else { profile_name });
                            *node_ref.borrow_mut() = Some(handle);
                            let mut initial = AppState::default();
                            initial.active_topic = restored.first().map(|r| r.topic_id.clone());
                            initial.rooms = restored.clone();
                            initial.name = local_name.clone();
                            chat_state.dispatch(Action::SetInitial(initial));

                            // Auto-rejoin restored rooms
                            for r in &restored {
                                let _ = gossip.send(ChatGossipCommand::Join {
                                    topic: r.topic_id.clone(),
                                    room_secret: r.room_secret,
                                    peers: r.bootstrap_peers.clone(),
                                    endpoint: ep.clone(),
                                    name: local_name.clone(),
                                }).await;
                            }

                            let state = chat_state.clone();
                            spawn_local(async move {
                                gossip_event_loop(gossip, ep, state).await;
                            });
                            // Peer discovery is event-driven — see the
                            // ChatWireMessage docs in protocol.rs. No
                            // periodic heartbeat task needed here.
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

    // Keep live_topics in sync with the joined room list so the pagehide
    // handler reads an up-to-date snapshot.
    {
        let live_topics = live_topics.clone();
        let snapshot: Vec<String> = chat_state
            .rooms
            .iter()
            .filter(|r| r.joined)
            .map(|r| r.topic_id.clone())
            .collect();
        use_effect_with(snapshot.clone(), move |s| {
            *live_topics.borrow_mut() = s.clone();
            || ()
        });
    }

    // Register a pagehide listener once we reach Ready. On tab close we
    // dispatch a best-effort signed Leave for each currently-joined room.
    // Browsers cut off async work during pagehide, so this is
    // best-effort: peers may or may not receive the Leave before the
    // sender's connection drops. They'll always see the transport-level
    // NeighborDown afterward and render "X disconnected" instead.
    {
        let phase_val = (*phase).clone();
        let live_topics = live_topics.clone();
        let node_ref = node_ref.clone();
        use_effect_with(matches!(phase_val, AppPhase::Ready), move |ready| {
            let cleanup: Box<dyn FnOnce()> = if *ready {
                let live_topics = live_topics.clone();
                let node_ref = node_ref.clone();
                let handler = Closure::<dyn FnMut()>::new(move || {
                    let topics = live_topics.borrow().clone();
                    let Some(gossip) = node_ref.borrow().as_ref().map(|h| h.gossip.clone()) else {
                        return;
                    };
                    for topic in topics {
                        let g = gossip.clone();
                        spawn_local(async move {
                            let _ = g.send(ChatGossipCommand::Leave { topic }).await;
                        });
                    }
                });
                let window = web_sys::window().expect("no window");
                let _ = window.add_event_listener_with_callback(
                    "pagehide",
                    handler.as_ref().unchecked_ref(),
                );
                Box::new(move || {
                    if let Some(window) = web_sys::window() {
                        let _ = window.remove_event_listener_with_callback(
                            "pagehide",
                            handler.as_ref().unchecked_ref(),
                        );
                    }
                    drop(handler);
                })
            } else {
                Box::new(|| ())
            };
            cleanup
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
                let pending_name = pending_name.clone();
                Callback::from(move |(kb, pass, name): ([u8; 32], Option<String>, String)| {
                    let phase = phase.clone();
                    let pending_name = pending_name.clone();
                    spawn_local(async move {
                        if let Some(p) = pass {
                            if !p.is_empty() {
                                if let Ok((enc, salt)) = encrypt_key(&kb, &p).await {
                                    let _ = persist(&enc, &salt);
                                }
                            }
                        }
                        pending_name.set(if name.is_empty() { None } else { Some(name) });
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
                let on_leave_room = {
                    let gossip = gossip.clone();
                    let chat_state = chat_state.clone();
                    Callback::from(move |topic_id: String| {
                        let g = gossip.clone();
                        let cs = chat_state.clone();
                        spawn_local(async move { do_leave(g, topic_id, cs).await; });
                    })
                };
                html! {
                    <ChatRoom {endpoint_id} {state} {key_bytes} {persistent} ephemeral={is_ephemeral} {initial_name} {on_host} {on_join} {on_send} {on_switch_room} {on_leave_room} {on_clear_error} />
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
