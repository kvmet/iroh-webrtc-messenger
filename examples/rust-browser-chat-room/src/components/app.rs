use std::cell::RefCell;
use std::rc::Rc;

use iroh::SecretKey;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::commands::{NodeHandle, do_host, do_join, do_send, gossip_event_loop, init_node};
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
                            let (profile_name, restored) = profile.into_rooms();
                            let local_name = if profile_name.is_empty() { stored_name() } else { profile_name };
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
