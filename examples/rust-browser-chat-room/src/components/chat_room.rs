use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use iroh_gossip::TopicId;
use js_sys::Uint8Array;
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlElement, HtmlInputElement, HtmlTextAreaElement};
use yew::prelude::*;

use crate::state::{AppState, RoomMode};
use crate::storage::{export_backup, save_profile};
use crate::util::{copy_to_clipboard, download_text, endpoint_icon_svg, make_invite_url, make_qr_svg, parse_invite};

#[derive(Properties, PartialEq)]
pub(crate) struct ChatRoomProps {
    pub(crate) endpoint_id: String,
    pub(crate) state: AppState,
    pub(crate) key_bytes: [u8; 32],
    /// Encrypted profile (rooms + name) is being saved
    pub(crate) persistent: bool,
    /// One-shot session: nothing saves anywhere
    pub(crate) ephemeral: bool,
    pub(crate) initial_name: String,
    pub(crate) on_host: Callback<(String, String, String)>,     // (topic_b64, room_name, screen_name)
    pub(crate) on_join: Callback<(String, String, String)>,     // (invite, room_name, screen_name)
    pub(crate) on_send: Callback<(String, String, String)>,     // (text, name, topic_id)
    pub(crate) on_switch_room: Callback<String>,                // topic_id
    pub(crate) on_leave_room: Callback<String>,                 // topic_id
    pub(crate) on_clear_error: Callback<()>,
}

#[function_component(ChatRoom)]
pub(crate) fn chat_room(props: &ChatRoomProps) -> Html {
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
    let confirm_leave: UseStateHandle<Option<String>> = use_state(|| None);
    let qr_url: UseStateHandle<Option<String>> = use_state(|| None);
    let sidebar_open = use_state(|| false);

    // On mount, decide what to do with a URL hash invite:
    //   - if it points at a room we already have, just switch to it
    //   - otherwise pre-fill the proposed room name and open the join modal
    use_effect_with((), {
        let host_input = host_input.clone();
        let show_join_modal = show_join_modal.clone();
        let room_name_input = room_name_input.clone();
        let rooms = props.state.rooms.clone();
        let switch = props.on_switch_room.clone();
        move |_| {
            if !(*host_input).is_empty() {
                if let Some((topic_bytes, _host, name)) = parse_invite(&host_input) {
                    let topic_id = TopicId::from_bytes(topic_bytes).to_string();
                    if rooms.iter().any(|r| r.topic_id == topic_id) {
                        switch.emit(topic_id);
                    } else {
                        if let Some(n) = name {
                            room_name_input.set(n);
                        }
                        show_join_modal.set(true);
                    }
                } else {
                    show_join_modal.set(true);
                }
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
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            // Persistent sessions save via the encrypted profile effect.
            // Non-persistent sessions never persist the screen name.
            name.set(el.value());
        })
    };
    let on_host_input = {
        let host_input = host_input.clone();
        let room_name_input = room_name_input.clone();
        Callback::from(move |e: InputEvent| {
            let el: HtmlInputElement = e.target_unchecked_into();
            let v = el.value();
            // Auto-fill the room name from the pasted invite, but only if the
            // user hasn't customized the field yet.
            if (*room_name_input).as_str() == "general" {
                if let Some((_, _, Some(name))) = parse_invite(&v) {
                    room_name_input.set(name);
                }
            }
            host_input.set(v);
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

    let titlebar_right = match active_room {
        Some(room) => {
            let active = room.participants.len();
            let known = room.bootstrap_peers.len();
            let dot = if active == 0 && known == 0 {
                "text-gray-300"
            } else if active == 0 {
                "text-red-400"
            } else if active < known {
                "text-yellow-300"
            } else {
                "text-green-400"
            };
            html! {
                <>
                    <span class={dot} title={format!("{active} active / {known} known")}>{"●"}</span>
                    <span>{format!("#{} {}/{}", room.name, active, known)}</span>
                </>
            }
        }
        None => html! { <span>{"WebRTC P2P"}</span> },
    };

    html! {
        <div class="aim-window flex flex-col h-full">
            <div class="aim-titlebar">
                <button class="md:hidden aim-btn px-2 py-1 text-sm leading-none mr-1"
                    onclick={Callback::from({let s = sidebar_open.clone(); move |_: MouseEvent| s.set(!*s)})}>
                    {"☰"}
                </button>
                {"🔵 Iroh Messenger"}
                <span class="ml-auto font-normal opacity-75 text-[10px] truncate flex items-center gap-1">
                    { titlebar_right }
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
                            <button class="ml-auto aim-btn px-2 py-1 text-sm leading-none"
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
                            <button class="ml-auto aim-btn px-2 py-1 text-sm leading-none"
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
                            <button class="ml-auto aim-btn px-2 py-1 text-sm leading-none"
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

            // Outside-click catcher for meatball menu. Sits below the sidebar
            // (z-20) so menu items inside the sidebar still receive clicks.
            if open_menu.is_some() {
                <div class="fixed inset-0" style="z-index:15"
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
                        if props.persistent {
                            <button
                                class="mt-2 text-[10px] text-blue-700 underline cursor-pointer bg-transparent border-0 p-0"
                                onclick={Callback::from(|_: MouseEvent| {
                                    if let Some(json) = export_backup() {
                                        download_text("iroh-messenger-backup.json", &json);
                                    }
                                })}>
                                {"Export backup"}
                            </button>
                        }
                    </div>

                    <div class="p-2 border-b border-[#808080] flex gap-1">
                        <button class="aim-btn flex-1"
                            onclick={Callback::from({
                                let s = show_host_modal.clone();
                                let rn = room_name_input.clone();
                                move |_: MouseEvent| { rn.set("general".into()); s.set(true); }
                            })}>
                            {"New Room"}
                        </button>
                        <button class="aim-btn flex-1"
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
                                        let invite_url = make_invite_url(room.topic_bytes, &props.endpoint_id, &room.name)
                                            .unwrap_or_default();
                                        html! {
                                            <li class="relative">
                                                <div class={if is_active { "flex items-center bg-[#000080] text-white" } else { "flex items-center" }}>
                                                    <span class="flex-1 aim-buddy truncate"
                                                        onclick={Callback::from({
                                                            let om = open_menu.clone();
                                                            move |_: MouseEvent| {
                                                                switch_cb.emit(tid.clone());
                                                                sidebar_close.set(false);
                                                                om.set(None);
                                                            }
                                                        })}>
                                                        {format!("#{}", room.name)}
                                                        if !room.participants.is_empty() {
                                                            <span class="ml-1 opacity-70 text-[10px]">
                                                                {format!("({})", room.participants.len())}
                                                            </span>
                                                        }
                                                    </span>
                                                    <button class="aim-btn px-2 py-1 text-sm leading-none shrink-0"
                                                        onclick={Callback::from(move |e: MouseEvent| {
                                                            e.stop_propagation();
                                                            open_menu_h.set(if is_menu_open { None } else { Some(menu_tid.clone()) });
                                                        })}>
                                                        {"⋯"}
                                                    </button>
                                                </div>
                                                if open_menu.as_deref() == Some(room.topic_id.as_str()) {
                                                    <div class="aim-window absolute right-0 min-w-[160px]" style="top:100%;z-index:30">
                                                        if confirm_leave.as_deref() == Some(room.topic_id.as_str()) {
                                                            <div class="px-3 py-2 text-xs">{format!("Leave #{}?", room.name)}</div>
                                                            <button class="block w-full text-left px-3 py-2 text-sm hover:bg-[#000080] hover:text-white"
                                                                onclick={Callback::from({
                                                                    let leave_cb = props.on_leave_room.clone();
                                                                    let tid = room.topic_id.clone();
                                                                    let om = open_menu.clone();
                                                                    let cl = confirm_leave.clone();
                                                                    move |_: MouseEvent| {
                                                                        leave_cb.emit(tid.clone());
                                                                        cl.set(None);
                                                                        om.set(None);
                                                                    }
                                                                })}>
                                                                {"Yes, leave"}
                                                            </button>
                                                            <button class="block w-full text-left px-3 py-2 text-sm hover:bg-[#000080] hover:text-white"
                                                                onclick={Callback::from({
                                                                    let cl = confirm_leave.clone();
                                                                    move |_: MouseEvent| cl.set(None)
                                                                })}>
                                                                {"Cancel"}
                                                            </button>
                                                        } else {
                                                            <button class="block w-full text-left px-3 py-2 text-sm hover:bg-[#000080] hover:text-white"
                                                                onclick={Callback::from({
                                                                    let url = invite_url.clone();
                                                                    let om = open_menu.clone();
                                                                    move |_: MouseEvent| { copy_to_clipboard(&url); om.set(None); }
                                                                })}>
                                                                {"Copy invite link"}
                                                            </button>
                                                            <button class="block w-full text-left px-3 py-2 text-sm hover:bg-[#000080] hover:text-white"
                                                                onclick={Callback::from({
                                                                    let url = invite_url.clone();
                                                                    let om = open_menu.clone();
                                                                    let qr = qr_url.clone();
                                                                    move |_: MouseEvent| { qr.set(Some(url.clone())); om.set(None); }
                                                                })}>
                                                                {"Show QR code"}
                                                            </button>
                                                            <button class="block w-full text-left px-3 py-2 text-sm hover:bg-[#000080] hover:text-white text-red-700"
                                                                onclick={Callback::from({
                                                                    let cl = confirm_leave.clone();
                                                                    let tid = room.topic_id.clone();
                                                                    move |_: MouseEvent| cl.set(Some(tid.clone()))
                                                                })}>
                                                                {"Leave room"}
                                                            </button>
                                                        }
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
                                    <li class="aim-buddy font-bold text-[#000080]" style="display:flex;align-items:center;gap:3px">
                                        {identity_icon(&props.endpoint_id, &(*name))}
                                        {(*name).clone()}{" (me)"}
                                    </li>
                                    { for room.participants.iter().map(|ep| {
                                        let display = room.names.get(ep).cloned().unwrap_or_else(|| {
                                            let short: String = ep.chars().take(20).collect();
                                            format!("{short}…")
                                        });
                                        let ep = ep.clone();
                                        let d = display.clone();
                                        html! {
                                            <li class="aim-buddy" style="display:flex;align-items:center;gap:3px">
                                                {identity_icon(&ep, &d)}
                                                {display}
                                            </li>
                                        }
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
                                    let icon = identity_icon(&msg.from_endpoint, &display_name);
                                    html! {
                                        <p style="display:flex;align-items:baseline;gap:2px">
                                            {icon}
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

/// Renders an 18×18 bishop-walk identity icon with a hover tooltip showing
/// the endpoint ID and security properties of the session.
fn identity_icon(endpoint: &str, display_name: &str) -> Html {
    let svg = endpoint_icon_svg(endpoint);
    let short_id = if endpoint.len() > 28 {
        format!("{}…", &endpoint[..28])
    } else {
        endpoint.to_string()
    };
    let tooltip = format!(
        "{display_name}\nID: {short_id}\nSigned by this peer (Ed25519)\nEncrypted with the room's shared key (AES-256-GCM)\nNote: anyone with the room invite can read messages."
    );
    html! {
        <span
            title={tooltip}
            style="display:inline-block;vertical-align:middle;margin-right:3px;border-radius:2px;overflow:hidden;cursor:default;flex-shrink:0"
        >
            { Html::from_html_unchecked(svg.into()) }
        </span>
    }
}
