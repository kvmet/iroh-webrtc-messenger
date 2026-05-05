use iroh::SecretKey;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::storage::{save_name, stored_name};

// ── PassphraseGate ────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub(crate) struct PassphraseGateProps {
    pub(crate) on_submit: Callback<String>,
    pub(crate) on_forget: Callback<()>,
    pub(crate) on_ephemeral: Callback<()>,
    pub(crate) error: Option<String>,
}

#[function_component(PassphraseGate)]
pub(crate) fn passphrase_gate(props: &PassphraseGateProps) -> Html {
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
        Callback::from(move |_: MouseEvent| {
            confirm_forget.set(false);
            cb.emit(());
        })
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
pub(crate) struct NewUserSetupProps {
    pub(crate) on_ready: Callback<([u8; 32], Option<String>)>,
}

#[function_component(NewUserSetup)]
pub(crate) fn new_user_setup(props: &NewUserSetupProps) -> Html {
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
