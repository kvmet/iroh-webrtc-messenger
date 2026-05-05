//! Browser chat room example.
//!
//! ## Before changing serialized formats: read [`VERSIONING.md`].
//!
//! Five formats ship to real users and have stability contracts:
//! - Encrypted blobs (`crypto.rs`)
//! - Profile JSON (`storage.rs`)
//! - Wire protocol `ChatWireMessage` (`protocol.rs`)
//! - Invite link hash (`util.rs`)
//! - Backup file (`storage.rs`)
//!
//! Each format has a doc comment at its definition site spelling out
//! the rules. `VERSIONING.md` at the crate root is the rule book.
//!
//! [`VERSIONING.md`]: ../VERSIONING.md

use wasm_bindgen::prelude::*;

mod commands;
mod components;
mod crypto;
mod protocol;
mod state;
mod storage;
mod util;

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
    yew::Renderer::<components::App>::with_root(root).render();
}
