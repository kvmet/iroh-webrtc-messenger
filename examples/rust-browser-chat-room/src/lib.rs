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
