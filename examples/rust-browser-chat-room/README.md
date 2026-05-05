# Browser chat room (PoC)

A Yew + WebAssembly chat app built on `iroh-webrtc-transport` and `iroh-gossip`. Peers connect directly via WebRTC; messages are gossiped over a mesh of subscribers to a per-room topic and end-to-end encrypted with a room-derived AES key.

This is a proof-of-concept. The crypto choices are deliberate and the threat model below is honest about what is and isn't protected.

## How a room works

1. The host generates a 32-byte random **room secret** and shares it via an invite URL of the form `…#v2:<secret_b64>|<host_endpoint>[|<name>]`. The secret lives in the URL fragment, so it is never sent to the page server.
2. Both peers derive `(topic_id, aes_key)` from the secret via HKDF-SHA256 with disjoint info strings. `topic_id` is the public iroh-gossip topic; `aes_key` is secret and used only for AES-256-GCM.
3. Each peer signs every gossip message (`AboutMe`, `Chat`, `Leave`) with their Ed25519 identity key. Receivers verify the signature and reject messages with replayed nonces before delivering them to the UI.

## Security properties

What the app does protect:

- **Per-message authenticity.** Every `AboutMe`, `Chat`, and `Leave` is Ed25519-signed; the receiver verifies before display. Domain-separated, NUL-terminated tags prevent cross-variant signature reuse. Identity is the verified signer pubkey; there is no self-claimed identity field on the wire.
- **Confidentiality from non-members.** Message contents are AES-256-GCM-encrypted with the room-derived key. Anyone outside the room (including iroh-gossip relays that don't share the topic) cannot read messages.
- **Replay protection.** Each authenticated message carries a 16-byte random nonce. The receiver maintains a bounded per-signer LRU of seen nonces and drops duplicates.
- **Topic-id / AES-key separation.** Because the topic id and the AES key are independent HKDF outputs, leaks of the topic id (logs, dependency tracing, future debug exports) do not compromise message encryption.
- **Identity at rest.** The user's Ed25519 secret key is stored in localStorage encrypted with AES-256-GCM under a key derived from the user's passphrase via PBKDF2-SHA256 (600,000 iterations). The encrypted profile (room list, screen name) is encrypted with a key derived from the identity. Plaintext screen names are never written.
- **Deliberate-departure signaling.** A signed `Leave` message lets peers distinguish an intentional exit ("X left the room") from a transient transport disconnect ("X disconnected"), and a best-effort `pagehide` listener fires `Leave` when the user closes the tab.
- **Browser-layer hardening.** A strict Content-Security-Policy meta tag restricts script and connection origins. The Tailwind CDN script is loaded with a Subresource-Integrity hash, and the WASM bundle is served with one as well, so a CDN compromise can't silently swap the code that runs alongside the app.

What WebRTC and iroh provide for free, on top:

- WebRTC data channels run over DTLS, so the gossip-relay layer is also protected at the transport hop.
- Iroh QUIC connections used for signaling are TLS-1.3-style, authenticated to the peer's Ed25519 pubkey end-to-end.

## Threat model — what is *not* protected

Be honest with yourself before using this for anything sensitive.

- **The invite is the capability.** Anyone who obtains the invite URL has full read and write access to the room. There is no asymmetric admission control, no per-member key, and no way to rotate the room key. Treat the invite like a password.
- **No forward secrecy.** The room's AES key is fixed for the lifetime of the room. If the invite leaks at any later point, all *previously captured* ciphertext is decryptable. WebRTC's DTLS provides FS at the transport hop, but the application-layer encryption (which is what protects against gossip-relay observers) does not. Forward secrecy and post-compromise security are planned via an MLS pass; see Roadmap.
- **Connection metadata is exposed to third parties.**
  - Iroh's public relays (n0.computer by default) see your iroh pubkey, the iroh pubkeys of peers you connect to, traffic timing, and traffic volume per peer. Message contents stay encrypted, but the social graph and activity pattern do not.
  - STUN (Google's `stun.l.google.com:19302` by default) sees your public IP at connection setup time.
  - These are infrastructure-level leaks, not fixable in the app. Self-hosting iroh relays and a STUN server would close them; otherwise document and accept.
- **Identity correlation across rooms.** Your iroh / signing pubkey is the same in every room you join. Anyone present in two of your rooms can link your identity. This is a deliberate property of the persistent-identity model.
- **Group membership leaks via mesh observation.** A peer in a room learns the iroh pubkeys of other peers in the same room, both from `NeighborUp` events and from `AboutMe` broadcasts.
- **Signed `Leave` on tab close is best-effort.** Browsers cut off async work during `pagehide`, so peers may see only a transport-level disconnect rather than the deliberate-departure signal.
- **Local storage is per-origin.** If the app is hosted on a shared origin (e.g. `username.github.io/...`), other apps under the same origin can read the encrypted identity blob. Decrypting it requires the passphrase, but the ciphertext can be exfiltrated.
- **This is a PoC.** The crypto has not been independently reviewed. Do not use for threats where compromise has serious real-world consequences.

## Roadmap

- **MLS** for the room key layer, providing forward secrecy and post-compromise security with cheap key rotation on membership change. The wire format already isolates the AES key from the topic id and uses verified signer identity, both of which simplify dropping MLS in.
- Optional self-hosted iroh relay and STUN config for users who want to close the metadata channel.

## Build

```sh
trunk build --release
```

See the workspace `Trunk.toml`. CI builds and deploys to GitHub Pages on push to `main`; the `docs/` directory is gitignored.
