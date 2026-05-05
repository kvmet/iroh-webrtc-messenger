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
- **No forward secrecy or member revocation.** The room's AES key is fixed for the lifetime of the room, and "removing" a member has no cryptographic meaning — they keep the secret. See [Forward secrecy and member revocation](#forward-secrecy-and-member-revocation) below for the gap, what it would take to close it, and what mitigations work today.
- **Connection metadata is exposed to third parties.**
  - Iroh's public relays (n0.computer by default) see your iroh pubkey, the iroh pubkeys of peers you connect to, traffic timing, and traffic volume per peer. Message contents stay encrypted, but the social graph and activity pattern do not.
  - STUN (Google's `stun.l.google.com:19302` by default) sees your public IP at connection setup time.
  - These are infrastructure-level leaks, not fixable in the app. Self-hosting iroh relays and a STUN server would close them; otherwise document and accept.
- **Identity correlation across rooms.** Your iroh / signing pubkey is the same in every room you join. Anyone present in two of your rooms can link your identity. This is a deliberate property of the persistent-identity model.
- **Group membership leaks via mesh observation.** A peer in a room learns the iroh pubkeys of other peers in the same room, both from `NeighborUp` events and from `AboutMe` broadcasts.
- **Signed `Leave` on tab close is best-effort.** Browsers cut off async work during `pagehide`, so peers may see only a transport-level disconnect rather than the deliberate-departure signal.
- **Local storage is per-origin.** If the app is hosted on a shared origin (e.g. `username.github.io/...`), other apps under the same origin can read the encrypted identity blob. Decrypting it requires the passphrase, but the ciphertext can be exfiltrated.
- **This is a PoC.** The crypto has not been independently reviewed. Do not use for threats where compromise has serious real-world consequences.

## Forward secrecy and member revocation

The chat layer does not provide forward secrecy or post-compromise security. The room's AES key is fixed for the lifetime of the room. Concretely:

- An attacker who captures encrypted wire traffic and *later* obtains the room secret (compromise of a member's device, the invite forwarded to the wrong person, social engineering) can decrypt every captured message.
- A member who has been "removed" from a room socially has no cryptographic equivalent of removal. They retain the room secret indefinitely and can rejoin the gossip mesh whenever they want.

### What the right fix looks like

The standard answer is **MLS** (Messaging Layer Security, RFC 9420). MLS provides:

- **Forward secrecy:** per-message ratcheted keys, old keys deleted after use, so a future compromise of the device key can't decrypt captured ciphertext.
- **Post-compromise security:** a `Commit` operation rotates the entire group state, so an attacker who briefly held full state can no longer decrypt new messages once the next Commit lands.
- **Cryptographic membership:** the group is an agreed-upon, signed set of members. Removal is meaningful — a removed member is locked out of all subsequent epochs.

Integrating MLS into this app would require, roughly:

1. **A library.** `openmls` is the mature Rust impl, ~400-600 KB additional wasm bundle.
2. **An ordered delivery channel for handshake messages.** MLS assumes reliable, ordered delivery of `Commit` / `Welcome` / `Proposal`. The current gossip layer is best-effort and unordered. The simplest workable model is a designated orderer (the room creator signs Commits; other members propose) with epoch-mismatch retry on receive.
3. **A revised invite flow.** "Invite as shared secret = perpetual capability" has to give way to a 2-step handshake: the joiner sends a `KeyPackage` to a current member, who issues an `Add` + `Welcome`. Either the inviter has to be online to complete the handshake, or pending invites need to be cached.
4. **Wire format v3** to carry MLS application messages and the new handshake variants in place of the current per-message AES-GCM scheme. v2 invites and v2 saved profiles would not be readable.
5. **State persistence.** Each member needs to durably store MLS group state (epoch, ratchet tree, exporter secrets), encrypted at rest like the rest of the profile.

This is a multi-week effort and adds non-trivial bundle size. For the PoC's targeted use cases (ephemeral or low-stakes group chat) the cost outweighs the benefit. If your use case actually depends on forward secrecy or cryptographic revocation, this app is the wrong tool — use Signal.

### Mitigations that work today

Several properties of the current design narrow the practical gap, and a few user-side practices narrow it further:

- **No message archive.** The app does not persist message history. When you reload the page, the chat log is gone. An attacker who later steals the room secret cannot decrypt anything that wasn't captured on the wire at the time. To retroactively decrypt your conversation, an adversary would need both the room secret *and* a full ciphertext capture from the relevant time window.
- **Use ephemeral identities for sensitive conversations.** "Sign in for this session only" gives you a fresh Ed25519 identity that doesn't persist. The trade-off is no rejoinable rooms across sessions; the upside is the device key isn't sitting on disk to be stolen later.
- **Rotate rooms when membership changes.** If someone leaves a room and you want to exclude them going forward, create a new room (new room secret, new invite) and re-invite the remaining members. The old room becomes a graveyard you abandon. This is the manual equivalent of an MLS `Commit` after a `Remove`.
- **Don't share invites through channels that retain them.** The invite URL contains the room secret in the URL fragment. The fragment is never sent to a server, but it does end up in browser history, clipboard managers, screenshot apps, and chat-app link previews. Treat invite links like passwords.
- **Avoid the backup feature for high-sensitivity rooms.** The backup file contains your encrypted identity and saved rooms (including their room secrets), encrypted with your passphrase. A weak passphrase plus a leaked backup file means everything in those rooms is recoverable.

## Other planned work

- Optional self-hosted iroh relay and STUN config for users who want to close the metadata-leak channel described in the threat model.

## Build

```sh
trunk build --release
```

See the workspace `Trunk.toml`. CI builds and deploys to GitHub Pages on push to `main`; the `docs/` directory is gitignored.
