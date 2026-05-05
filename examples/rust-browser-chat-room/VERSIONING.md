# Versioning & forward-compatibility contracts

**Read this before changing any of the formats listed below.** The chat
example has four serialized boundaries that ship to real users. Once we
have users, breaking these silently means losing their chats, locking
them out of their identity, or making old peers unintelligible.

This doc is the rule book. Each format has a stability contract enforced
by code structure (versioning) and convention (don't remove fields).

## The four formats

| Format | Where | Crosses what boundary |
|---|---|---|
| **Crypto container** | `iroh.id.enc`, `iroh.profile` blobs | Time (old data, new code) |
| **Profile JSON** | inside the encrypted `iroh.profile` blob | Time |
| **Wire protocol** (`ChatWireMessage`) | gossip messages between peers | Network (peer A version != peer B version) |
| **Invite link** | URL hash | Time + network (old links, new clients) |
| **Backup file** | exported `iroh-messenger-backup.json` | Time (user re-imports later) |

Each is documented in the source where it's defined. The rules below
apply universally; the source comments are the authoritative reference
for the format itself.

## Crypto container

**Source:** `src/crypto.rs`

**Layout:** `[1 byte version][12 byte IV][AES-GCM ciphertext + 16 byte tag]`

**Rule:** to change KDF iterations, cipher, IV size, or anything else
about how the binary blob is produced or consumed:

1. Bump `ENC_VERSION_CURRENT` (e.g. 1 → 2)
2. Add a new arm to the `decrypt_*` `match`: `2 => { ... new params ... }`
3. **Keep the old arm.** Existing user data was written under the old
   version and you still need to read it.
4. New saves use the new version. Old saves keep working.
5. (Optional) lazy-migrate: after successful decrypt of an old version,
   re-encrypt with the new version on next save.

**Don't:** change params silently without bumping. We've already broken
this once (PBKDF2 100k → 600k pre-launch); doing it post-launch locks
users out forever.

## Profile JSON

**Source:** `src/storage.rs` — `Profile`, `RoomSave`

**Rule:** treat as a long-lived JSON schema.

Safe changes:
- **Adding a field:** new field must have `#[serde(default)]`. Old data
  missing the field deserializes as the default value.
- **Adding a struct:** fine.

Unsafe changes (require bumping `PROFILE_VERSION_CURRENT`):
- Renaming a field. Use `#[serde(rename = "old", alias = "new")]` if
  you must.
- Removing a field. Mark unused but leave it in the struct.
- Changing a field's type or semantics.
- Restructuring (splitting/merging fields).

**To bump the schema version:**

1. Bump `PROFILE_VERSION_CURRENT`
2. In `load_profile`, after deserializing, dispatch on `profile.version`
   and run a migration that produces the current shape.
3. `save_profile` always stamps `PROFILE_VERSION_CURRENT`, so subsequent
   reads see the new shape.
4. Keep the old fields and migration code around indefinitely — users
   who haven't logged in for a long time still have v1 data.

## Wire protocol

**Source:** `src/protocol.rs` — `ChatWireMessage`

This is over-the-wire JSON between peers. Different peers will be on
different versions of the app indefinitely (cached browser tabs, slow
deployments). There is **no version field** by design — forward
compatibility is by convention, not negotiation.

Safe changes:
- **Adding a variant:** old peers receive it as `Unknown` and silently
  no-op. Don't put critical-path semantics in a new variant; old peers
  will not act on it.
- **Adding a field to an existing variant:** must be
  `#[serde(default)]`.

Unsafe changes (will break old or new peers, depending on direction):
- Removing a variant or renaming one (changes the `type` tag).
- Removing a required field.
- Renaming a field.
- Changing a field's type.

**Don't:** ever bump a wire "version". Just evolve the schema additively
forever. If you genuinely need an incompatible break, ship a new ALPN
and run two protocols in parallel during a deprecation window.

## Invite link

**Source:** `src/util.rs` — `parse_invite`, `make_invite_url`

**Layout:** `<origin><path>#<topic_b64>|<endpoint_id>[|<urlencoded_name>]`

**Rule:** positional, pipe-separated. The parser already tolerates extra
trailing segments (so a v1+ extension can append data without breaking
older clients).

Safe additions:
- Append a new optional positional field after `name`. Old clients will
  ignore it. New clients should fail soft if it's missing.

Unsafe changes:
- Reordering existing positional fields.
- Changing the meaning of an existing position.
- Inserting a new field in the middle.

**For a major break (e.g. moving to a structured token):** prefix with
a version tag — `#v2:...`. The current parser will fail cleanly on the
topic decode and surface "Invalid invite link," which is the right
behavior for an incompatible upgrade.

## Backup file

**Source:** `src/storage.rs` — `Backup`, `BACKUP_FORMAT_TAG`

**Layout:** JSON document with `format`, `version`, `id_enc`, `id_salt`,
`profile?` fields.

Same rule as Profile JSON: additive changes need `#[serde(default)]`,
restructures need a version bump in `import_backup`'s validation.

The current `import_backup` rejects any version > 1. To support a new
version, raise that ceiling and add migration logic.

## Recipes

### "I want to add a feature that needs a new field"

1. Add the field to the appropriate struct with `#[serde(default)]`.
2. Done. No version bump needed.

### "I want to add a new wire variant"

1. Add the variant to `ChatWireMessage`.
2. Add the variant to the receive-side `match` in `protocol.rs`.
3. Done. Old peers get `Unknown`, no-op.

### "I want to change how the identity is encrypted"

1. Bump `ENC_VERSION_CURRENT` in `crypto.rs`.
2. Add new `match` arm in both `decrypt_key` and `decrypt_data`.
3. Keep the old arms.
4. Test with an existing account from before the change.

### "I want to restructure Profile in a way `#[serde(default)]` can't handle"

1. Bump `PROFILE_VERSION_CURRENT`.
2. Convert `load_profile` to deserialize into an intermediate enum that
   covers v1 and v2 shapes, then transform v1 into the current shape
   before returning `Profile`.
3. Keep the v1 deserialize types and migration code around indefinitely.

## When in doubt

Bias toward forward-compat-by-default. Adding `#[serde(default)]` to a
new field costs nothing. Removing a field that turned out to be load-
bearing will cost you a support thread.

If you're unsure whether a change is breaking, write down what an old
client would see and what a new client would see, in both directions.
If any of the four cells produces a parse error or wrong behavior,
you're breaking compat — version-bump.
