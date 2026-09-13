# pass-syncd

The embedded, single-purpose real-time sync daemon behind `pass`'s
cross-device sync. A sibling fork of
[`reading-list-syncd`](https://github.com/antoniopicone/karakeep-browser-extension/tree/main/native/reading-list-syncd)
(itself a scoped-down fork of
[serverless-sync](https://github.com/antoniopicone/serverless-sync)): `src/core.rs`
(the CRDT reducer) and `src/discovery.rs` (peer discovery over
Tailscale/LAN broadcast/PEX) are carried over near-verbatim — only two
port constants in `discovery.rs` were changed, so this daemon doesn't
cross-talk with `reading-list-syncd` if both run on the same machine (see
that file's doc comment). `src/main.rs`/`src/persist.rs` are adapted the
same way reading-list-syncd's were: one dataset (this vault's entries)
instead of a multi-application registry, no per-application secret, and —
unlike reading-list-syncd — no Native Messaging bridge mode either, since
none of `pass`'s clients are spawned per-call by a browser; they all just
speak plain HTTP to the loopback API below.

This replaces `pass`'s previous `pass watch`/`pass merge`-on-a-shared-folder
sync flow: instead of periodically reconciling two full copies of the KDBX
file, every client pushes each change the instant it happens and pulls
others' changes continuously, over a CRDT op log replicated peer-to-peer —
no Nextcloud/shared-folder dependency required.

## Mode

```
pass-syncd serve [--device NAME] [--port N] [--data PATH]
                  [--bootstrap host:port,...] [--advertise ADDR]
                  [--peer-prefix PREFIX] [--no-lan-discovery]
```

The long-running background daemon (install as a systemd/launchd/Task
Scheduler service — see [`service/`](service/)): owns the CSV ledger, runs
the peer-to-peer anti-entropy loop against other devices, and exposes a
small loopback-only HTTP control API on `--port` (default `47210`). Every
client finds it automatically even on a non-default `--port`, without
needing to set `PASS_SYNCD_URL` themselves: `serve` records the port it
actually bound at `<data-dir>/port`, and `passlib::sync` (the local client
every `pass` frontend uses) reads that same file if present.

`--device` defaults to a randomly generated id, persisted at
`<data-dir>/device_id` so it survives restarts — unlike reading-list-syncd,
which defaults to the fixed string `"device-1"` and expects the operator to
pass a unique `--device` per machine. `pass-syncd` is meant to be installed
with zero flags via the `service/` scripts, so a safe unique default
matters more here: two devices silently sharing one id would make the CRDT
under-count their divergent writes.

## Encryption

**This is the one substantive divergence from reading-list-syncd**, whose
plaintext reading-list URLs don't need it. `pass-syncd` itself never sees a
password in the clear: every `value` it stores in the CSV ledger, serves
over its local API, or relays peer-to-peer is already an opaque
`base64(nonce ‖ ciphertext)` blob by the time it reaches here.

Encryption happens one layer up, in `passlib::sync` (see
`../passlib/src/sync.rs`): each device derives an AES-256-GCM key from the
vault's own master password plus a random salt stored in the vault's KDBX
file (a custom meta field, generated once at `pass init`), so any device
holding the master password derives the same key — no separate secret to
distribute. `pass-syncd`'s job stays exactly as content-agnostic as
reading-list-syncd's: replicate opaque blobs by `entity` (a password
entry's UUID) with last-writer-wins semantics (see `core.rs`), never
inspecting `value`.

The one exception is the salt itself, replicated under the reserved entity
id `__pass_sync_salt__` alongside every real push — see "Joining from a
brand-new device" below for why, and why that's fine: a KDF salt isn't a
secret by design (the same reason a password hash is stored right next to
its own salt), so it's the one value `passlib::sync` ever sends
unencrypted. Everything else stays exactly as opaque to this daemon as
described above.

## Joining from a brand-new device

A new device doesn't need the vault file copied to it by hand first. As
long as its `pass-syncd` can reach at least one existing device's (over the
tailnet/LAN — no vault, no client needed for this part, it's pure
daemon-to-daemon anti-entropy), running `pass init --import-from-sync` (or
the equivalent option on the GNOME/Chromium/Apple create-vault screen)
there:

1. Creates the new, empty vault as usual.
2. Notices the salt entity above is already present (some other device
   pushed it) and adopts that exact salt instead of generating an
   incompatible random one of its own.
3. Immediately pulls in every entry the mesh currently has, decrypting them
   with the key that salt (plus the master password just typed) derives.

Without `--import-from-sync` (or on a genuinely first device, where there's
nothing to import), `pass init` behaves exactly as before: an empty vault,
with its own sync salt generated lazily on the first add/update/delete.

## The CSV ledger

One row per accepted change (local or synced from a peer), appended as it
happens, at `--data` (default `~/.pass-syncd/ledger.csv`):
`device,seq,entity,kind,value,hlc`, where `value` is the encrypted blob
above — meaningless on disk without the vault's master password, so a
compromised device's ledger alone doesn't leak passwords at rest. This is
the actual source of truth, not a cache — on startup, `serve` replays every
row through `core::Replica::apply` to rebuild the in-memory state. No
compaction: see serverless-sync's README for why a CRDT op log can't just
drop old rows without also shrinking what a far-behind peer's
`/v1/ops/since` can still answer.

## HTTP surface

Local control (loopback-only — this is what passcli/pass-native-host/
pass-gnome/the Apple app call):

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/write` | `{ entity, value }` (`value: null` to delete) | `{ seq, vv }` |
| GET | `/state` | – | `{ device, entries, vv, fingerprint }` |
| POST | `/ops/since` | `{ vv }` | `{ ops }` |

Peer-to-peer (reachable from the LAN/tailnet, no loopback restriction — same
shapes as serverless-sync's per-application endpoints, minus the
`(name, token)` path segment and its own encryption envelope, since a value
here already arrives pre-encrypted):

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/v1/node` | – | `{ proto, device_id, hostname, port, entries, fingerprint }` |
| POST | `/v1/peers` | `{ peers }` | `[Peer, ...]` |
| POST | `/v1/vv` | – | `VersionVector` |
| POST | `/v1/ops/since` | `{ vv }` | `{ ops }` |
| POST | `/v1/ops` | `{ ops }` | `{ applied, vv }` |

## Known limitation: peer-to-peer transport isn't independently encrypted

Same as reading-list-syncd: the primary transport (Tailscale) already runs
inside its own WireGuard tunnel; the LAN-broadcast fallback is opt-in and
intended for a trusted home network. What travels over that transport is
still only ciphertext (see "Encryption" above), so a passive observer on an
untrusted LAN learns nothing about entry contents — only traffic metadata
(which entities changed, when, from which device). Revisit (bring
`crypto.rs` back from serverless-sync for the transport itself) if this
daemon ever needs to defend a genuinely untrusted LAN.

## Pairing devices

1. Install `pass-syncd` on each device via the matching script in
   [`service/`](service/) (`install-systemd.sh` / `install-launchd.sh` /
   `install-windows.ps1`).
2. Get every device on the same [Tailscale](https://tailscale.com) tailnet
   (or the same trusted LAN, with `--no-lan-discovery` left off). No further
   pairing step is required — the anti-entropy loop finds peers via the
   tailnet, LAN broadcast, and peer exchange automatically.
3. On the first device, open (or create) the vault with any `pass`
   client — the CLI, the GNOME app, the Chromium extension, or the Apple
   app. On every device after that, use the same master password and
   `pass init --import-from-sync` (or the equivalent create-vault option
   elsewhere) instead of copying the vault file by hand — see "Joining
   from a brand-new device" above. From then on, every change made while
   the vault is unlocked propagates to the other devices within one
   anti-entropy round (a few seconds).

If two devices should stay on separate tailnets/LANs with no discovery
path between them, use `--bootstrap host:port` to point one at the other's
address explicitly.
