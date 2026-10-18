<p align="center">
  <img src="images/janus-removebg-preview.png" alt="Janus Knot" width="668">
</p>

Janus Knot is an open source Rust core for private one-to-one communication. Nobody can write
to you without 6 words exchanged out of band, and no server learns who talks, when or what:
everything travels as identical 16 KiB encrypted blocks, and one message carries up to ~16 MB
(a 4K image).

- **Invitation:** 6 random words from the BIP-39 list, never chosen by people. B then reads 3
safety words back to A, who must type them before the session opens, so even someone who
intercepted the 6 words cannot sit in the middle unnoticed.
- **Handshake:** CPace + X25519 + ML-KEM-768, so breaking it needs all three, quantum included.
- **Ratchet:** double ratchet with encrypted headers and a post-quantum ratchet; a new key per
block and recovery after a compromise.
- **No metadata by design:** fixed-size blocks, cover traffic, no public identifiers, no wall
clock on the wire.

## Status

MVP of the core, a development mailbox, the shared client with its Swift and Kotlin bindings,
and the mixnet transport: constant-rate requests, mailbox assignment, path selection by operator
and gateway failover, tested on a simulated mixnet.

Our own Katzenpost client (`janus_transport::katzenpost`) is under way, written only from
Katzenpost's published specifications and from black-box observation of a test network, never
from its code, so the app can contain only code the project is free to ship. Against a live
Katzenpost network it already completes the post-quantum Noise (`pqXX`, X-Wing) wire handshake,
downloads the consensus and verifies it against the pinned directory authorities (see the
ignored `katzenpost_interop` test). Sphinx packets and single-use reply blocks are implemented
to the Sphinx specification with their own tests, but are **not yet accepted byte-for-byte** by
the current servers: this build derives the per-hop keys in a way its published spec does not
document, and a black-box search over the whole plausible space (shared-secret form, KDF, hash,
IV and counter) did not recover it. That is the one piece left before messages cross a real
mixnet. The first iOS (SwiftUI) and Android (Compose) apps are in `apps/`, and neither has run
on a device yet. No external audit. Do not rely on it for real protection: the development
mailbox sees who connects.

## Pending

- Sphinx byte-level interop with the current Katzenpost servers (per-hop key derivation).
- `janus-mailbox` as a Katzenpost service (or Pigeonhole), and the production network.
- Phone measurements of cover traffic: latency, battery and data.
- Mobile apps on real devices: Secure Enclave and StrongBox storage, backup proof, two
  phones chatting over the mixnet.
- Desktop: runs on Windows and Linux, TPM-bound key, OS app lock, receiving with the window
  closed, state out of backups, the macOS app from the SwiftUI code.
- Core hardening: fuzzing, cheap rejection of forged blocks, formal model in Tamarin or
  ProVerif.
- Before release: external audit, reproducible builds, legal review and a closed beta.

## Try it

```bash
make test      # run all tests
make demo      # lint, test and open the web demo
make mailbox   # terminal chat: the mailbox, then `make invite` and `make join` in two more terminals
make chat WHO=alice   # back to saved contacts after quitting
make bindings  # Swift and Kotlin bindings in target/bindings
make apple     # iOS app: Rust library and Janus.xcodeproj in apps/apple (Xcode, xcodegen)
make android   # Android app: Rust libraries and bindings in apps/android (NDK, cargo-ndk)
make desktop   # desktop app for Windows and Linux (runs on macOS too, for testing)
```

Debug builds of the apps also reach the development mailbox: run `make mailbox` first, so its
`mailbox.der` is there when `make apple` or `make android` copies it in.

| Crate | Role |
| --- | --- |
| `janus-core` | The engine: plaintext to fixed-size encrypted blocks and back |
| `janus-transport` | The `Transport` trait; `Mixnet` over a mixnet client, network profiles and directories, `Memory` for tests, `Direct` to a mailbox over TLS 1.3, and our clean-room Katzenpost client (`katzenpost`: PQ Noise wire, Sphinx, SURBs, PKI verification) |
| `janus-mailbox` | Store-and-forward by queue id, in memory, no accounts, no logs; one request format for TLS and the mixnet |
| `janus-client` | The client every app shares: contacts, encrypted storage, timers, cover traffic |
| `janus-ffi` | UniFFI bindings over `janus-client` for the native apps |
| `janus-cli` | Reference terminal client on `janus-client`, and a web demo of the core |
| `apps/apple`, `apps/android` | Native apps on `janus-ffi`: SwiftUI and Kotlin with Compose |
| `janus-desktop` | The Windows and Linux app on `janus-ffi`, in egui |

## License

[GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`). Anyone may use, study,
modify and share the code. Whoever distributes a modified version, or runs one as a network
service, must publish its source under the same license.
