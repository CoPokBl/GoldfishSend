# GoldfishSend

An end-to-end encrypted messenger for Android with no accounts: no phone numbers, emails or usernames, and no contact
discovery. Contacts are added by QR code or link. The server is a blind relay: it takes an opaque ciphertext addressed
to an opaque per-contact mailbox, pushes it to the recipient's phone through UnifiedPush, and forgets it.

- **Messages** are encrypted with libsignal (PQXDH and the Double Ratchet), then again with Web Push (RFC 8291) on the
  way to the phone. **API calls** are encrypted to the server's own key (hybrid ML-KEM-768 and P-256), inside TLS.
- **Mailboxes** are per contact, so the server can't tell which ones belong to the same person. Push endpoints are
  sealed at rest, and undelivered messages are held under daily keys that are deleted when no message can need them.
- **Abuse resistance without accounts:** memory-hard proof of work (Argon2id) to create mailboxes, rate limits per
  address, network, mailbox and server, verification pushes, and an SSRF-safe push client.
- **Self-hostable and federated:** each person receives on their own server, and invites carry the server's address
  and key fingerprint.
- **Groups** of up to 100 are pairwise libsignal sessions with an owner-signed member list. The server can't tell them
  from 1:1 chats.
- **On the phone:** SQLCipher with keys in the Android Keystore, per-message keys for crypto-shredding, disappearing
  messages, app lock, duress PIN, panic wipe, built-in Tor, and an on-device security audit.

## Repository

| Path | Contents |
|---|---|
| [`server/`](server/README.md) | The relay: ASP.NET Core (.NET 10) with MySQL and Redis. Setup, configuration, deployment and operations. |
| [`android/`](android/README.md) | The app: Kotlin and Jetpack Compose. Building, testing, architecture and security features. |
| `deploy/` | The Docker Compose stack: Caddy (or your Traefik), api, worker, MySQL, two Redis instances, an optional onion service. |
| [`docs/protocol.md`](docs/protocol.md) | The wire protocol between app and server. Change it here first. |
| [`docs/groups.md`](docs/groups.md) | The group protocol, and the reasoning behind it. |
| [`docs/threat-model.md`](docs/threat-model.md) | Who can learn what, and where the protections stop. |
| [`docs/RELEASING.md`](docs/RELEASING.md) | Signing, automatic releases, Obtainium, and verifying a reproducible build. |
| [`docs/fdroid/`](docs/fdroid/README.md) | Notes and a draft recipe for F-Droid. |

## Where to start

- **Run a server:** [server/README.md, "Deployment with Docker Compose"](server/README.md#deployment-with-docker-compose).
- **Hack on the server:** [server/README.md, "Local development"](server/README.md#local-development).
- **Build the app:** [android/README.md, "Build"](android/README.md#build).
- **Install the app:** releases are published on this repository's GitHub releases page, signed and reproducible. Add
  the repository to [Obtainium](https://github.com/ImranR98/Obtainium) and check the signing fingerprint
  ([docs/RELEASING.md](docs/RELEASING.md#installing-with-obtainium)).

## Licence

The Android app is AGPL-3.0-or-later, as libsignal requires.
