# GoldfishSend: Android client

A native Kotlin and Jetpack Compose client for GoldfishSend. It has no accounts and no phone numbers. Messages are end-to-end encrypted with libsignal (PQXDH and Double Ratchet) and delivered through UnifiedPush.

Licence: **AGPL-3.0-or-later** (required by libsignal).

The wire protocol lives in [`../docs/protocol.md`](../docs/protocol.md), and this client implements its client side exactly.

## Build

Requirements: Android SDK (compileSdk 37, NDK 27.1 for native symbol stripping) and JDK 21.

```sh
cd android
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
./gradlew :app:assembleDebug          # debug APK (allows http:// for a local dev server)
./gradlew :app:assembleRelease        # R8-minified release APK (https only)
./gradlew :app:testDebugUnitTest      # JVM tests: protocol vectors, HTTP contract (MockWebServer), real libsignal PQXDH handshake
./gradlew :app:connectedDebugAndroidTest  # on-device: Keystore, SQLCipher, crypto-shredding, locked inbox, panic wipe
```

The default server URL is a build property: `./gradlew assembleRelease -Pgf.defaultServer=https://your.server`.
Users can also change it under *Settings → Network → Server* (or "Advanced" during onboarding).

Release builds need your own signing config. `assembleRelease` produces `app-release-unsigned.apk`.

## Architecture

There's a single `:app` module, so the build stays simple and fast. It has no DI framework, no Room, no KSP and no reflection-based libraries.

| Package | Responsibility |
|---|---|
| `proto` | Pure Kotlin wire formats: base64url, padding, PoW, mailbox tag/owner hash, push envelope, E2E blob, Content JSON, chunking, invite link/blob. JVM-tested. |
| `crypto` | `KeyVault` (Keystore and Argon2 key hierarchy), `MessageVault` (per-message keys), `SignalStore` (libsignal stores on SQLCipher) |
| `db` | `Db` (SQLCipher wrapper, schema) and `Repo` (typed queries; every message body goes through `MessageVault`) |
| `net` | `ServerApi` (OkHttp, TLS 1.2+ restricted ciphers, no redirects) with friendly error mapping. `NetStack`: per-request routing (direct, built-in Tor or Orbot, fail closed) and TOFU key pinning. `TorManager` (in-process tor-android). `NetRules`/`PinPolicy` are pure rules, JVM-tested. |
| `push` | UnifiedPush connector 3.x (`GfPushService`, `PushHub`), registered with the server's VAPID key |
| `core` | `Graph` (service locator and unlocked `Session`), `Mailboxes`, `Invites`, `Messenger` (receive/send), `Outbox`, `Sweeper`, `LockedInbox`, `Notifier`, `Prefs` |
| `security` | `AppLock`, `Wiper`, `SecurityAudit`, `ClipboardGuard` |
| `work` | WorkManager workers (outbox, maintenance), boot/expiry receivers, Quick Settings panic tile |
| `ui` | Material 3 Compose UI (theme, screens, components) |

### Message flow
- **Send**: `Messenger.sendText` stores the message (per-message key), chunks it to the padded-size limits, and queues it in `outbox`. `Outbox` then encrypts each row **once** with libsignal, stores the ciphertext, and POSTs it with a fixed idempotency key. It retries with backoff and keeps per-contact ordering.
- **Receive**: the UnifiedPush connector decrypts RFC 8291. `Messenger` parses the envelope, then either confirms a mailbox verification or looks up the mailbox by tag, decrypts with libsignal and unpads. It then dispatches `hello`, `text`, `receipt`, `timer`, `delete` or `mailbox`.
- **While locked** (passphrase set, or device locked): pushes are sealed with libsignal's HPKE to the *locked-inbox* public key and written to disk. The private key lives inside the encrypted DB, and the inbox is drained on unlock.
- **Reliability**: if a delivery receipt hasn't arrived after 6 h, the message is re-sent (up to 3 times, deduped by message id on the receiver). This covers push servers that drop messages for offline devices.
- **Back-pressure**:
  - `507 mailbox_full` (the recipient has been offline a long time) keeps the message queued. It backs off at least 1 h, honouring `Retry-After`, and the UI shows the normal "sending" state.
  - A `429` triggers one retry with a solved `GF-PoW` header, which pays the per-IP limit on shared IPs and Tor. After that it's normal backoff.
- **Endpoint rotation**: only verified mailboxes are rotated. A `404` on a batch falls back to rotating one by one. A contact's mailbox that the server no longer knows is replaced, and the contact gets an E2E `mailbox` message. Rate-limited rotations (`429`) are retried by maintenance.

### Contacts (invites)
A pool of two ready, verified mailboxes is kept in the background (PoW plus verification push), so **Add contact is instant**.
Showing your code uploads a one-time encrypted `InviteBundle` (signed prekey and one-time Kyber-1024 prekey). The QR code holds only `server + inviteId + key`.
Scanning fetches the invite (which deletes it), builds a PQXDH session and opens the chat right away. `hello` and anything typed are queued until delivery succeeds.
Contacts added by scanning in person are marked **verified**. Contacts added by link are not, until you compare safety numbers.

## Security notes

**Key hierarchy**
- MK is 256 random bits and lives only in RAM while unlocked.
- MK is wrapped by an Android Keystore AES-GCM key (StrongBox when available, `setUnlockedDeviceRequired`).
- With a passphrase, MK is first wrapped by an Argon2id-derived key (64 MiB, t = 3), so both the hardware key and the passphrase are required.
- The DB key is `HMAC(MK, "gf/db-key/v1")`, used as a raw SQLCipher key.

**Storage**
- SQLCipher has `secure_delete` and `cipher_memory_security` on.
- Each message body is encrypted with its own key, wrapped by a message root key. The root key is in turn wrapped by a separate Keystore key (`gf_msg`).
- Deleting a message deletes its key first. Deleting `gf_msg` makes every message unreadable instantly, even while the app is locked. That's how *Erase messages on restart* works: it runs from `BOOT_COMPLETED` and also when `Settings.Global.BOOT_COUNT` changes at app start.

**Controls**
- Disappearing messages: per-chat timer synced via `timer`, start on read or on receipt, view-once. Expired rows are filtered at query time and crypto-shredded by an alarm and a sweeper.
- App lock: passphrase, optional biometric unlock (a Keystore CryptoObject that's invalidated when new biometrics are enrolled), auto-lock timeout, lock on screen-off.
- Wipes: erase after N wrong attempts, a duress PIN (silent full wipe), a panic wipe (in the app and as a Quick Settings tile), and an inactivity wipe.
- Screen and input: `FLAG_SECURE` is on by default. All text input uses `IME_FLAG_NO_PERSONALIZED_LEARNING`, through `SecureTextField`, because Compose text fields can't set this flag.
- Clipboard: copied text is marked sensitive and cleared automatically.
- Notifications reveal nothing by default (`VISIBILITY_SECRET`).
- No backups or device transfer.

**Network** (Settings › Connection, also reachable from onboarding's Advanced section)
- **Connection mode**: Direct (default), **Built-in Tor**, or **Orbot**. Built-in Tor embeds the Guardian Project's
  `tor-android` and runs it in-process as a bound, non-exported service, with no extra permissions. Its torrc adds
  `SafeSocks`, `ClientOnly` and `AvoidDiskWrites`. With Tor or Orbot selected, every request to a GoldfishSend server
  goes over SOCKS with remote DNS. Requests **fail closed**: they wait up to 45 s for built-in Tor to connect, then fail
  and are retried later, and never fall back to a direct connection. The UI shows "Connecting to Tor…".
- **Onion servers**: `http://<v3>.onion` server URLs are accepted (the v3 address and its checksum are validated).
  Plain http is allowed only to onion hosts (network security config plus the route check), and only through Tor or
  Orbot. If a contact's server is an onion and Tor is off, the user is asked to turn Tor on. Nothing is sent directly.
- **Pin server keys** (off by default, because servers legitimately rotate keys): trust on first use of the SHA-256
  SPKI of each server's leaf certificate, checked in an OkHttp network interceptor before any request bytes are
  written. A change fails closed and shows "This server's identity changed", with the old and new fingerprints and
  **Keep blocked** or **Trust new key** (confirmed a second time). It never auto-accepts. Onion servers are skipped,
  because the onion address is the key. Fingerprints are shown in Connection settings for comparison with the
  operator's (see server/README.md).
- Tor covers connections to GoldfishSend servers only. **Push delivery still goes through your UnifiedPush
  distributor** (ntfy etc.), which sees delivery timing but never content.
- A panic wipe deletes the network settings, pins and Tor's state directory, **after** the best-effort mailbox
  deletions have been sent over the same route (so a Tor user's last requests don't go out directly).

**Security tab**: an on-device audit covering patch age, Android end of life, a Google/FCM push distributor, screen lock, encryption, ADB and developer options, root or bootloader state, accessibility services, the keyboard (closed-source keyboards such as Gboard or SwiftKey are a warning and known cloud keyboards such as Sogou, Baidu or Grammarly are critical; known open-source keyboards and anything installed by an F-Droid client are trusted, see `security/KeyboardTrust.kt`), StrongBox, the auto-lock delay (screen timeout plus lock delay: info over 2 min, warning over 5 min or "never"), apps with notification access (a warning if previews are on), Private DNS (a zero-penalty note, since Tailscale MagicDNS and similar setups are good reasons to leave it off; skipped when a VPN handles DNS), and app settings. Each item has a one-tap **Fix** where possible.

Findings can be **dismissed** if there's a legitimate reason to leave them as they are, for example root, an unlocked bootloader, accessibility services, USB debugging, a Google push service or a closed-source keyboard a language needs. Dismissed findings stop counting toward the score, and a Restore option keeps them visible. They come back if the situation changes. Findings with no safe justification can't be dismissed: no screen lock, a non-HTTPS server, unencrypted storage, push not working, a cloud keyboard, patches over 180 days old, and an unsupported Android version (`security/AuditRules.kt`).

The audit adds **no extra permissions**. Checks that would need one, such as listing apps that can draw over other apps (which needs `QUERY_ALL_PACKAGES`), are deliberately left out.

## Known gaps / TODO
- **No group chats or attachments.** Multi-device isn't supported either.
- **Key pinning is opt-in and trust-on-first-use.** A first connection that's already intercepted gets pinned.
  Compare the fingerprint with the operator's.
- **Built-in Tor adds about 8 MB per ABI** (`libtor.so`) to the APK, and isn't yet exercised on a device by the tests.
- **Requests over Tor can be linked by the server**, just like requests from one IP: connections are reused across a
  device's mailboxes on the same server.
- **Changing server needs an empty contact list.** Mailboxes don't record which server they live on, so you must remove your contacts before switching.
- **Locked inbox needs one unlock first.** The inbox key pair is created on first unlock, so a push that arrives before the app has ever been unlocked is dropped.
- **Key material can't always be wiped from memory.** Text you type in fields passes through `EditText` and `String`, which the JVM can't reliably zero. Raw key arrays are zeroed.
- **The UI is only smoke-tested** on an emulator (onboarding renders). End-to-end delivery through a real push distributor and server hasn't been exercised yet.
