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

Release signing is optional and local: `android/keystore.properties` or `GF_KEYSTORE_*` environment variables
(see [`../docs/RELEASING.md`](../docs/RELEASING.md)). Without either, `assembleRelease` produces `app-release-unsigned.apk`.

### Reproducible builds

The release APK is bit-for-bit reproducible. Two clean builds, one of them from a copy of the tree at a different
absolute path, produce identical unsigned APKs. To make that hold:

- The toolchain is pinned: Gradle 9.7.1 (wrapper with `distributionSha256Sum`), AGP 9.4.1, Kotlin 2.4.20,
  build-tools 37.0.0, and NDK 27.1.12297006 (it strips the prebuilt native libraries, so its version affects the bytes).
  Gradle runs on JDK 21, and sources compile with a JDK 17 toolchain.
- No timestamps, git state (`vcsInfo.include = false`), dependency-metadata blob (`dependenciesInfo`) or random
  values go into the APK. `BuildConfig.DEFAULT_SERVER_URL` depends only on `-Pgf.defaultServer`, so verifiers
  must pass the same value as the release (stated in its notes), or none for the default.
- Every downloaded artifact is checked against `gradle/verification-metadata.xml` (SHA-256). See
  [`../docs/RELEASING.md`](../docs/RELEASING.md#8-updating-dependencies) for updating it when dependencies change.

To verify a published release yourself, see [`../docs/RELEASING.md`](../docs/RELEASING.md#7-verifying-a-release-is-reproducible).
In short: build `assembleRelease` from the tag, then `apksigcopier compare published.apk --unsigned app-release-unsigned.apk`.

### Baseline profiles

The release APK ships a baseline profile (code ART compiles ahead of time, so startup, scrolling and opening chats
don't run interpreted) and a startup profile (R8 puts the classes needed at startup first in `classes.dex`). Both are
generated on a device by the `:baselineprofile` module and committed under `app/src/release/generated/baselineProfiles/`.
A normal `assembleRelease` only compiles those text files: it never regenerates them and needs no device, so the build
stays reproducible. `androidx.profileinstaller` installs the profile on first launch, so installs from F-Droid,
Obtainium or adb benefit too, not just Play.

Regenerate the profiles after changes to startup, the chat list, the chat screen, unlocking or settings, after
Compose or other UI dependency updates, and before a release. With one device or emulator connected (Android 13+, or a
rooted device):

```sh
cd android
./gradlew :app:generateReleaseBaselineProfile
# on an emulator, add: -Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.suppressErrors=EMULATOR -Pgf.abis=x86_64
git add app/src/release/generated/baselineProfiles
```

The generator drives the real UI with UiAutomator: cold start to the chat list, cold start to the PIN lock screen and
unlocking, scrolling the chat list, opening and scrolling a long conversation, typing and sending, a group chat, and
settings (`baselineprofile/src/main/java/.../BaselineProfileGenerator.kt`). Its data comes from a seeding provider that
exists only in the `benchmarkRelease` and `nonMinifiedRelease` build types (`app/src/benchmark/`), which the
baseline-profile plugin adds for measuring. They use the application id `app.goldfishsend.bench`, so they never touch a
real install, and every server in the seeded data is `127.0.0.1`, so nothing leaves the device. The provider is not in
debug or release builds.

Macrobenchmarks (cold and warm startup, unlocking, scrolling the chat list and a long conversation, opening a chat, sending), each
without AOT compilation and with the baseline profile:

```sh
./gradlew :baselineprofile:connectedBenchmarkReleaseAndroidTest
# results: baselineprofile/build/outputs/connected_android_test_additional_output/benchmarkRelease/connected/*/*benchmarkData.json
```

Use a physical device for absolute numbers. Emulator results are only good for comparisons.

### Fuzzing

Everything that decodes bytes or text from someone else is fuzzed, as is the group protocol. `testDebugUnitTest` (and so
CI) replays the committed inputs and 150 seeded group scenarios, about 7 s more than the other tests; longer runs are
local only.

| Test | What it covers |
|---|---|
| `fuzz/ParserFuzzTest` | Invite links (QR, pasted text, deep links), invite blobs, push payloads and E2E blobs, decrypted plaintext (padding and Content JSON), chunking, display names |
| `fuzz/GroupReceiveFuzzTest` | One member receiving whatever a hostile member, invitee or stranger can send: raw blobs, forged or replayed rosters and cards, chunks in any order, claimed senders |
| `fuzz/GroupStatefulTest`, `fuzz/GroupScenarioFuzzTest` | Random sequences of joins, leaves, removals, ownership and name changes, inbox rotations and messages, with pushes reordered, duplicated and delayed and a hostile member (who also signs rosters on older ones and departures carrying old rosters; `GroupScenarioFuzzTest.forks`). Always checked: no rollback, no fork, authority, and that whoever is out can't read or post. Once the hostile member stops, what was held back is lost, and after one message from each member, members who can reach each other must agree (roster, facts, cards) with no state ping-pong, and messages must arrive |
| `PoisonMessageTest` | A message that fails to process is dropped (counted, logged without content); it never crashes the app or blocks what comes after |

The Jazzer tests ([Jazzer](https://github.com/CodeIntelligenceTesting/jazzer), on the JUnit Platform next to the JUnit 4
tests) take their inputs from `app/src/test/resources/app/goldfishsend/fuzz/<Test>Inputs/<method>/`. To fuzz one of them
(one at a time; the duration is optional):

```sh
./gradlew :app:testDebugUnitTest -Pgf.fuzz=10m --tests 'app.goldfishsend.fuzz.GroupReceiveFuzzTest.hostileMember'
```

The corpus it builds goes to `app/.cifuzz-corpus/` (not committed). A finding is written as a `crash-…` file into the
inputs directory above, where it replays from then on: fix the bug, rename the file after it and commit it.
`GroupScenarioFuzzTest` also prints the failing scenario shrunk, as below.

For a longer run of the seeded group scenarios: `-Pgf.groupFuzz.minutes=10` (or `-Pgf.groupFuzz.seeds=5000`, and
`-Pgf.groupFuzz.start=` to begin elsewhere) with `--tests 'app.goldfishsend.fuzz.GroupStatefulTest'`. A failing seed is
shrunk to a short list of steps, printed ready to paste into a regression test in `GroupStatefulTest`. To see what each
member decides along the way, replay it: `-Pgf.groupFuzz.replay="<seed>; Op(…), …"` with
`--tests 'app.goldfishsend.fuzz.GroupStatefulTest.replay' -i`.

### Verifying your download

Official releases are signed with a single key whose certificate SHA-256 fingerprint is:

```
TBD: published with the first release (see docs/RELEASING.md §5)
```

Check an APK before installing it with [AppVerifier](https://github.com/soupslurpr/AppVerifier), or run
`apksigner verify --print-certs goldfishsend.apk` and compare the `SHA-256 digest`. F-Droid and Obtainium refuse
updates signed with a different key. F-Droid packaging notes are in [`../docs/fdroid/`](../docs/fdroid/README.md).

## Architecture

There's a single `:app` module, so the build stays simple and fast. It has no DI framework, no Room, no KSP and no reflection-based libraries. (`:baselineprofile` only generates profiles and runs benchmarks; see "Baseline profiles".)

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
A pool of two ready, verified mailboxes is kept in the background (Argon2id PoW plus verification push), so **Add contact is instant**.
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
- Wipes: erase after N wrong attempts, a duress PIN (silent full wipe, or a separate decoy profile), a panic wipe (in the app, as a Quick Settings tile, or from a PanicKit app), and an inactivity wipe based on when you last used the app (clock changes don't fool it).
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


## Optional security features

All of these live in **Settings**. Only those with no real downside are on by default.

- **Unlock method.** Choose between:
  - **Phone screen lock:** the system prompt. GoldfishSend never sees your PIN, pattern or password. It needs Android 11+, and if you ever remove your phone's screen lock, the data can't be recovered.
  - **App PIN:** typed on GoldfishSend's own keypad, so your keyboard app never sees it. You can scramble the keypad if you want.
  - **Passphrase:** the advanced option, typed with your keyboard.

  Fingerprint unlock, the duress PIN and erasing after failed attempts all need the app PIN or the passphrase.
- **Duress PIN.** It's a verifier only: it can never decrypt your real data. Choose what it does: erase everything (the default), or open a separate **decoy profile** with its own database, identity and contacts, which persists between duress unlocks. While the decoy is open, your real chats stay encrypted and untouched. Incoming messages wait in the locked inbox (with no notification) and appear at your next real unlock. The decoy never contacts the server, and its settings show the duress and erase options as off. The duress PIN's storage slot looks the same whether it's set or not.
- **Hidden chats.** Set a separate PIN, then hide chats from their contact info. To see them, long-press "Chats" and enter the PIN. They're hidden again when the app locks. Notifications for hidden chats are off unless you turn them on, and even then they're generic.
- **Panic button (PanicKit).** Panic apps such as Ripple can lock GoldfishSend. Only the app you approve can erase it. Off by default.
- **Safety numbers.** If a verified contact's key changes, their messages are held and sending pauses until you review the new number in their contact info. Unverified contacts get a notice instead, or you can choose to pause those too.
- **Mailbox rotation.** On by default, every 30 days. Each contact gets a fresh mailbox, and the old one is deleted after they've switched.
- **Clear memory when locking.** On by default.

## Security notes (client audit fixes)

- **Invite links never act on their own.** Opening a `gfsend://` link only proposes a contact. You see the server and accept first.
- **Changing the unlock method makes a new master key.** The database is rekeyed and the old device key is deleted, so an older, weaker wrapping (for example "no lock") left in flash can't open anything. Interrupted changes recover automatically.
- **Re-authentication** (your app PIN or passphrase, or the phone's screen lock) is needed before changing the unlock method, duress PIN, hidden chats, erase settings, the panic response or the connection mode.
- **Disappearing messages are shredded on time, even while locked.** Messages with an expiry are wrapped under hourly Keystore keys that are deleted when their hour is over. The chat's timer is the ceiling: a contact can make messages vanish sooner, never later.
- **View-once** messages are deleted before they're shown.
- **Hostile contacts and servers:** proof-of-work parameters are capped (difficulty, Argon2 memory and iterations, expected work), solver threads × memory stays within a heap budget, and solving times out, responses are capped at 64 KiB, each contact is sent to separately, contact-supplied servers must use https on 443 (or a valid onion), invites are bound to their own mailbox and prekey, names are sanitised and timestamps clamped.
- **Restart wipe** also clears pushes waiting in the locked inbox and replaces its key.
- **The Security tab** uses hardware key attestation for boot and bootloader state where available. It's checked on the device itself, without a server-side chain check, but it's far harder to spoof than system properties.

Database storage: SQLCipher with `journal_mode = DELETE`, `temp_store = MEMORY`, `secure_delete` and `cipher_memory_security`, plus an idle `VACUUM` after bulk deletes.
