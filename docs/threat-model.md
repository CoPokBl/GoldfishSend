# GoldfishSend threat model

This document says who GoldfishSend defends against, what each of them can and can't learn, and where the
protections stop. It describes protocol v2 (`docs/protocol.md`), the server in `server/` and the app in `android/`.
When the code and this document disagree, that's a bug in one of them.

## Summary

| Party | Message content | Who talks to whom | When / how much | Your IP |
|---|---|---|---|---|
| Network observer (ISP, Wi-Fi) | No | No | Yes: timing and padded sizes of your traffic | Yes (hidden with Tor) |
| TLS terminator (Traefik, load balancer) | No | No | Yes | Yes |
| Push provider (ntfy, FCM through a distributor) | No | No | Yes: when your phone is woken | Yes, your phone's |
| Server at rest (seized disk, backup) | No | No | Coarse: expiry days, queued message counts | No |
| Server operator, live | No | Partly, see "The live server" | Yes | Yes, at request time |
| A contact | Only what you send them | Only you | Only their own chat | No |
| Anyone else | No | No | No | No |
| Seized phone, app locked | No, unless the lock is broken | No | No | n/a |
| Seized phone, app unlocked | Yes | Yes | Yes | n/a |

## What we protect

1. **Message content** and attachments-to-be, including names and the contact list.
2. **The social graph:** who is in contact with whom.
3. **Identity and location:** which phone, which IP and which push account a mailbox belongs to.
4. **History:** what was said in the past, after keys or devices are compromised (forward secrecy) and after deletion.
5. **Availability:** that messages arrive, despite abuse of an account-less server.

## Design principles

- **No accounts, no identifiers.** There are no phone numbers, usernames or emails, and no contact discovery.
  Contacts exchange capabilities directly (QR code or link).
- **The server is a blind relay.** It holds a message only until the push is accepted, then deletes it. It can't tell
  which mailboxes belong to the same person.
- **Two layers of end-to-end encryption.** Messages are encrypted with libsignal (PQXDH key agreement and the Double
  Ratchet). Each push is encrypted again with Web Push (RFC 8291) to the recipient's device. The API itself is
  encrypted to the server's identity key (hybrid ML-KEM-768 and P-256), inside TLS.
- **Every protection that costs something is optional.** Defaults are on only where there's no downside.

## Adversaries

### Network observer
Your ISP, a Wi-Fi operator, or a state tapping links.
- **Sees:** that you connect to a GoldfishSend server and a push server, when, and how much. Requests and responses
  are padded to fixed buckets (512 B to 17 KiB). Messages are padded inside libsignal to 256 B steps.
- **Can't:** read or alter anything, or tell which API call you made. Every call goes to `POST /v1/gw` and returns 200.
- **Can't:** impersonate the server, even with a valid TLS certificate for its domain. The app checks the server's identity
  key, which is independent of TLS.
- **Mitigation for metadata:** built-in Tor or Orbot, and `.onion` servers. Tor hides your IP from the server and your
  ISP, but it doesn't hide push wake-ups, which reach your phone over the push provider's own connection.

### TLS terminator
Traefik, Caddy, a cloud load balancer, or a compromised proxy in front of the API.
- **Sees:** client IPs, timing and padded sizes. With the gateway it sees no paths, headers, bodies or error codes, so it
  learns no mailbox secrets, push endpoints or invite ids.
- **Can:** drop or delay requests, and log IPs. The deployment docs say to turn off access logs.
- **Can't:** decrypt or forge API traffic. Replaying a captured request gets a `409 replay` from the server. Replays are also
  harmless by design: libsignal rejects duplicate messages, and owner operations are idempotent.

### Push provider and distributor
ntfy (public or self-hosted), Google FCM through a distributor app, or another UnifiedPush server, plus the distributor app
on the phone.
- **Sees:** the endpoint (which identifies your phone to it), when it's woken, the GoldfishSend server's IP, and
  Web Push ciphertext of padded size.
- **Can't:** read content (Web Push is end-to-end between the GoldfishSend server and the app), or send pushes in the
  server's name when the distributor enforces VAPID.
- **Learns more if it's Google:** FCM ties wake-ups to your Google account. The Security tab warns about Google-based
  distributors.
- **Can:** withhold pushes. Held messages are retried for up to 14 days.

### Server at rest
A seized disk, a stolen backup, a subpoenaed database.
- **Has:** per mailbox, an HMAC id, an endpoint sealed with a key derived from the mailbox's own `sendSecret`,
  `SHA-256(ownerSecret)`, a verification state and an expiry date. Per undelivered message, the mailbox id and the E2E
  ciphertext under a daily epoch key.
- **Can't:** link mailboxes to each other or to people, or unseal endpoints without that mailbox's `sendSecret`.
  Epoch keys are deleted when no message can still need them, so deleted rows left in redo logs or free disk space are
  unrecoverable (crypto-shredding).
- **Keys matter:** the server keys (`Pepper`, `SealSalt`, `EpochKek`, `VapidPrivateKey`, `ServerKey`) live in the
  environment, not the database. A database alone is useless. An attacker with the keys **and** a database still sees
  only E2E ciphertext, plus endpoints of mailboxes that had messages held at that moment.
- **Residual:** MySQL's own redo and undo logs aren't encrypted by default; see "Known gaps".

### The live server
Whoever runs the server, or an attacker who has taken it over while it's running. This is the strongest network-side
adversary.
- **Sees per request:** the client IP. On a send, it sees the sender's IP and the recipient's mailbox id. On delivery, it
  sees the recipient's endpoint, briefly decrypted in memory.
- **Can therefore link:** "IP A sent to mailbox M, which is woken at endpoint E". Over time, and especially without Tor,
  that reveals a lot of who talks to whom. It's the same position as any relay operator.
- **Mitigations:**
  - **Mailbox rotation:** the optional "rotate mailboxes every N days" setting limits how long one mailbox can be followed.
  - **Tor:** hides IPs from the server.
  - **Your own server:** each person receives on their own server, so your contacts' servers see only your sends to them.
- **Can't:** read content, forge messages (libsignal authenticates them), learn names or contact lists, or link one
  person's mailboxes except by IP and timing.
- **Can:** drop, delay or replay messages. Drops look like an offline recipient. libsignal rejects replays.
- **Deferred:** two-relay routing, where your server forwards to your contact's server, would hide your IP from the
  recipient's server (PLAN.md §11, item 11).

### A malicious or compromised contact
- **Can:** read what you send them, keep it (disappearing timers and "delete for everyone" are honoured by honest apps
  only), screenshot it on another device, and spam their own mailbox to you within per-mailbox rate limits.
- **Can't:** learn your IP (all traffic goes through servers), your phone number (there isn't one), or your other contacts.
- **Defence:** blocking deletes their mailbox on the server, so their sends fail. A changed safety number is held for
  review before any message is accepted.

### Groups
Groups (`docs/groups.md`) are pairwise libsignal sessions to each member plus a signed member list (roster) and signed
member cards. There's no group state on any server.
- **The server** sees one ordinary mailbox per member per group, and N sends from the sender's IP when a message fans
  out (as N 1:1 messages would). It can't tell group traffic from 1:1 traffic, see who's in a group, or link two
  messages from the same member: the sender hint is a random-nonce HMAC only members can check.
- **Members** see each other's identity keys, self-chosen names and group inboxes (each member's own server and a
  `sendSecret` only for that group). Members who aren't your contacts are marked unverified; you can compare safety
  numbers with each of them. A member can do what any contact can: keep what's said, and send junk to your group inbox
  (dropped unless it decrypts from a current member).
- **Admins** decide membership. A malicious admin can add anyone, including someone impersonating a person (an
  identity key the admin vouches for), remove people, or rename the group. Everyone sees these changes as signed
  system lines, and the added person's safety number can be compared. Admins can't read anything sent before the new
  member joined, and can't forge messages from other members.
- **Non-admins** can only leave, accept or decline (and rename or set the timer if the group allows it). A forged or
  modified roster is rejected unless an admin of the current roster signed it.
- **Removed members** stop receiving at once (nobody encrypts to them any more), and every remaining member moves to a
  new inbox, so they can't even send noise for long. What they received before stays with them. Their old sessions
  carry nothing new.
- **Residual:** concurrent changes converge but can briefly differ between members; membership is eventually
  consistent. If every admin loses their phone, membership can't change any more (members can still leave).

### Strangers and abusers
Anyone without a capability.
- **Can't:** message you at all. Sending needs that mailbox's `sendSecret`, which only your contact has.
- **Can:** try to exhaust a server: create mailboxes, flood sends, use invites. Defences:
  - proof of work that adapts to load;
  - GCRA limits per IP, network, mailbox and global, in Redis;
  - verification pushes before a mailbox goes live;
  - per-push-host circuit breakers;
  - an SSRF-safe push client.
- **Residual:** SHA-256 proof of work is cheap on GPUs. Memory-hard PoW or Privacy Pass are future work.

### Seized phone
- **App locked, or phone before first unlock:** the database is SQLCipher, keyed from the Android Keystore
  (hardware-backed, unusable while the device is locked). With an app secret, it also needs an Argon2id-hardened
  passphrase or PIN, so extracting Keystore keys isn't enough.
  - Each message has its own key, so deleted messages are crypto-shredded.
  - Deleted rows are zeroed in the file (`secure_delete`), so even someone who later gets the database key (coerced
    unlock) finds no deleted message, key or name. `ForensicDeviceTest` checks this against a full dump.
  - Options: wrong-PIN wipe, a duress PIN that erases everything or opens a decoy, an inactivity wipe, erase on
    restart, a PanicKit trigger.
- **App unlocked:** everything visible in the app is exposed. Use a short auto-lock timeout.
- **Coercion:** a duress PIN can never decrypt real data; it only verifies. The decoy is a separate database. Hidden
  chats need their own PIN. An examiner who knows the app can still see that GoldfishSend is installed, and that
  hidden and duress features exist.

### Compromised phone OS or apps
Malware with root, accessibility or notification access, or a keyboard that uploads what you type.
- **Out of scope** to defeat: a compromised OS sees everything you see.
- **The app reduces exposure:**
  - `FLAG_SECURE` blocks screenshots and recents thumbnails;
  - incognito keyboard flags;
  - auto-clearing clipboard;
  - content-free notifications by default;
  - Security tab warnings for closed-source keyboards, accessibility services, notification listeners, an
    unpatched or end-of-life OS, and more.

### Future quantum attacker (record now, decrypt later)
- **E2E messages:** PQXDH protects session setup with ML-KEM. libsignal 0.107 has no switch to turn off its SPQR
  post-quantum ratchet; we haven't independently confirmed that it's active in our sessions.
- **API traffic:** the hybrid ML-KEM-768 and P-256 gateway protects request contents.
- **Web Push:** that layer is P-256 only. Breaking it reveals only the inner libsignal ciphertext.
- **TLS:** depends on your server's TLS stack (X25519MLKEM768 where supported). The gateway doesn't rely on it.

## Trust assumptions
- **Your phone:** the OS, the hardware Keystore and the app build are not compromised. Releases are reproducible
  and signed with a published key.
- **libsignal, SQLCipher, Bouncy Castle and the .NET cryptography libraries** are correct.
- **The first contact exchange:** the QR code or link reaches the right person. Scanning in person is strongest.
  Comparing safety numbers detects tampering later.
- **Server identity:** the fingerprint you pin is correct. It's built in for the default server, carried in invites for
  contacts' servers, and trusted on first use for servers typed in by hand. Publish your server's fingerprint.

## Not goals
- Hiding that you use GoldfishSend from someone who can inspect your phone or watch your network (without Tor).
- Protecting a phone whose OS is compromised.
- Enforcing deletion on a recipient's device.
- Anonymity against a global passive adversary correlating traffic at both ends.

## Known gaps
- **Some messages can't be shredded while the app is locked:** messages with no expiry, and unread start-on-read
  messages, are crypto-shredded only while the app is unlocked.
- **A duress erase is visible:** after "erase everything", the app shows its first-run screens, which differ from a
  locked app.
- **MySQL logs:** InnoDB redo and undo log encryption is documented but not enabled in the compose stack.
- **Sender IPs:** the live server sees them on sends, until two-relay routing exists.
- **Proof of work:** it isn't memory-hard.
- **Server key:** `ServerKey` never expires. If it leaks, someone who can also intercept TLS can impersonate the server
  until you replace it, and replacing it warns every user.
- **Group members who aren't contacts** are vouched for by an admin. Until you compare safety numbers with them, a
  malicious admin could slip in an impostor.

## Advice for users
- Scan QR codes in person when you can. Compare safety numbers for important contacts.
- Use a push distributor that isn't Google's (ntfy, self-hosted if you can).
- Set an app PIN or passphrase and a short auto-lock.
- Turn on Tor if your IP matters.
- Use disappearing messages, and treat anything you send as something the recipient keeps.
