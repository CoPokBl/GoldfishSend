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

1. **Message content**, display names and the contact list.
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
- **Not built yet:** two-relay routing, where your own server forwards to your contact's server (as in SimpleX's
  private message routing), would hide your IP from the recipient's server. It needs a server-to-server forwarding
  endpoint with its own abuse controls.

### A malicious or compromised contact
- **Can:** read what you send them, keep it (disappearing timers and "delete for everyone" are honoured by honest apps
  only), screenshot it on another device, and spam their own mailbox to you within per-mailbox rate limits.
- **Can't:** learn your IP (all traffic goes through servers), your phone number (there isn't one), or your other contacts.
- **Defence:** blocking deletes their mailbox on the server, so their sends fail. A changed safety number is held for
  review before any message is accepted.

### Groups
Groups (`docs/groups.md`) are pairwise libsignal sessions to each member, plus a member list (roster) signed by the
group's owner, members' own signed accepts and leaves (facts), and signed member cards. There's no group state on any
server.
- **The server** sees one ordinary mailbox per member per group, and N sends from the sender's IP when a message fans
  out (as N 1:1 messages would). It can't tell group traffic from 1:1 traffic, see who's in a group, or link two
  messages from the same member: the sender hint is a random-nonce HMAC only members can check.
- **Members** see each other's identity keys, self-chosen names and group inboxes (each member's own server and a
  `sendSecret` only for that group). Members who aren't your contacts are marked unverified; you can compare safety
  numbers with each of them. A member can do what any contact can: keep what's said, and send junk to your group inbox
  (dropped unless it decrypts from a current member). Anyone holding your inbox's hint key (current members, and past
  ones while the old inbox drains) can also write as identities they make up, since a newcomer's first message is
  read before a roster lists them. That stores no session or identity, counts only if it claims to be from further on
  than your roster, and leaves at most what's bounded anyway: held messages (200 per group, 7 days), chunks, and 40
  facts about stints your roster doesn't reach.
- **The owner** decides membership, and is trusted to. A malicious owner can:
  - add anyone, including someone impersonating a person (an identity key the owner vouches for);
  - remove people, or rename the group;
  - **equivocate:** sign two different rosters at the same version and show each to different members. Members would
    disagree about who's in until the owner's next roster; this isn't detected. A member next in line can do the same
    once the owner leaves, by sending their own departure to some members while signing as the owner for the rest.

  Everyone sees the owner's changes as signed system lines, and the added person's safety number can be compared. The
  owner can't read anything sent before a new member joined, and can't forge messages or facts from other members.
- **Members** can only accept, decline or leave, by facts they sign about their own stint.
  - **Replaying.** A fact about an earlier stint (before they were removed and invited again) is ignored.
  - **Forging.** A forged or modified roster is rejected unless the current roster's owner signed it. The one
    exception: the next member may sign once the owner has left, and only with the departures that make them next as
    proof.
  - **Flooding.** Facts are capped: one of each kind per stint, and 2 per member for stints we can't place yet.
  - **Made-up heads.** Every group message carries the sender's head (docs/groups.md, "Heads"), and a head that differs
    from ours makes us send our state. A member who invents heads gets at most 3 state messages per head of ours, plus
    one each time they send something an hour or more after the last: no more than an honest member who is behind.
    A head only steers what we send them, never what we accept: rosters, facts and cards check themselves. Likewise,
    a blob whose hint names someone the owner removed makes it send them their removal again, once an hour at most.
- **Removed members** stop receiving at once (nobody encrypts to them any more), and every remaining member moves to a
  new inbox, so they can't even send noise for long. What they received before stays with them. Their old sessions
  carry nothing new.
- **The server** can drop, delay, reorder or replay messages. Replays and reordering change nothing: rosters are
  chained, and merging state is idempotent. Dropping only delays, until the next message between those members: its
  head shows what's missing, and whoever is ahead sends it (an hour after the last send, so it isn't sent twice while
  still on its way).
- **Residual:**
  - **Eventual consistency.** Membership can briefly differ between members while facts and rosters travel. Nothing
    is sent in the background: a group nobody writes in doesn't catch up, and what was lost (retention expiry) is
    sent again only once someone writes. A member whose copy of a departure was lost, and whom nobody who holds it
    can reach, goes on taking the leaver's messages (the leaver still has their sessions) until they hear.
  - **Invitees** are reached over 1:1 only, by the owner. An acceptance, a decline or a withdrawn invitation that's
    lost isn't sent again by itself: the invitee learns how things stand when they act (the owner answers an
    acceptance, and a waiting invitee can send theirs again, at most every 10 minutes), and the owner when the invitee
    writes to them again.
  - **A lost owner.** If the owner loses their phone (rather than leaving), membership can't change any more. Members
    can still talk, accept, decline and leave.

### Strangers and abusers
Anyone without a capability.
- **Can't:** message you at all. Sending needs that mailbox's `sendSecret`, which only your contact has.
- **Can:** try to exhaust a server: create mailboxes, flood sends, use invites. Defences:
  - memory-hard proof of work (Argon2id, 16 MiB per call, 256 calls at base) whose difficulty rises mostly for the
    network (or IPv6 /32) causing the load, and only a little (at most 4x) for everyone else;
  - GCRA limits per IP, network, IPv6 /32, mailbox and global, in Redis. The global creation limit is a high resource
    cap, so filling it takes hundreds of networks;
  - verification pushes before a mailbox goes live, and only verified mailboxes raise everyone's difficulty;
  - a bounded pool for PoW verification, of which one network may hold only a quarter, so checking junk solutions can't
    take the server's CPU or make everyone else wait;
  - send-limit challenges that can't create mailboxes, and tight caps on how much work the app does for a contact's
    server (at most 2^11 calls of 16 MiB, 180 s), so a hostile server can't burn the phone;
  - per-push-host circuit breakers;
  - an SSRF-safe push client.
- **Residual:** proof of work prices out cheap mass abuse; it doesn't stop a funded attacker. With native Argon2 a base
  mailbox costs about 3 core-seconds, so a million cost roughly $10–35 of cloud CPU, or a few dollars on GPUs (server
  README, `Goldfish:Pow`). Argon2 keeps the GPU advantage to a small factor (memory bandwidth, not hashing speed, limits
  it; our estimate is 1–20x cheaper per call than cloud CPUs, uncertain by an order of magnitude), instead of the 100x or
  more that SHA-256 gives. A phone is still far slower than any server, so honest users pay more time than attackers pay
  money. What actually caps an attacker with many networks (a botnet, many cloud addresses, a large IPv6 allocation) is
  the per-IP, per-network and per-/32 limits, with each of their networks paying its own rising difficulty. Privacy Pass
  tokens are future work.

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
- **Proof of work:** it costs an attacker with real computers little (about $10–35 per million mailboxes at base), and
  many networks get many budgets. The rate limits are the real cap. Privacy Pass would tie creation to something scarcer.
- **Server key:** `ServerKey` never expires. If it leaks, someone who can also intercept TLS can impersonate the server
  until you replace it, and replacing it warns every user.
- **Group members who aren't contacts** are vouched for by the owner. Until you compare safety numbers with them, a
  malicious owner could slip in an impostor.

## Advice for users
- Scan QR codes in person when you can. Compare safety numbers for important contacts.
- Use a push distributor that isn't Google's (ntfy, self-hosted if you can).
- Set an app PIN or passphrase and a short auto-lock.
- Turn on Tor if your IP matters.
- Use disappearing messages, and treat anything you send as something the recipient keeps.
