# Group chats (protocol v2)

Groups are a client-side protocol over the existing mailboxes and libsignal sessions. The server learns nothing new,
except a batch send endpoint so fan-out doesn't hit per-IP limits. This file is the contract; `docs/protocol.md`
links here.

## Design choices

- **Pairwise fan-out over libsignal sessions.** Every group message is encrypted separately to each member with the
  same Double Ratchet sessions used for 1:1 chats (PQXDH setup). We considered two alternatives:
  - **Sender Keys** (Signal's group cipher) save encryption work but weaken post-compromise security until keys are
    re-sent. Every member still needs its own push in our model, so there's nothing to gain.
  - **MLS** (RFC 9420) gives group-wide epochs, but there's no maintained Android library. A Rust library over JNI
    would add a large native dependency to the reproducible build.

  With per-recipient mailboxes the cost is one send per member either way.
- **No server-side group state.** The server can't tell a group message from a 1:1 message, or link the members.
- **Admins are trusted to manage membership.** The roster is signed by the admin who changed it, and every member
  checks it. Concurrent changes converge deterministically. The model is eventual consistency: there's no central
  ordering, by design.
- **Maximum 100 members.**

## Identifiers

- `groupId`: 32 random bytes, b64u. Chosen by the creator.
- **Member id:** the member's libsignal identity public key (33 B, b64u). A member is their identity key; a reinstall
  is a new member.
- **Sessions:** one libsignal session per remote identity, shared by every group that person is in, and separate from
  any 1:1 session with them (the app's address is `"m" ‖ b64u(SHA-256(identityKey))[0..22]`, device 1). It's dropped
  once they're in no group any more.

## Per-member data

### Group inbox
Each member creates **one mailbox per group** on their own server. They give its `sendSecret` to all other members
inside their card. Every member sends to it. The server sees one ordinary mailbox.

### Member card (signed by the member)
```json
{ "v": 1, "g": "groupId", "id": "identityKey b64u", "name": "self-chosen display name, optional",
  "inbox": { "server": "https://...", "serverKey": "fp b64u", "sendSecret": "b64u" },
  "hintKey": "b64u 32 B",
  "bundle": { "registrationId": 1, "deviceId": 1, "signedPreKeyId": 1, "signedPreKey": "b64u", "signedPreKeySig": "b64u",
              "kyberPreKeyId": 1, "kyberPreKey": "b64u", "kyberPreKeySig": "b64u" },
  "seq": 1 }
```
- `sig = XEdDSA(identityPrivate, "gf/group-card/v1" ‖ canonicalCardBytes)`, carried next to the card. "Canonical" means
  the exact UTF-8 JSON bytes as sent: the card travels as a b64u string, so nobody re-serialises it.
- `seq` grows with every new card from that member. A receiver keeps the highest `seq` per member and ignores older ones.
- `bundle` lets other members start a PQXDH session with this member. The prekeys are this group's own and are kept
  until the member leaves or publishes a new card. The Kyber prekey is a last-resort key, reused by every initiator.
- Receivers check that `sig` verifies under `id`, that `bundle`'s signatures verify under `id` and its keys parse, that
  `g` is this group, and that `inbox.server` passes the usual contact-server checks.

### Roster (signed by an admin)
```json
{ "v": 1, "g": "groupId", "ver": 7, "prev": "b64u SHA-256 of the previous roster's bytes, or empty at ver 1",
  "name": "Group name", "timer": 0, "adminsOnly": true,
  "members": [ { "id": "b64u", "role": "admin" }, { "id": "b64u", "role": "member" }, { "id": "b64u", "role": "invited" } ],
  "by": "author identityKey b64u", "ts": 1763000000 }
```
- `sig = XEdDSA(authorPrivate, "gf/group-roster/v1" ‖ rosterBytes)`. The roster travels as a b64u string with `sig`.
- `adminsOnly`: if true, only admins may change `name` and `timer`. Membership and roles always need an admin.
- `invited` members are listed but get no messages until they accept and publish a card.

#### Accepting a roster
For a received roster R, with current roster C:
1. `R.g` matches, `sig` verifies under `R.by`, and `R.members` has at most 100 entries, no duplicates and at least
   one admin.
2. **Authority:** `R.by` must be an admin in C. A member may also publish a roster whose only change is removing
   themselves (leaving), or turning their own `invited` into `member` (accepting).
3. **Order:**
   - If `R.ver == C.ver + 1` and `R.prev == hash(C)`, accept.
   - If `R.ver == C.ver` and `hash(R) != hash(C)` (two admins changed it at once), keep the one with the larger hash,
     except that a roster removing the other's author wins (an invitee's acceptance loses to the invitation being
     withdrawn). If both remove each other's author, the larger hash wins.
   - **Our own changes aren't lost.** Whenever we accept someone else's roster while a change of ours is still pending
     and that roster neither contains it nor builds on it, through any number of versions (our change lost a tie,
     possibly to a sibling we never saw), we re-apply it on top as the next version. A roster that builds on our change
     and lacks it was changed back on purpose. A change stays pending even once it's in, since the roster that took it
     in can still lose a tie, until it's 10 versions old. Our last 4 changes are pending (an admin's own change and the
     admits and removals it makes for others below can overlap).
   - Rosters we don't take (a lost tie, or an older version that's a valid change on its parent) are kept, at most 16
     per version, so that rosters others build on them can still be checked.
   - If `R.ver > C.ver` but it doesn't chain onto C (we missed some versions, or it builds on a concurrent sibling we
     never saw), accept only if `R.by` is an admin in C, then ask that admin for the missing history with `gsync`.
   - Otherwise ignore it.
   - **Departures can't be lost.** A roster signed by X that doesn't list X means "X is leaving" (or declining),
     whatever its version. If it lost a tie or arrived too late to apply, the leaver won't try again, so an admin who
     sees it while X is still in C publishes a roster removing X. The same when a roster we had taken loses a tie
     later: the losing branch (back to where it meets the winner) may hold someone's departure (or acceptance).
   - **Removals can't be lost on the removed member's side.** A roster by an admin (of its parent) that leaves us out
     and that we can't keep (it lost a tie here, now or later, or we had moved on) still means we're out: nothing
     the others take after it reaches us, since we're not in it.
   - **Acceptances can't be lost either.** Likewise, a roster signed by X that makes X a `member` while C still lists X
     as `invited` is X's acceptance: an admin who sees it but can't apply it publishes a roster making X a member.
     (Found on a real device: two invitees who join at about the same time produce concurrent rosters.)
   - Both only count if they're newer than X's current stint (the run of our rosters back from C that list X, or list
     X as invited): an old departure or acceptance, from before X was removed and added again, can be replayed by
     anyone who kept it.
   - A newer roster by a non-admin whose parent we don't have (we missed what came before), passed on by an admin:
     ask that admin for the history with `gsync`.
4. **Diff against the old roster:**
   - **Removed members:** stop sending to them. Their card is kept only until what's already queued to them (the roster
     that removed them) is delivered, then deleted, and so is their session once they're in no other group.
   - **If we were removed:** mark the group "You were removed" and stop sending.
   - **Once out** (removed, left or declined), only a roster built on the one that took us out invites us again. A
     concurrent roster that still lists us isn't an invitation.
   - **If anyone was removed:** rotate our group inbox (a new mailbox and a new card with a new `hintKey`), send the
     new card to the remaining members, and delete the old mailbox after a 15-day drain.

#### Relaying
Members only reach the members whose cards they have, and a member's view can lag (an invitee only has the cards the
admin forwarded when inviting them). Admins, who keep every card, close the gaps:
- **Rosters by non-admins** (accepting, leaving, declining, or a rename when `adminsOnly` is off): an admin who accepts
  one sends it on to every member whose card they have.
- **A newcomer's first card:** an admin who receives a member's first card sends it on to every other member. Every
  member who receives someone's first card sends them their own (the newcomer's copy may be missing or old: cards
  change when inboxes rotate), and admins also send the current roster (rosters relayed before the newcomer could be
  reached didn't reach them).
- **Invited members** have no inbox yet: rosters reach them only over 1:1, from an author who has them as a contact. An
  admin relaying a roster sends it to invitees over 1:1 too, so they don't build their acceptance on a stale roster.
  On joining they send `gsync` to their inviter, over 1:1 if they can. A roster that arrives over 1:1 from an admin of
  it, for a group we don't know, and leaves us out, voids an older invitation from that admin arriving after it (1:1
  messages aren't ordered either). The newest 32 are remembered.
- **`gsync` from someone who's out** (the roster removing them never reached them, for example it arrived before the
  invitation, and they joined): an admin answers over 1:1 with the roster that removed them, and nothing newer.
- **`gsync` answers start one version early:** the rosters from `have` onwards (not just after it), because the asker's
  copy of version `have` may be a concurrent sibling that lost, and they need the winner.

Duplicates are harmless: a roster already held is ignored, and a card with a `seq` already held is ignored.

## Message format

### Blob
The E2E blob to a group member is `type ‖ hint ‖ ciphertext`:
- `type`: `0x13` (PreKey) or `0x12` (normal), the 1:1 type values with `0x10` set.
- `hint = nonce(16) ‖ HMAC-SHA256(recipient.hintKey, "gf/group-hint/v1" ‖ nonce ‖ senderId)[0..16]`, where `senderId`
  is the sender's 33-byte serialized identity key.
- `ciphertext`: the libsignal ciphertext.

The recipient computes the HMAC for every member of the group whose inbox this is (with that inbox's own hint key: a
rotated inbox keeps its old one while it drains), to find the sender. That's cheap, and the server can't link two
messages from the same sender, because the nonce is random. A blob with no matching member is dropped. A PreKey message
whose hint matches the identity inside it, but who isn't a member yet, is held for up to 7 days waiting for a roster
that adds them, then dropped.

Pushes aren't ordered, so a newcomer's first messages can arrive before their acceptance. A `gtext`, `greceipt` or
`gdelete` from someone C still lists as `invited` is kept (already decrypted, in the encrypted database, for at most
7 days) and replayed once a roster makes them a member.

**Senders address every active member**, not only the members whose card they hold. A row for a member whose card hasn't
arrived yet (a newcomer's card can come after their roster) waits in the outbox, for about a week at most.

The plaintext uses the same padding as 1:1 messages, at most **2048 B padded** for every group message: content is
encrypted once per member, and any member's session may still be at the PreKey stage.

### Chunking
Content too large for one message (any type: long texts, cards, rosters) is sent as `chunk` parts, in groups and 1:1:
```json
{ "t": "chunk", "id": "b64u 12 B", "part": 0, "parts": 3, "data": "b64u slice of the content's JSON bytes" }
```
`parts` is 2 to 64. Each slice except the last is a multiple of 3 bytes, so the parts' `data` strings concatenate to the
b64u of the whole content. Parts are reassembled per sender (and, in groups, per member), then handled as the content
they carry. A chunk never contains a chunk. In 1:1 chats, `text` keeps its own `part`/`parts` fields as before.

### Content types (JSON `t`), all with `g` = groupId
| t | Fields | Sender | Meaning |
|---|---|---|---|
| `gtext` | `id`, `body`, `ts`, `exp?`, `once?` | member | A chat message (long ones go as `chunk` parts) |
| `greceipt` | `ids[]`, `kind` (`read`) | member | Read receipts, batched per author, sent only to the message's author and only if read receipts are on. Groups send no delivery receipts: that would be a push to the author per member per message. An outgoing message shows "read" once every member it went to has read it. |
| `gdelete` | `ids[]` | author of those messages | Delete for everyone |
| `groster` | `roster` (b64u bytes), `sig` | admin, or self for leave/accept | A new roster, sent to every member in the old and new roster (see "Relaying") |
| `gcard` | `card` (b64u bytes), `sig` | anyone forwarding a valid card | A member card |
| `gsync` | `have` (`ver`) | member | "Send me the roster and cards." Any admin who receives it answers with the rosters after `have` (at most 50, oldest first, including the current one), and all cards. |
| `gleave` | | member | "I'm leaving". Receivers stop sending to that member at once. The leaver's own self-removal roster updates the roster (with the departure rule as a backstop). |

## Flows

### Create
The creator picks a name and some contacts. They create their group inbox and card, and publish roster v1: themselves
as admin and the contacts as `invited`. Each invitee gets, over the existing **1:1 session**, a `groster` plus the
creator's `gcard`. The 1:1 session identifies the creator, so this needs no new trust.

### Add a member (admin only, and only the admin's own contacts)
The admin publishes `ver + 1` with the new member as `invited`. They send `groster` to everyone, and send the newcomer
all current cards over the 1:1 session.

### Accept or decline
The invitee sees "Alice added you to <name>", with Join or Decline.
- **Join:** create the group inbox, prekeys and card. Publish the self-accept roster (`invited` to `member`), then send
  the card, to every member whose card we have (starting PQXDH sessions from their bundles), then `gsync` to the inviter.
  Admins relay the roster and the card to everyone else.
- **Decline:** publish the self-removal roster. It also goes to the inviter over 1:1, which still arrives if the chat is
  deleted right away.

### Leave
Send `gleave` to all, publish the self-removal roster, delete the group inbox (no drain needed) and this group's
prekeys. The chat stays (read-only) until the user deletes it.
- **The last admin can't leave** without promoting someone; the UI requires it.
- **If the last admin's app is gone,** the roster can't change any more; members can only leave. That limitation is
  stated in the UI.

### Remove or change a role (admin only)
Publish a roster, as above. The removed member gets the roster too, so they know.

## Rules and limits

- **Per-member checks:** a `gtext`, `greceipt` or `gdelete` is accepted only from a current member (not `invited`),
  identified by the hint and authenticated by their session (a PreKey message must carry the roster's identity key).
- **Who changes name and timer:** admins, or anyone if `adminsOnly` is false. The change is sent as a new roster, so
  only admins can sign it. A non-admin's change, allowed when `adminsOnly` is false, is a `groster` they author
  themselves, accepted under rule 2 only for those two fields.
- **Group timer:** works like the 1:1 disappearing timer. `exp` on each message is authoritative.
- **Names:** if a member is also your contact (same identity key), you see your own name for them. Otherwise you see
  their self-chosen name, marked as unverified. Safety numbers can be compared per member.
- **Identity changes:** a member's identity key never changes inside a group. A reinstalled member must be removed and
  added again.
- **Hidden chats, the decoy profile and wipes** treat groups like chats. Wiping messages keeps queued rosters and cards
  (they aren't messages), so the group stays consistent.
- **Inbox rotation** also happens on the mailbox-rotation schedule (if enabled) and when our own server's identity key
  changes (the new card carries the new `serverKey`).
- **A member's server presents a different identity key** than their card says: only that member's deliveries wait,
  until they send a new card (E2E-authenticated) or the server proves the pinned key again. There's no manual
  override per member.

## Server: batch send

`POST /v1/messages/batch` (an inner gateway request), `Content-Type: application/octet-stream`. The body:
```
u8 count (1..32)
per item: sendSecret(32) ‖ idempotencyKey(16) ‖ u32 ttlSeconds (0 = default) ‖ u16 len ‖ blob(len)
```
- **Body limit:** the whole body stays within the normal 16 KiB inner limit. Clients split larger fan-outs.
- **`GF-PoW`:** optional, and pays for the whole batch.
- **Parsing is strict:** `count` 1 to 32, every `len` 1 to `maxMessageBytes`, and the items must use up the body exactly.
  Anything else rejects the whole batch with `400 invalid_request`, and a wrong `Content-Type` gets `415`.
- **Response:** `200 { "results": [ { "status": 202, "id": "b64u" } | { "status": 404|429|507, "error": "...",
  "scope": "...", "retryAfter": n } ] }`, in item order. `retryAfter` is in seconds. Each item is handled exactly like
  `POST /v1/messages`, including its idempotency key: retrying a whole batch with the same keys returns the same ids
  and delivers nothing twice. A repeated key inside one batch also returns the first item's id.
- **Whole-batch errors:** the client rate limit (`429` with `Retry-After` and `scope` `ip` or `network`), the errors
  above, and server failures. After a failure, retry the whole batch with the same idempotency keys.
- **Rate limits:**
  - **Per item:** the mailbox-lookup cap, per-mailbox and global limits, and the held-message quotas, like single sends.
    A batch can't probe mailboxes any faster than single sends.
  - **Per batch:** the per-IP and per-network buckets are charged `ceil(count / 8)` tokens for the whole batch. A batch
    leaks nothing new: the server already sees fan-out as N sends from one IP at one moment. If the bucket can't cover
    the cost, the whole batch gets `429`.
- **Fallback:** if the server doesn't have the endpoint (`404` for the path), clients fall back to single sends. Through
  the gateway that's an inner `404` with no JSON error code (unlike a send's `not_found`). The app remembers it per
  server for 6 hours.
- **Client batching:** one batch per member server, at most 32 items and 16 KiB of body, each member's head row only
  (per-member order is kept). Per-item `404` means that member's inbox is gone: their rows wait for their next card.
