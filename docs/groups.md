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
- Receivers check that `sig` verifies under `id`, that `bundle`'s signatures verify under `id`, that `g` is this group,
  and that `inbox.server` passes the usual contact-server checks.

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
   - If `R.ver == C.ver` and `hash(R) != hash(C)` (two admins changed it at once), keep the one with the larger hash.
     If C loses and we authored it, re-apply our change on top of R as `ver + 1`.
   - If `R.ver > C.ver + 1` (we missed some), accept only if `R.by` is an admin in C, then ask for the missing history
     with `gsync`.
   - Otherwise ignore it.
4. **Diff against the old roster:**
   - **Removed members:** delete their card, stop sending to them, and drop their sessions for this group.
   - **If we were removed:** mark the group "You were removed" and stop sending.
   - **If anyone was removed:** rotate our group inbox (a new mailbox and a new card with a new `hintKey`), send the
     new card to the remaining members, and delete the old mailbox after a 15-day drain.

## Message format

### Blob
The E2E blob to a group member is `type ‖ hint ‖ ciphertext`:
- `type`: `0x13` (PreKey) or `0x12` (normal), the 1:1 type values with `0x10` set.
- `hint = nonce(16) ‖ HMAC-SHA256(recipient.hintKey, "gf/group-hint/v1" ‖ nonce ‖ senderId)[0..16]`.
- `ciphertext`: the libsignal ciphertext.

The recipient computes the HMAC for every member of every group whose inbox this is, to find the sender. That's cheap,
and the server can't link two messages from the same sender, because the nonce is random. A blob with no matching
member is dropped. PreKey messages from an identity that isn't a member (or isn't yet) are held for up to 7 days
waiting for a roster that adds it, then dropped.

The plaintext uses the same padding and chunking (`part`/`parts`) as 1:1 messages. Chunking applies to any content
type, not only `text`.

### Content types (JSON `t`), all with `g` = groupId
| t | Fields | Sender | Meaning |
|---|---|---|---|
| `gtext` | `id`, `body`, `ts`, `exp?`, `once?`, `part?`, `parts?` | member | A chat message |
| `greceipt` | `ids[]`, `kind` | member | Delivered/read receipts. Sent only to the message's author, and only if read receipts are on. |
| `gdelete` | `ids[]` | author of those messages | Delete for everyone |
| `groster` | `roster` (b64u bytes), `sig` | admin, or self for leave/accept | A new roster, sent to every member in the old and new roster, invited members included |
| `gcard` | `card` (b64u bytes), `sig` | anyone forwarding a valid card | A member card |
| `gsync` | `have` (`ver`) | member | "Send me the roster and cards." Any admin who receives it answers with the latest roster, its history back to `have`, and all cards. |
| `gleave` | | member | "I'm leaving". Receivers stop sending to that member at once. Any admin then publishes a roster without them. |

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
- **Join:** create the group inbox, prekeys and card. Publish the self-accept roster (`invited` to `member`) and send it
  with the card to every member, starting PQXDH sessions from their bundles.
- **Decline:** publish the self-removal roster.

### Leave
Send `gleave` to all, publish the self-removal roster, and delete the group inbox (no drain needed).
- **The last admin can't leave** without promoting someone; the UI requires it.
- **If the last admin's app is gone,** the roster can't change any more; members can only leave. That limitation is
  stated in the UI.

### Remove or change a role (admin only)
Publish a roster, as above. The removed member gets the roster too, so they know.

## Rules and limits

- **Per-member checks:** a `gtext`, `greceipt` or `gdelete` is accepted only from a current member (not `invited`) with a
  valid card.
- **Who changes name and timer:** admins, or anyone if `adminsOnly` is false. The change is sent as a new roster, so
  only admins can sign it. A non-admin's change, allowed when `adminsOnly` is false, is a `groster` they author
  themselves, accepted under rule 2 only for those two fields.
- **Group timer:** works like the 1:1 disappearing timer. `exp` on each message is authoritative.
- **Names:** if a member is also your contact (same identity key), you see your own name for them. Otherwise you see
  their self-chosen name, marked as unverified. Safety numbers can be compared per member.
- **Identity changes:** a member's identity key never changes inside a group. A reinstalled member must be removed and
  added again.
- **Hidden chats, the decoy profile and wipes** treat groups like chats.

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
- **Fallback:** if the server doesn't have the endpoint (`404` for the path), clients fall back to single sends.
