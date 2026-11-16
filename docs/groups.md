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
3. **Order (fork choice).** Concurrent changes make the rosters a tree: every roster names its parent (`prev`), and two
   members can build on the same parent, or on each other's siblings, before they hear of each other. Every member
   takes the same branch of that tree, given the same rosters, whatever order they arrived in:
   - **The tree.** A roster R joins it if its parent P is held and R is a valid step from P: `R.ver == P.ver + 1` and
     R passes rule 2 against P (not against C). Rosters that don't join it are still kept (at most 64 per version, 8 per
     author), so they count once what they build on arrives.
   - **The window.** Forks are decided from the roster 16 versions below C (or the oldest one we hold of C's line, if
     we skipped versions). Anything forking further back is final: an old branch can never be brought back.
   - **The choice.** From there, at each fork take the child whose branch (followed down by the same rule to its tip)
     wins; the tip of that walk is the current roster. Between two branches A and B growing from fork F, in order:
     1. If A ends without the author of B's first roster, who is in F (they were removed, or they left), and B doesn't
        do the same to A's, A wins. A removal beats the removed member's own concurrent change (an invitee's
        acceptance loses to the invitation being withdrawn), and a departure stands.
     2. The branch with more changes made by an admin (of the roster each builds on) wins. A member who isn't one can't
        outweigh an admin's change, however many rosters they sign or however long their branch is.
     3. The branch with more distinct authors wins: one member can't outweigh several.
     4. The larger hash of the first roster wins.
   - **Rebasing.** When the choice moves us off our branch, our own changes on it that the new branch neither has nor
     builds on are re-applied on top of it and re-signed, all in one roster. A roster that builds on our change and
     lacks it was changed back on purpose. Our last 8 changes stay pending, even once they're in (the roster that took
     them in can still lose), until they're 16 versions old.
   - **Skipped versions.** A roster whose parent we don't have, from an admin of C and newer than C, is taken anyway
     (we missed versions), and we ask that admin for the history with `gsync`. Any other roster we can't place: if an
     admin signed or passed it on, ask them for the history from 16 versions back, once per roster.
   - **Departures can't be lost.** A roster signed by X that doesn't list X means "X is leaving" (or declining),
     whatever its version or branch. An admin who holds one while X is still in C publishes a roster removing X. Every
     roster in the tree counts, not only new ones: one can join the tree long after it arrived, or sit on a branch that
     lost.
   - **Acceptances can't be lost either.** Likewise, a roster signed by X that makes X a `member` while C still lists X
     as `invited` is X's acceptance: an admin publishes a roster making X a member. And when we've joined but take a
     roster that still lists us as invited (our acceptance was lost, or was for an earlier invitation), we accept again
     and send our card again.
   - Both only count if they're newer than X's current stint (the run of our rosters back from C that list X, or list
     X as invited): an old departure or acceptance, from before X was removed and added again, can be replayed by
     anyone who kept it.
   - **Removals can't be lost on the removed member's side.** A roster by an admin (of its parent) that leaves us out
     and that we don't take (it's on a branch that lost, or too old) still means we're out, if it's from our current
     stint: nothing the others take after it reaches us, since we're not in it.
   - **Cost.** Duplicates change nothing: the choice depends only on the rosters held. A roster that moves a member to
     another branch costs at most: their rebased changes (at most 8, one roster each), the departures and acceptances
     on the losing branch (one roster each, from each admin), and the losing branch passed on by admins; each roster
     goes to every member once, so O(members) per change involved. A member who isn't an admin can only win a fork
     against other non-admins' changes, one author against one, and only by hash, so each roster they sign moves
     others at most once.
4. **Diff against the old roster:**
   - **Removed members:** stop sending to them. Their card is kept only until what's already queued to them (the roster
     that removed them) is delivered, then deleted, and so is their session once they're in no other group.
   - **If we were removed:** mark the group "You were removed" and stop sending.
   - **Once out** (removed, left or declined), only a roster on whose line we were taken out at some point (a step from
     a roster listing us to one that doesn't) invites us again. A branch on which that never happened (it lost to our
     departure or removal elsewhere) isn't an invitation. Where we don't hold the line that far back, it's checked
     again as the rosters we were missing arrive.
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
  copy of version `have` may be a concurrent sibling that lost, and they need the winner. To someone who isn't an
  active member (still invited, or invited again while out) they go over 1:1 where possible: such a member may not
  read their group inbox. A member who is out but listed as invited, and can't tell whether that's a new invitation
  (a gap in their history), asks the admin who signed it, once per roster.

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
