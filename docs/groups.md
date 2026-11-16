# Group chats (protocol v2)

Groups are a client-side protocol built on the existing mailboxes and libsignal sessions. The server learns nothing new,
apart from a batch send endpoint so that fan-out doesn't hit per-IP limits. This file is the contract;
`docs/protocol.md` links here. `docs/groups-redesign.md` explains why groups have one owner rather than admins.

## Design choices

- **Pairwise fan-out over libsignal sessions.** Every group message is encrypted separately to each member, with the
  same Double Ratchet sessions used for 1:1 chats (PQXDH setup). We considered two alternatives:
  - **Sender Keys** (Signal's group cipher) save encryption work, but weaken post-compromise security until keys are
    re-sent. In our model every member still needs their own push, so there's nothing to gain.
  - **MLS** (RFC 9420) gives group-wide epochs, but there's no maintained Android library. A Rust library over JNI
    would add a large native dependency to the reproducible build.

  With per-recipient mailboxes the cost is one send per member either way.
- **No server-side group state.** The server can't tell a group message from a 1:1 message, or link the members.
- **One owner orders the membership.** Only the owner signs rosters, so the roster is a single chain with no forks.
  Each member's own accept and leave is a fact they sign themselves. Every member applies the facts they hold to the
  roster, so those decisions never wait for the owner and can't be lost. Concurrent changes therefore always agree:
  the same roster and the same facts give the same membership, in any order. When the owner leaves, the next member
  in the roster takes over.
- **Maximum 100 members.**

## Identifiers

- `groupId`: 32 random bytes, b64u, chosen by the creator.
- **Member id:** the member's libsignal identity public key (33 B, b64u). A member is their identity key, so a
  reinstall is a new member.
- **Sessions:** one libsignal session per remote identity. It is shared by every group that person is in, and kept
  separate from any 1:1 session with them. The app's address is `"m" ‖ b64u(SHA-256(identityKey))[0..22]`, device 1.
  The session is dropped once they're in no group any more.

## Per-member data

### Group inbox
Each member creates **one mailbox per group** on their own server, and gives its `sendSecret` to all other members in
their card. Every member sends to it. The server sees one ordinary mailbox.

### Member card (signed by the member)
```json
{ "v": 1, "g": "groupId", "id": "identityKey b64u", "name": "self-chosen display name, optional",
  "inbox": { "server": "https://...", "serverKey": "fp b64u", "sendSecret": "b64u" },
  "hintKey": "b64u 32 B",
  "bundle": { "registrationId": 1, "deviceId": 1, "signedPreKeyId": 1, "signedPreKey": "b64u", "signedPreKeySig": "b64u",
              "kyberPreKeyId": 1, "kyberPreKey": "b64u", "kyberPreKeySig": "b64u" },
  "seq": 1 }
```
- `sig = XEdDSA(identityPrivate, "gf/group-card/v1" ‖ canonicalCardBytes)`, carried next to the card.
  - "Canonical" means the exact UTF-8 JSON bytes as sent. The card travels as a b64u string, so nobody re-serialises it.
- `seq` grows with every new card from that member. A receiver keeps the highest `seq` per member and ignores older
  ones.
- `bundle` lets other members start a PQXDH session with this member.
  - Its prekeys belong to this group, and are kept until the member leaves or publishes a new card.
  - The Kyber prekey is a last-resort key, reused by every initiator.
- Receivers check that:
  - `sig` verifies under `id`;
  - `bundle`'s signatures verify under `id`, and its keys parse;
  - `g` is this group;
  - `inbox.server` passes the usual contact-server checks.

### Roster (signed by the owner)
```json
{ "v": 2, "g": "groupId", "ver": 7, "prev": "b64u SHA-256 of the previous roster's bytes, or empty at ver 1",
  "name": "Group name", "timer": 0,
  "members": [ { "id": "b64u", "role": "owner", "since": 1 }, { "id": "b64u", "role": "member", "since": 3 },
               { "id": "b64u", "role": "invited", "since": 7 } ],
  "by": "signer identityKey b64u", "ts": 1763000000,
  "proof": [ { "data": "b64u fact bytes", "sig": "b64u" } ] }
```
- `sig = XEdDSA(signerPrivate, "gf/group-roster/v2" ‖ rosterBytes)`. The roster travels as a b64u string with `sig`.
- **Exactly one `owner`.** Only they change the name, the timer or the membership.
- **`since`** is the version of the roster that invited the member. It names this **stint** of theirs: someone who is
  removed or leaves, then is invited again, starts a new stint with a new `since`.
- **`invited`** members are listed, but get no messages until they accept and publish a card.
- **`proof`** lists the departures this roster takes in (see "The view"). When the owner of the previous roster has
  left, it is also what makes the signer their successor.

### Fact (signed by the member it's about)
```json
{ "v": 2, "g": "groupId", "kind": "accept", "id": "identityKey b64u", "since": 7, "ts": 1763000000,
  "card": { "data": "b64u card bytes", "sig": "b64u" } }
```
- `sig = XEdDSA(idPrivate, "gf/group-fact/v2" ‖ factBytes)`.
- **`kind`**:
  - `accept`: an invitee joins;
  - `leave`: a member leaves, or an invitee declines.
- **`since`** names the stint the fact is about. A fact about any other stint means nothing. A late or replayed fact
  about an old stint is therefore ignored, and a member who is invited again isn't affected by their old departure.
- **`last`**, on a departure only, is the newest roster the leaver held. Whoever takes over from them builds on it, so
  a roster the leaver signed just before leaving isn't forked around.
- **`card`**, on an acceptance only, is the newcomer's card. Whoever learns they're in can reach them, including an
  owner who never got the card itself.

#### The view
Everything a member does with the group acts on the **view**: the newest roster, with the facts held for its stints
applied.
- **Departures.** A `leave` for a listed stint takes that member out.
- **Acceptances.** An `accept` for an `invited` stint makes that member a `member`.
- **Effective owner.** It's the roster's owner, unless a held `leave` ended their stint. Then it's the first `member`
  in roster order whose stint hasn't ended, or nobody.
  - Only departures move ownership, never acceptances. So of two honest members, at most one can believe they're the
    next owner: everyone ahead of them must have left.
- **Nobody left to own it.** If no member is left to take over, nothing can change any more, and nobody can join.
  Acceptances nobody took in don't count either, so everyone still listed as invited stays invited. Nobody passes facts
  on then, so who's still listed may differ between members; nothing anyone can do depends on it. A member who sees
  this may only be behind, though: a newer roster, with an owner, still counts.
- **A departure carrying a newer roster** (`last`) only applies once our roster has caught up with it.
- **Applying the view.** The view is a pure function of the roster and the facts. It's applied the moment it changes:
  - who receives our messages;
  - whose messages we accept;
  - inbox rotation when someone goes;
  - system lines.

The effective owner **folds** the facts it holds into its next roster: departures out (as `proof`), acceptances made
`member`, and itself as `owner`. It does this whenever it holds facts that the roster doesn't show yet, and folds the
facts into every change it makes. Folding is housekeeping: the view is already right before it.

#### Accepting a roster
For a received roster R, with current roster C:
1. **Structure.** `R.g` matches, and `sig` verifies under `R.by`. `R.members` has 1 to 100 entries, no duplicates,
   exactly one owner, and every `since` is between 1 and `R.ver`. At version 1, the owner signed it and `prev` is
   empty.
2. **Chain.** `R.ver == C.ver + 1` and `R.prev` is C's hash.
   - `R.by` is C's effective owner, given the departures in `R.proof` and no others: a roster carries what it relies on.
   - None of the proof's members are still listed.
   - Every member in both rosters keeps their `since`. A new entry is `invited`, with `since == R.ver`.
3. **Order.**
   - **Older rosters.** One at or below our version is old news and is ignored. A second roster at a version we hold
     means the owner equivocated. That includes a successor who sent a departure and went on signing.
   - **Rosters with a gap.** One further on is kept (at most 16 per version, 2 per signer), and we ask for what's in
     between with `gsync`: from whoever sent it, and from the owner, once per gap an hour. Kept rosters that follow on
     are taken as the gap fills. One kept like that is looked at again if it comes once more (as an invitation, say).
4. **Diff the view before and after:**
   - **Members who went:** stop sending to them. A departure shows as "left", a removal as "removed".
     - Their card is kept only until what's already queued to them (the roster that took them out) is delivered. Then
       it is deleted, and so is their session once they're in no other group.
   - **If we were taken out:** mark the group "You were removed" and stop sending.
   - **Once out** (removed, left or declined), a roster that lists us as `invited` with a newer `since` is a new
     invitation. Like a first invitation, it's taken on the word of the owner who sent it over 1:1, even past a gap:
     what happened while we were out isn't ours to know.
   - **If anyone went:** rotate our group inbox. That means a new mailbox and a new card with a new `hintKey`, sent to
     the remaining members; the old mailbox is deleted after a 15-day drain.

#### Accepting a fact
- **Checks.** A fact must verify under its `id` and be for this group. If it carries `last`, that roster is taken
  first (it may be news).
- **Before the invitation.** A fact over 1:1 for a group we don't know yet may have overtaken our invitation (the
  owner left right after inviting us). It's kept, the newest 16 in all, and applied once the invitation comes.
- **Which facts are kept.**
  - **Our roster lists the stint:** the fact counts at once.
  - **About a newer stint than our roster reaches:** it's kept until the roster catches up, at most 2 per member.
  - **About a stint that's over:** it's ignored.
  - **Duplicates:** one fact of each kind per stint.
- **Forwarding to the owner.** Whoever gets a fact first-hand from its author passes it on to the effective owner,
  who takes facts in and may not be reachable by the author (no card, not a contact). When the effective owner
  changes, every member passes the new owner the facts it holds that the roster doesn't show yet (the old owner may
  have been the only one they reached). Either way, at most once per member and fact.
- **After leaving.** A member who has left still passes a fact that reaches it over 1:1 to the roster's members who
  are its contacts, once. It may be the only link between the author and the people it invited.

#### Relaying
Members only reach the members whose cards they have, and a member's view can lag: an invitee only has the cards the
owner sent when inviting them. The owner, who keeps every card, closes the gaps:
- **Facts** go from their author to everyone in the roster: through their card if the author has it, and otherwise
  over 1:1. Invitees have no inbox yet, but the owner invited them, so they're the owner's contacts. Facts also go to
  the author's inviter over 1:1. The owner's next roster takes the facts in, and reaches everyone.
- **A newcomer's first card.** Every member who receives it sends the newcomer their own card. The newcomer's copy may
  be missing or old, since cards change when inboxes rotate. The owner also sends:
  - the newcomer the current roster (rosters sent before the newcomer could be reached didn't reach them) and every
    card;
  - the newcomer's card to every other member, and to invitees over 1:1.
- **Invited members** have no inbox yet: rosters reach them only over 1:1. The owner sends every roster to them that
  way.
- **On joining,** invitees send `gsync` to their inviter (over 1:1 if they can), and their card the same way.
- **Unordered 1:1 messages.** A roster that arrives over 1:1 from its owner, for a group we don't know, and leaves us
  out, voids an older invitation from that owner arriving after it. The newest 32 are remembered.
- **`gsync` from someone who's out** (the roster taking them out never reached them; for example, it arrived before
  the invitation, and they joined): a member answers over 1:1 with that roster, and nothing newer.
- **`gsync` answers** come from any member, since the chain checks itself. They contain:
  - the rosters from `have` onwards, at most 50 (the asker asks again from where it got to);
  - the facts held that the roster doesn't show yet;
  - every card.

  To someone who isn't an active member, the answer goes over 1:1 where possible.

Duplicates are harmless: a roster, fact or card already held is ignored.

## Message format

### Blob
The E2E blob to a group member is `type ‖ hint ‖ ciphertext`:
- `type`: `0x13` (PreKey) or `0x12` (normal), the 1:1 type values with `0x10` set.
- `hint = nonce(16) ‖ HMAC-SHA256(recipient.hintKey, "gf/group-hint/v1" ‖ nonce ‖ senderId)[0..16]`, where `senderId`
  is the sender's 33-byte serialized identity key.
- `ciphertext`: the libsignal ciphertext.

The recipient finds the sender by computing the HMAC for every member of the roster of the group whose inbox this is.
Each inbox uses its own hint key: a rotated inbox keeps its old one while it drains.
- **Cost and privacy.** That's cheap, and because the nonce is random the server can't link two messages from the
  same sender.
- **No match.** A blob with no matching member is dropped.
- **Newcomers.** A PreKey message whose hint matches the identity inside it, but from someone who isn't a member yet,
  is held for up to 7 days, waiting for a roster that adds them. Then it's dropped.
- **Early messages.** Pushes aren't ordered, so a newcomer's first messages can arrive before their acceptance. A
  `gtext`, `greceipt` or `gdelete` from someone the view still lists as `invited` is kept, already decrypted, in the
  encrypted database, for at most 7 days. It's replayed once the view makes them a member.

**Senders address every active member**, not only the members whose card they hold. A row for a member whose card hasn't
arrived yet (a newcomer's card can come after their acceptance) waits in the outbox, for about a week at most.

The plaintext uses the same padding as 1:1 messages, at most **2048 B padded** for every group message: content is
encrypted once per member, and any member's session may still be at the PreKey stage.

### Chunking
Content too large for one message is sent as `chunk` parts, in groups and 1:1. This applies to any type: long texts,
cards, rosters, facts that carry a roster.
```json
{ "t": "chunk", "id": "b64u 12 B", "part": 0, "parts": 3, "data": "b64u slice of the content's JSON bytes" }
```
- `parts` is 2 to 64.
- Each slice except the last is a multiple of 3 bytes, so the parts' `data` strings concatenate to the b64u of the
  whole content.
- Parts are reassembled per sender (and, in groups, per member), then handled as the content they carry.
- A chunk never contains a chunk.
- In 1:1 chats, `text` keeps its own `part`/`parts` fields as before.

### Content types (JSON `t`), all with `g` = groupId
| t | Fields | Sender | Meaning |
|---|---|---|---|
| `gtext` | `id`, `body`, `ts`, `exp?`, `once?` | member | A chat message (long ones go as `chunk` parts) |
| `greceipt` | `ids[]`, `kind` (`read`) | member | Read receipts, batched per author, sent only to the message's author and only if read receipts are on. Groups send no delivery receipts: that would be a push to the author per member per message. An outgoing message shows "read" once every member it went to has read it. |
| `gdelete` | `ids[]` | author of those messages | Delete for everyone |
| `groster` | `roster` (b64u bytes), `sig` | the owner (or anyone passing one on) | A new roster, sent to every member in the old and new roster |
| `gfact` | `fact` (b64u bytes), `sig` | the member it's about (or anyone passing it on) | An accept or a leave (see "Fact") |
| `gcard` | `card` (b64u bytes), `sig` | anyone forwarding a valid card | A member card |
| `gsync` | `have` (`ver`) | member | "Send me the roster and cards." Any member who receives it answers (see "Relaying"). |
| `gleave` | | member | "I'm leaving". Receivers stop sending to that member at once. The leaver's departure fact does the rest. |

## Flows

### Create
The creator picks a name and some contacts. They create their group inbox and card, and publish roster v1: themselves
as owner, and the contacts as `invited`, all with `since` 1. Each invitee gets a `groster` plus the creator's `gcard`
over the existing **1:1 session**. The 1:1 session identifies the creator, so this needs no new trust.

### Add a member (owner only, and only the owner's own contacts)
The owner publishes `ver + 1` with the new member `invited` and `since == ver + 1`. They send `groster` to everyone,
and send the newcomer all current cards over the 1:1 session.

### Accept or decline
The invitee sees "Alice added you to <name>", with Join or Decline.
- **Join:**
  1. Create the group inbox, prekeys and card.
  2. Send an `accept` fact (see "Relaying"), and the card to every member whose card we have. Sessions start from
     their bundles.
  3. Send `gsync` to the inviter.

  The owner takes the acceptance into its next roster, and relays the card. A group with nobody left to own it can't
  be joined.
- **Decline:** send a `leave` fact. It goes to the inviter over 1:1 too, which still arrives if the chat is deleted
  right away.

### Leave
1. Send `gleave` to all, and a `leave` fact carrying our newest roster.
2. Delete the group inbox (no drain needed) and this group's prekeys.

The chat stays, read-only, until the user deletes it.
- **Anyone can leave, the owner too.** An owner first folds the acceptances it holds, so that whoever has joined can
  take over. The next member in the roster becomes the owner, and the UI says who that will be. An owner who wants
  someone else to take over makes them owner first.
- **If the owner's app is gone** (lost phone, wipe), with no departure: the roster can't change any more. Members still
  talk, and accept, decline and leave, since those are facts; nobody can be added or removed. To carry on, a member
  starts a new group with the members who are their contacts. That limitation is stated in the UI.

### Remove, or make someone else the owner (owner only)
Publish a roster, as above. The removed member gets the roster too, so they know. Making someone else the owner keeps
us on as a member.

## Rules and limits

- **Per-member checks:** a `gtext`, `greceipt` or `gdelete` is accepted only from a current member (not `invited`),
  identified by the hint and authenticated by their session (a PreKey message must carry the roster's identity key).
- **Who changes name and timer:** the owner only. The change goes out as a new roster.
- **Group timer:** works like the 1:1 disappearing timer. `exp` on each message is authoritative.
- **Names:** if a member is also your contact (same identity key), you see your own name for them. Otherwise you see
  their self-chosen name, marked as unverified. Safety numbers can be compared per member.
- **Identity changes:** a member's identity key never changes inside a group. A reinstalled member must be removed and
  added again.
- **Hidden chats, the decoy profile and wipes** treat groups like chats. Wiping messages keeps queued rosters, facts and
  cards (they aren't messages), so the group stays consistent.
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
