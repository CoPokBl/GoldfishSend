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
- **Delivery follows state, not events.** Every group message carries where its sender is (their head). Whoever is
  ahead sends one idempotent state message, whatever was lost before, so nothing depends on a particular message
  arriving. Invitees stay outside this until the owner takes them in. There is no background traffic: a group catches
  up as its members write.
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
- `seq` grows with every new card from that member, across stints: someone who joins again after being out uses a
  higher `seq` than their last card, which others may still hold. A receiver keeps the highest `seq` per member and
  ignores older ones.
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
  "members": [ { "id": "b64u", "role": "owner", "since": 1 },
               { "id": "b64u", "role": "member", "since": 3, "card": { "data": "b64u card bytes", "sig": "b64u" } },
               { "id": "b64u", "role": "invited", "since": 7 } ],
  "by": "signer identityKey b64u", "ts": 1763000000,
  "proof": [ { "data": "b64u fact bytes", "sig": "b64u" } ] }
```
- `sig = XEdDSA(signerPrivate, "gf/group-roster/v2" ‖ rosterBytes)`. The roster travels as a b64u string with `sig`.
- **Exactly one `owner`.** Only they change the name, the timer or the membership.
- **`since`** is the version of the roster that invited the member. It names this **stint** of theirs: someone who is
  removed or leaves, then is invited again, starts a new stint with a new `since`.
- **`invited`** members are listed, but get no messages until the owner takes their acceptance in.
- **`card`** appears only in the roster that admits a member (`invited` before, `member` now): it's the card from their
  acceptance. Everyone who takes that roster in can reach them from then on.
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
- **`last`** only appears on a departure: the version of the newest roster the leaver held (0 if none). The departure
  is sent with those rosters, the run the leaver signed themselves at the end of their chain (at most 8). Whoever takes
  over from them builds on these, so rosters the leaver signed just before leaving aren't forked around, even if they
  had reached nobody yet.
- **`card`**, on an acceptance only, is the newcomer's card. The owner puts it in the roster that admits them.

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
- **A departure whose `last` is newer than our roster** only applies once our roster has caught up with it.
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
   - **Rosters with a gap.** One further on is ignored: rosters travel as a chain from the receiver's head, so what's
     in between comes with it, or after (see "What's owed"). Two exceptions are taken past a gap: a new invitation
     (below), and a roster signed by our owner that no longer lists our stint (we were taken out; what happened in
     between isn't ours to know).
4. **Diff the view before and after:**
   - **Members who went:** stop sending to them. A departure shows as "left", a removal as "removed".
     - Their card is kept only until what's already queued to them (the roster that took them out) is delivered. Then
       it is deleted, and so is their session once they're in no other group.
   - **If we were taken out:** mark the group "You were removed" and stop sending.
   - **Once out** (removed, left or declined), or while only invited, a roster that lists us as `invited` with a newer
     `since`, signed by its owner, is a new invitation. Like a first invitation, it's taken on its owner's word, even
     past a gap: what happened while we were out isn't ours to know. That includes one we kept from beyond a gap
     before we learnt we were out. (Not while we're in: then we follow the chain.)
   - **If anyone went:** rotate our group inbox. That means a new mailbox and a new card with a new `hintKey`, sent to
     the remaining members; the old mailbox is deleted after a 15-day drain.

#### Accepting a fact
- **Checks.** A fact must verify under its `id` and be for this group.
- **Which facts are kept.**
  - **Our roster lists the stint:** the fact counts at once. An acceptance's card is taken too.
  - **About a newer stint than our roster reaches:** it's kept until the roster catches up, at most 2 per member.
  - **About a stint that's over:** it's ignored.
  - **Duplicates:** one fact of each kind per stint.
- **An acceptance of a withdrawn invitation,** over 1:1 from its author: the owner answers once per head of its own,
  over 1:1, with its chain from that invitation, which says how it ended.
- **An acceptance that reaches an inviter who has left.** The invitee only knows the inviter. They answer over 1:1,
  at most once an hour, with their chain from the invitation, the facts they hold (which say who owns the group now)
  and the new owner's card if they have it. The invitee then sends their acceptance on to the new owner. If nobody is
  left to own the group, the answer says so. The same goes for an acceptance the inviter took in before leaving: what
  they sent the newcomer since may have been lost.

#### Heads
Every `gtext`, `greceipt`, `gdelete` and `gstate` carries the sender's **head** `h`, inside the E2E payload:
```json
{ "v": 7, "r": "b64u, 16 chars", "d": "b64u, 32 chars", "s": 12 }
```
- `v`: the version of the sender's roster.
- `r`: b64u of the first 12 bytes of that roster's hash.
- `d`: two digests of 12 bytes each, b64u, concatenated (16 characters each):
  - **facts:** SHA-256 of the lines `b64u(SHA-256(factBytes))`, one per fact the sender holds that applies to the roster
    (see "The view") and isn't folded in yet. Lines are sorted (by their UTF-8 bytes) and joined with `\n`, UTF-8, no
    trailing newline (no facts: the empty string). First 12 bytes.
  - **cards:** SHA-256 of the lines `<member id> <seq>`, one per active member of the sender's view (the sender
    included), where `seq` is the card held for them (0 for none). Sorted by id, joined the same way. First 12 bytes.
- `s`: how many times the sender's head has changed. A head with a lower `s` than one already seen from that sender
  (a late copy) doesn't replace it. It isn't part of the comparison.

Comparing our head with theirs: a higher `v` is **ahead**; at the same `v`, a different `r` is a **fork** (the owner
equivocated: nothing to merge); the same `r` and `d` is **equal**; otherwise each may hold facts or cards the other
lacks.

#### State
`gstate` is the only message that carries membership: `{ h, rosters[], facts[], cards[] }`, each list of signed b64u
documents as above. Receiving one is a **merge**, the same whatever order states arrive in, and doing it twice changes
nothing:
- **rosters**, oldest first: each that's next in our chain is taken ("Accepting a roster"), the others ignored;
- **facts:** added to the set ("Accepting a fact");
- **cards:** for anyone in our roster, the highest `seq` wins.

A state for someone at version `n` holds our chain after `n` (at most 50 rosters: the receiver asks on from where it
got to), the facts our roster doesn't show yet, and every card we hold if the card digests differ. It's split into
several `gstate` messages, each at most 40 000 characters of documents, when it's larger. An empty one (just `h`) is
an **ask**: "you're ahead of me".

#### What's owed
What we send follows from our state and the head each peer last showed us, not from what happened. Each time our state
or a head we know changes, for every active member of our view:
- **Who owes whom.** The owner owes every member. A member owes the owner, and anyone whose head they've seen. A new
  owner by succession starts with no heads, so it sends everyone its state once.
- **Equal or forked:** nothing.
- **They're ahead:** an ask, once per head of theirs and version of ours.
- **Otherwise:** our state for their version (or, if they've shown no head yet, from the start of their stint), once
  per pair of their head and ours, and at most 3 to one member per head of ours, whatever heads they show.
- **Through their card** if we have one, else over 1:1. What can't go anywhere yet stays owed, and goes once a route
  appears.
- **Lost messages.** A state that was lost (retention expiry) isn't known to be lost. When a `gtext`, `greceipt`,
  `gdelete` or an ask arrives from them at least an hour after we last sent them anything, and still shows they lack
  something, it's owed again. Sooner than that, it's most likely still on its way: answering it again would have two
  members keep answering each other's states in flight.
- **Rosters that don't connect.** A state whose rosters are all further on than ours, with a gap, comes from someone
  whose chain starts after ours ends (they joined later). So does a message from someone our roster doesn't list,
  whose head is further on. Only an owner of ours can fill the gap, so what we owe it is owed again (at most once an
  hour); if it has left, its answer says who owns the group now.
- **Senders our roster doesn't list.** The first message from someone our roster doesn't list yet (a newcomer, or an
  owner who came after our roster) is read if its hint matches the identity in it (a PreKey message). A state is
  merged, since it checks itself; anything else waits, like an early message, for a roster that lists them. The newest
  8 such senders are remembered, so the rest of a chunked state is read too.

Besides members:
- **Joined, not taken in yet:** we owe the owner our state (our acceptance in it), once per head of ours: through
  their card if we have it, else over 1:1. Once the owner shows a head ahead of ours, we ask instead. Until the owner takes us in we don't
  know who else is in, so we send nothing to the group (the app says it's waiting).
- **Taken out:** a member the owner removes is owed the rosters that say so (from the head they last showed, or their
  stint, the newest 50), over 1:1 or through their old card. If that's lost, they go on writing to the group: the
  owner recognises them by the hint of a blob it can no longer attribute to a member, doesn't read it, and sends the
  rosters again, at most once an hour. Someone who left needs nothing.

**Convergence follows ordinary traffic.** Nothing is sent in the background or on a timer. Members who write to each
other converge: each message shows the other side where its sender is, and at most a few state messages follow. A
group where nobody writes doesn't heal by itself; a lost message is made up for only when someone next writes. A
member more than 150 versions behind gets the rest the next time they write, an hour later or more.

#### Invitees
Invitees are outside delivery: they have no inbox in the group, and nobody but the owner owes them anything.
- **An invitation** is a `gstate` with the roster that invites them, over the owner's 1:1 session.
- **The acceptance** (with the card) and a **decline** go only to the inviter (the owner), over 1:1. Neither is sent
  again if lost (expired, or sent to an owner who has left since, its inbox gone): they wait for the owner like
  anything sent to them. An invitee whose acceptance was lost stays waiting to be let in, until they leave.
- **Being let in.** The owner's next roster admits them and carries their card. Then the owner owes them its state, like
  any member who has shown no head.
- **A withdrawn invitation** goes to them once, over 1:1. If that's lost, they find out when they accept: the owner
  answers (see "Accepting a fact"). If that answer is lost too, they stay waiting to be let in, until they leave.
- **A decline that reaches an inviter who has left** is answered like an acceptance. The invitee then sends it on to
  the owner that answer names, and to every member they can reach (that owner may have left too), once each.
- **A pending member's acceptance** goes with their state: someone who accepted may be the only one to have heard that
  the inviter left, and so who owns the group now.

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
  is read (see "What's owed"): a state is merged, anything else is held for up to 7 days, waiting for a roster that
  adds them. Then it's dropped.
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
| `gtext` | `id`, `body`, `ts`, `exp?`, `once?`, `h` | member | A chat message (long ones go as `chunk` parts) |
| `greceipt` | `ids[]`, `kind` (`read`), `h` | member | Read receipts, batched per author, sent only to the message's author and only if read receipts are on. Groups send no delivery receipts: that would be a push to the author per member per message. An outgoing message shows "read" once every member it went to has read it. |
| `gdelete` | `ids[]`, `h` | author of those messages | Delete for everyone |
| `gstate` | `h`, `rosters[]`, `facts[]`, `cards[]` | anyone | State to merge (see "State"); empty, an ask |

## Flows

### Create
The creator picks a name and some contacts. They create their group inbox and card, and publish roster v1: themselves
as owner, and the contacts as `invited`, all with `since` 1. Each invitee gets the invitation over the existing **1:1
session**. The 1:1 session identifies the creator, so this needs no new trust.

### Add a member (owner only, and only the owner's own contacts)
The owner publishes `ver + 1` with the new member `invited` and `since == ver + 1`, and sends them the invitation over
the 1:1 session. Members learn of the new roster as described in "What's owed".

### Accept or decline
The invitee sees "Alice added you to <name>", with Join or Decline.
- **Join:**
  1. Create the group inbox, prekeys and card.
  2. Send an `accept` fact carrying the card to the owner (see "Invitees").

  The owner takes the acceptance into its next roster, which carries the card, and sends the newcomer its state. A
  group with nobody left to own it can't be joined.
- **Decline:** send a `leave` fact to the owner over 1:1. It still arrives if the chat is deleted right away.

### Leave
1. Send a `leave` fact at once, with the rosters at the end of our chain that we signed ourselves, in one `gstate`: to
   every active member, the owner and our inviter. Receivers stop sending to us as soon as they hold it.
2. Delete the group inbox (no drain needed) and this group's prekeys.

The chat stays, read-only, until the user deletes it.
- **Anyone can leave, the owner too.** An owner first folds the acceptances it holds, so that whoever has joined can
  take over. The next member in the roster becomes the owner, and the UI says who that will be. An owner who wants
  someone else to take over makes them owner first.
- **If the owner's app is gone** (lost phone, wipe), with no departure: the roster can't change any more. Members still
  talk, and accept, decline and leave, since those are facts; nobody can be added or removed. To carry on, a member
  starts a new group with the members who are their contacts. That limitation is stated in the UI.

### Remove, or make someone else the owner (owner only)
Publish a roster, as above. The removed member is sent the rosters that say so (see "What's owed"), so they know.
Making someone else the owner keeps us on as a member.

## Rules and limits

- **Per-member checks:** a `gtext`, `greceipt` or `gdelete` is accepted only from a current member (not `invited`),
  identified by the hint and authenticated by their session (a PreKey message must carry the roster's identity key).
- **Who changes name and timer:** the owner only. The change goes out as a new roster.
- **Group timer:** works like the 1:1 disappearing timer. `exp` on each message is authoritative.
- **Names:** if a member is also your contact (same identity key), you see your own name for them. Otherwise you see
  their self-chosen name, marked as unverified. Safety numbers can be compared per member.
- **Identity changes:** a member's identity key never changes inside a group. A reinstalled member must be removed and
  added again.
- **Hidden chats, the decoy profile and wipes** treat groups like chats. Wiping messages keeps queued state messages
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
