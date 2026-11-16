# Group membership: why it keeps breaking, and what to do instead

Status: option 1 chosen (one owner, no co-admins), and implemented on `group-fuzz-clean`. `docs/groups.md` is the spec; this file keeps the reasoning, and "Option 1 in detail" below checks the hard cases.

## Summary

The group fuzzers (`GroupScenarioFuzzTest#scenario` and `#forks`, plus the seeded `GroupStatefulTest`) keep finding
convergence bugs at a steady rate. Fixing them one at a time has not lowered that rate. The fixes are almost all of one
kind: a member's change was lost when another branch won, and some other member, who has to be present, informed,
reachable and allowed, must notice and apply it again. The last open finding (seed 2549) has nobody who can: the only
member allowed to apply the departure is the member who left, and their inbox is gone.

This is structural. Snapshots are chosen by a fork rule, and lost intent is put back afterwards by side effects. That
doesn't converge by construction, so adding more rules won't settle it.

The recommendation is **one owner who orders the roster, plus self-signed membership facts** (option 1 below). It
removes the bug class instead of patching it, needs no server change, and keeps the current threat model. It drops
co-admins. If co-admins are a must, option 2, a blind sequencer on the server, is the alternative, at the cost of a
new server feature and some linkability.

## The evidence

### Findings per fuzz-hour

Coverage-guided time on the latest code at each point, and the new convergence bugs found in it. Each run was 15
minutes or less and stopped at its first finding.

| Period | Fuzz time | New findings | Rate |
|---|---|---|---|
| `group-fork-fix` (approximate; runs stopped at findings) | ~90 min | ~12 | ~8/h |
| `group-fuzz-clean` (this branch, after its one fix) | ~10.5 min | 1 new, plus the open seed-2549 family again | ~6/h new |

Seeded scenarios point the same way. 1–600 and 1000–2999 were clean on `group-fork-fix`, but the next new range turned
up 2447 and then 2549.

### What the fixes looked like

Of the last ~15 fixes, 13 belong to one family: a change on a branch that lost, and a third party who has to re-apply
it.

- **Departures lost** (seed 1226, seed 2549, "admins remove each other"): an admin must hold the departure and
  publish a removal. That needs an admin who holds the parent roster, or who stores orphans, and who is still present.
- **Acceptances lost** (seed 509, "card after the inviter left", "decline after the inviter left"): an admin must
  re-admit, the member must re-accept and resend their card, and an inviter who has left must pass the answer on.
- **Invitations ambiguous after forks** ("left then invited by a stale branch", "declined then invited by a fork",
  "reinvited past a gap", "invitation lost to the inviter's removal"): a roster that lists you might be a real
  re-invitation, or a fork that never saw you leave. Telling them apart needs history the member may not have, so it
  needs sync requests, rechecks and inviter relays.
- **Rebase side effects** (the per-author sibling cap overflowing, sync-request loops): the cost of re-signing changes
  on every fork.

Every fix added a "who else must act when..." rule. Several of them only work if a member who has left keeps
relaying. The attempted fix for seed 2549 needed five more such rules. It also relied on the simulator keeping a
leaver's inbox, which the app deletes at once (`Groups.afterDeparture`). With the simulator made faithful (this
branch), the fix doesn't hold, and in the real app it can't.

## Root cause

1. **Group state is a chain of whole snapshots, and every change has to be one link.** That includes changes that
   concern only their author: accepting, declining, leaving. Two concurrent links can't both stand, so the fork rule
   picks a branch and throws the other away.
2. **What a discarded link meant isn't part of the state.** The chosen head is a pure function of the rosters held,
   and that part converges. But "Bob left" or "Carol accepted", when it sat on the losing branch, survives only
   through side effects:
   - the author rebases;
   - an admin enforces;
   - an inviter or a leaver relays.
3. **Each side effect needs a particular party to be four things at once:**
   - present (hasn't left, still has an inbox);
   - informed (holds the right history; a gap means a sync request);
   - reachable (has a card or a 1:1 contact on the path);
   - allowed (an admin, for removals and admissions).

   Every finding is a schedule where one of these fails: the leaver is gone, the admin has a gap, the invitee only
   knows the inviter, the only admin is the leaver. The conditions combine with each other (and with Mallory's
   replays), so each new rule opens new combinations.
4. **Convergence can't be tested as a property of a function.** It depends on who sends what to whom after which
   delivery order. Only scenario fuzzing can check it, and it keeps finding new orders.

What this needs is a state that is a **deterministic function of a set of signed facts**, where every fact is final
once any member holds it, plus dissemination that gets the same facts to everyone. Then convergence is "same facts,
same state", which a unit test can check over permutations. Liveness is "facts spread", which is simple gossip.

## Constraints

Any design has to keep these:

- **No accounts.** A member is their identity key.
- **Blind relay.** The server sees mailboxes only. Today members' inboxes may be on different servers. Messages are
  pushed and held only until the push service takes them (TTL up to 14 days). There is no readable log.
- **No server-side ordering of group state**, unless the server can do it blindly and safely.
- **E2E.** The server can't read group state or tell group traffic from 1:1 traffic.
- **Offline members.** Anyone can be offline for days, including admins. A member can disappear for good: the phone is
  lost, or they left and deleted their inbox.
- **Adversaries.** A hostile member replays, forges and forks. A hostile server drops, delays, reorders or splits.
- **Bounded messages.** O(members) per change, no storms.
- **No backwards compatibility needed.** Wire format, DB and spec can all change.

## Options

### 1. One owner orders the roster; members' own changes are signed facts (recommended)

**State.**
- **Only the owner signs rosters.** The roster becomes a linear chain: `ver + 1`, `prev` is the hash of the previous
  roster, owner signature. There are no forks, so no fork rule, no rebasing and no tree.
- **Roles are just owner, member, invited.** Ownership moves only by an explicit transfer roster signed by the owner.
- **Each membership stint has an id:** the hash of the roster that invited the member. Removing someone and inviting
  them again starts a new stint.

**Facts.** A member signs facts about their own membership: `accept(stint, card)`, `decline(stint)`, `leave(stint)`.
Optionally also `rename` and `timer`, if the group lets everyone change those.
- A fact is valid on its own: it's checked against the stint id alone, not against a current roster. It never loses
  anything, and it's final.
- The **effective membership** is the owner's latest roster combined with all valid facts held:
  - a `leave` or `decline` takes the member out of their stint at once;
  - an `accept` makes them active.

  This is a join over a set, so the same chain and the same facts give the same view, in any order.
- The owner folds the facts into the next roster when convenient. That is housekeeping, not correctness: the view is
  already right.

**Dissemination.**
- **Facts.** The author sends a fact to every member they can reach, and always to the owner. Everyone was invited by
  the owner, so everyone is the owner's 1:1 contact: there is always a path.
- **Rosters.** The owner sends each roster to everyone.
- **Catching up.** `gsync` can ask any member. The answer is checked by its hash chain and owner signatures, so
  nobody has to trust whoever sent it.
- **Leaving.** A leaver sends their `leave` fact, then may delete their inbox at once: the fact is final wherever it
  lands, and members pass on facts they hold to whoever asks.

**What it removes.**
- Fork choice, rebasing and the sibling caps.
- `enforceDeparture`, `enforceAcceptance` and `enforceAll`.
- The re-accept and card-resend rule.
- `reinviter` and `recheckInvitation`: a re-invitation is simply a new stint id.
- The orphan heuristics, `askOnce`, and the relays by leavers and inviters.
- Every finding above maps to something that no longer exists, or to "the fact is held, so it applies".

**Threats.**
- **Hostile member.** They can only sign facts about their own stint. Replaying an old fact does nothing (an old stint
  id). Forking is impossible, since they can't sign rosters.
- **Hostile owner.** They can already do anything to membership. One new thing: they could show two different rosters
  at the same version to different members. Members put the hash of the roster they're on in each text (8 bytes is
  enough). A member who sees a different hash at the same version from another member alerts and stops: it's proof
  of equivocation, two owner signatures.
- **Hostile server.** No change: it can drop or delay pushes, as it can today.

**Liveness and UX costs.**
- **No co-admins.** Only the owner adds and removes. A removal takes effect when the owner makes it, at once, since
  it's a roster. Adds wait for the owner, but today only the inviter can add their own contacts anyway.
- **An offline owner** delays only the owner's own changes. Leaves, declines and accepts take effect without the owner.
- **A lost owner** freezes the roster, but members can still leave and accept invitations already sent. That is
  already true today for the last admin (`docs/threat-model.md`, "Residual").
- **The owner leaving** has to transfer ownership first, as the last admin has to promote someone today.

**Messages.**
- A fact: one per member, plus one to the owner.
- A roster: one per member.
- A sync: one request and one answer.
- No rebase rounds.

**Size.**
- `GroupEngine.kt` shrinks from ~1150 lines to roughly 600. Fork choice, enforcement, rebasing, orphans, the
  invitation rechecks and relays go; a fact store, the effective view and the owner's fold come in.
- `proto/Group.kt`: the roster loses admin roles and `RosterRules.beats`; a `gfact` content type comes in.
- DB: a linear history, plus a fact table. No migration.
- UI: "make admin" becomes "transfer ownership".
- Spec: `docs/groups.md`, rules 2–3, Relaying and the flows, roughly 40% of the file, plus the threat model.
- Tests: protocol unit tests rewritten. The scenario fuzzers keep their invariants but swap role changes for
  transfers.
- Roughly 1.5–2.5k lines changed, about 1–2 weeks including fuzzing to clean.

**Possible later extension: moderators.** A moderator signs removal *facts* (`suspend(member, stint)`). These apply to
the effective view at once, so everyone stops sending to that member, and the owner confirms them in the next roster.
A moderator's adds stay proposals until the owner signs them. That keeps the "fact" property, since a removal is
monotone. It is extra scope.

### 2. A blind sequencer: the server orders commits in a group log

**State.**
- A **group log** mailbox on one server (the owner's, named in the roster, and movable).
- Members post commits with **append-if-length-is-n**. The server compares a counter and doesn't need to read
  anything.
- Everyone reads the same sequence and applies each commit against the state the earlier commits produced. Invalid
  commits are skipped, the same way by everyone.
- A losing writer gets a conflict at append time. They fetch the new entries and retry with full knowledge, so
  there's no fork choice at all.
- Multiple admins work naturally. This is MLS's delivery-service model, without MLS's key schedule.

**Encryption.**
- Log entries must be readable by every member and by no one else. That needs a group key per epoch: wrapped
  pairwise in each commit that changes membership, and rotated on removal. This is new crypto.
- The other option is encrypting each entry once per member, which brings the fan-out back and defeats a shared log.

**Threats.**
- **The server can censor or delay.** That is already possible today.
- **The server can split the log**, showing two members different entries at the same index. Each commit carries the
  hash of the previous entry its author applied, and members include the log head in their texts. A split is then
  detected, but it isn't prevented.

**Costs.**
- **New server capability.** A persistent, readable, append-if-length log with retention, quotas, PoW and deletion.
  Today mailboxes are push-only, hold-until-pushed. That is a substantial change to the C# server and to
  `docs/protocol.md`.
- **Weakens a stated design choice.** "The server can't tell group traffic from 1:1, or link the members." A log
  that every member reads links them, by IP and timing, unless reads go over something like Tor.
- **Members offline longer than the log's retention** need checkpoints: periodic snapshot entries signed by an admin.
- **Cross-server members** all depend on the log's server being up.

**Size.** Server: new endpoints and storage, about 1 week. Client: log sync, conflicts, the epoch key and checkpoints,
about 2–3 weeks. Spec and threat model: a new section. Roughly 3–5 weeks.

### 3. Membership as a CRDT over a causal graph of signed operations

**State.**
- Every change (add, remove, leave, accept, role, rename) is a signed op that names the op heads its author had seen.
- The state is a deterministic fold over the ops, in a deterministic topological order. Each op's authority is
  checked against its causal past.
- **Conflicts** are settled by fixed rules:
  - removal wins over anything concurrent by the removed member, which also covers backdated ops by someone already
    removed;
  - concurrent mutual removals are settled by seniority, so the group never ends up with no admin;
  - add and remove of the same member: remove wins.

**Pros.**
- Keeps co-admins and needs no server change.
- Nothing is ever discarded, so there is no "who re-applies it".
- Convergence is "same op set, same state", and it can be property-tested.

**Cons.**
- The semantics are subtle and hard to get right. Matrix's state resolution, the closest deployed design, went
  through several versions and still had "state reset" bugs and attacks.
- The op set grows. It needs compaction once ops are causally stable (every current member has acknowledged them),
  which needs acknowledgements, or signed checkpoints, which bring authority questions back.
- Offline members with long gaps need the whole causal history, or a trusted checkpoint.

**Size.** The largest client change: a new engine and spec. Probably 3–4 weeks, and the highest risk of a long tail
of semantic bugs, which is the problem we're trying to leave.

### Also considered: keep the design, but turn self-changes into facts

Keep multi-admin rosters with fork choice, but move accept, decline and leave out of the chain, into facts as in
option 1. That would remove the departure and acceptance families. But admin-vs-admin forks would stay:
- admins removing each other;
- an invitation lost to the inviter's removal;
- reinvitation on a fork;
- rebase caps.

That is half the work of option 1 without its main benefit. It is a reasonable intermediate step only if co-admins
are a must and the server change in option 2 isn't acceptable.

## Comparison

| | 1. Owner + facts | 2. Blind sequencer | 3. CRDT |
|---|---|---|---|
| Converges by construction | yes (linear chain + set join) | yes (one log) | yes, if the rules are right |
| Co-admins | no (moderators later) | yes | yes |
| Server change | none | new log feature | none |
| Server linkability | as today | worse (shared log) | as today |
| Owner/admin offline | own changes wait; self-changes don't | nothing waits | nothing waits |
| Lost owner | roster frozen (as today) | admins carry on | admins carry on |
| Messages per change | O(members) | O(1) write + reads | O(members) + sync |
| New crypto | none | epoch group key | none |
| Rough size | 1–2 weeks | 3–5 weeks | 3–4 weeks |
| Risk of a new bug tail | low | medium (server and keys) | high |

## Recommendation

Go with **option 1**. It removes the bug class the fuzzers keep finding instead of patching it, keeps the blind,
unlinkable server, adds no crypto, and is the smallest change. What it gives up:
- co-admins, which could come back later as moderators with removal facts;
- membership changes while the owner is offline, apart from members' own changes, which still work.

The owner-loss limitation exists today already.

If co-admins working while the owner is away is a hard requirement, choose option 2. It also needs a decision on the
linkability trade-off.

Either way, keep the scenario fuzzers and their invariants. They're design-independent. They should become the
acceptance test for the redesign: seeds 1–5000 clean, and 30 minutes or more of clean coverage-guided fuzzing per
target.

## Option 1 in detail: the hard cases

The design as built. `docs/groups.md` has the exact rules.

**Building blocks.**
- **The roster** is a linear chain signed by its owner. Each entry is `{id, role, since}`:
  - `role` is `owner`, `member` or `invited`;
  - `since` is the version of the roster that invited them, and names their **stint**.
- **A fact** is a member's signed statement about their own stint: `accept` or `leave` (a decline is an invitee's
  `leave`). It names the stint by `since`.
- **The view** is what everyone acts on: the head roster with the facts held for its stints applied. A `leave` takes
  that stint out, and an `accept` makes that invitee a member.
- **The effective owner** is the roster's owner, unless a held `leave` ended the owner's stint. Then it's the first
  `member` in roster order whose stint hasn't ended, and if there is none, nobody.
- **Who may sign the next roster.** Only the effective owner of the parent. A successor's roster carries the `leave`
  facts that make them the successor, so anyone can check it without other state.

**The owner leaves.** Leaving is the same for everyone: a `leave` fact. Ownership passes to the next member in roster
order, and that member signs a roster folding the departures, with the facts as proof.
- **Choosing the heir.** An owner who wants a particular heir makes them owner first ("Make owner" signs a roster
  transferring ownership). The UI says who will take over.
- **A departure can't strand the group.** While any member is left, someone is next. If the heir also left, possibly
  at the same moment, their `leave` passes it on again.
- **Signing is never ambiguous.** Only facts from the people ahead in line make you heir, and a member who hasn't left
  can't have a `leave` fact. So two honest members never both think they're the owner.
- **A former owner's `leave` carries the last roster they signed.** Nobody takes over from a stale roster, so a
  transfer just before leaving can't fork.
- **Nobody left to own it.** If the only ones left are invitees, the group can't change any more. Those already in it
  can still talk and leave.

**The owner is gone for good** (lost phone, duress wipe, uninstall), without a `leave`.
- **What freezes.** The roster: no adds, removals, renames or timer changes.
- **What keeps working.** Members chat as before (sessions and cards are pairwise and member-signed). Accepts,
  declines and leaves are facts, so they still take effect, and members still rotate inboxes when someone leaves.
- **Recovery.** A member starts a new group with the members who are their contacts. Inviting non-contacts through the
  old group isn't built.
- This limitation existed before for "the last admin" (`docs/threat-model.md`, Residual). A time-based takeover was
  rejected: it would fork whenever the owner came back.

**Concurrency.**
- **Facts vs. the owner's changes.** A fact applies only to the stint it names (`since`).
  - **Leave vs. removal:** both end the stint, so they agree.
  - **Accept vs. withdrawal:** once the roster no longer lists that stint, the accept is void. Members who acted on
    it briefly stop when the roster reaches them, as today.
- **Re-invitation** starts a new stint, with a new `since`. Facts about older stints, replayed or late, are ignored,
  and a member who is out knows a re-invitation by its newer `since`, with no history lookups.
- **Folding.** The owner folds the facts it holds into every roster it signs, so a re-invitation can't resurrect a
  stint that already ended.

**A malicious member.**
- **Forging.** They can sign facts only about their own stints; anything else fails the signature check.
- **Replaying.** A replay names an old stint and is ignored.
- **Flooding.** At most one `accept` and one `leave` are kept per stint, and at most 2 facts per author for stints we
  don't know yet. Each is one signature check.
- **Rosters.** They can't sign one unless they are the effective owner. A takeover needs the `leave` facts of
  everyone ahead, signed by those members.

**A malicious server** can drop, delay, reorder or replay.
- **Replays and reordering.** Facts are idempotent. Rosters are chained by `prev` and version, so an older one is
  ignored, and a newer one with a gap triggers a sync from the owner or any member, checked by chain and signatures.
- **Dropping** can only delay. Anything dropped for good partitions, as it would today.

**A malicious owner** is within the trust model. They decide membership, as admins did. The one new power is
equivocation: two different rosters at one version. Members can detect it but not prevent it, and
`docs/threat-model.md` says so.

**Offline members.**
- **Short gaps.** Pushes are held for up to 14 days.
- **Longer gaps.** A member back after a long gap gets a newer roster with a gap, and asks the owner, or any member,
  for the chain since their version. The answer is at most 50 rosters, plus the unfolded facts, and they ask again if
  more is missing.
- **Messages per change:**
  - a roster: one push per member;
  - a fact: one push per member it reaches, plus the owner;
  - a succession: the heir's one roster, plus at most one forward of the deciding facts per member.

## Results under the owner design (rounds since cb881ed)

The rounds are on this branch. Each round ran seeds 1–600 and 1000–4999, then up to 15 minutes per fuzz target,
stopping at the first finding. Times are time to first finding.

| Round | Seeds | `scenario` | `forks` |
|---|---|---|---|
| 1 | 233, 1108 | 27 s | 51 s |
| 2 | 1236 | 42 s | 46 s |
| 3 | 1367 | 76 s | 54 s |
| 4 | clean | 81 s | 335 s |
| 5 | clean | 295 s | 196 s |
| 6 | clean | 677 s (oracle) | 573 s |
| 7 | 3839 (oracle) | 126 s | 366 s |
| 8 | clean | 247 s | 609 s |
| 9 | clean | 15 min clean | 721 s (open, not fixed) |

That is about 90 minutes of fuzzing and 23 findings. About 15 of them were protocol bugs, and since round 4 the rate has
been flat at roughly 5 to 10 an hour.

**The membership semantics held.** After round 3, no finding was about the view or the chain. The roster stays linear,
facts can't be lost or replayed, and succession never forked between honest members. The equivocation and
ownerless cases are limits of the design, now stated in the spec.

**What remains is delivery.**
- **Who can reach whom.** Members reach each other through 1:1 contacts, through cards, or through relays by others.
  Invitees have no inbox. After an ownership change or a new stint, someone can be left without a route.
- **Catch-up.** Catching up after a gap means rebuilding the chain from whoever answers.
- **Each fix was a relay rule:**
  - forward facts to the owner, and again to a new owner;
  - a leaver passes facts on;
  - keep facts that arrive early;
  - answer a stale acceptance;
  - reach invitees over 1:1 first;
  - keep a roster seen past a gap, and look at it again;
  - don't count a sync ask that couldn't go out.

  That is structural in the transport and catch-up layer, though not in the membership rules.

**Proposed next step (not implemented): owner snapshots.**
- **Catch-up.** Members stop rebuilding history. Anyone behind or unsure asks the owner, and gets back one snapshot:
  - the current roster;
  - the rosters where ownership changed since the asker's version (usually none or one), so it can be checked from
    the owner the asker knew;
  - every member's current card.
- **Cards in the roster.** Each roster entry records the member's card `seq` and hash. A stale card can then be seen
  by comparing against the roster, and is fetched from the owner; the peer-to-peer card hand-offs go away.
- **When members ask.** On a gap, on joining, on an owner change, and once a day if their version is behind what
  they've seen.
- **A simpler oracle.** After quiescence plus one snapshot round, all honest views and card sets are equal.

