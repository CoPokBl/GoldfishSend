package app.goldfishsend.fuzz

import app.goldfishsend.GroupNet
import app.goldfishsend.Peer
import app.goldfishsend.cardState
import app.goldfishsend.factState
import app.goldfishsend.rosterState
import app.goldfishsend.core.ReceiveGuard
import app.goldfishsend.group.GroupEngine
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Fact
import app.goldfishsend.proto.FactKind
import app.goldfishsend.proto.Chunker
import app.goldfishsend.proto.Content
import app.goldfishsend.proto.GroupBlob
import app.goldfishsend.proto.GroupCrypto
import app.goldfishsend.proto.Padding
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.Roster
import app.goldfishsend.proto.RosterMember
import app.goldfishsend.proto.RosterOp
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.proto.SignedRoster
import app.goldfishsend.proto.View

/**
 * One step of a group scenario. Its numbers are read against the state at that point (see [GroupScenario.apply]): a step
 * that doesn't apply does nothing, so every list is a valid scenario, and lists shrink by deleting steps.
 */
data class Op(val kind: Int, val a: Int = 0, val b: Int = 0, val c: Int = 0) {
    override fun toString() = "Op($kind, $a, $b, $c)"
}

class Failure(val message: String, val cause: Throwable? = null) {
    /** What kind of failure, for shrinking: the same check failing, not just any. */
    val signature: String = message.substringBefore(':')

    override fun toString() = message + (cause?.let { "\n" + it.stackTraceToString().lines().take(12).joinToString("\n") } ?: "")
}

/**
 * Alice creates a group and invites Bob and Mallory; Carol and Dave can be added. Mallory is a member who also misbehaves:
 * she replays and forges rosters, facts and cards, claims to be others, sends junk chunks, and lends a stranger (Sam)
 * cards. Pushes are delivered in random order, duplicated, or held back and delivered later. After the steps, everything
 * still queued is delivered, then the invariants are checked: honest members agree, nobody did what only the owner may,
 * nothing honest was lost, and those who are out can't read or post.
 */
class GroupScenario(private val seed: Long) {
    private val net = GroupNet()
    private val names = listOf("alice", "bob", "carol", "dave", "mallory")
    private val peers = names.mapIndexed { i, n -> net.peer(n, FuzzKit.identity(seed * 31 + i)) }
    private val alice = peers[0]
    private val mallory = peers[4]
    private val honest = peers.take(4)
    private val sam = Peer("sam", net, FuzzKit.identity(seed * 31 + 9))
    private val gid = B64.enc(java.util.Random(seed).let { r -> ByteArray(32).also { r.nextBytes(it) } })
    private var now = 1_700_000_000_000L
    private val limbo = mutableListOf<GroupNet.Envelope>()

    /** Who lost messages sent to them, and who lost messages they sent, when the held-back ones were lost. */
    private val lostTo = mutableSetOf<String>()
    private val lostFrom = mutableSetOf<String>()

    // What honest actions and Mallory's own did, for the invariants.
    private val added = mutableSetOf<String>()

    /** The newest roster Mallory claimed to hold when she sent a departure of hers (her client carried on regardless). */
    private var malloryLeftAt: Long? = null
    private val churned = mutableSetOf<String>()
    private val joined = mutableSetOf<String>()

    private class Said(val from: Peer, val body: String, val to: List<String>, val last: Boolean = false)

    private val said = mutableListOf<Said>()
    private var msg = 0
    private val drops = mutableListOf<String>()

    init {
        net.clock = { now }
        if (debug) {
            net.trace = { println(it) }
        }
        for (p in peers.drop(1)) {
            alice.befriend(p)
        }
        bob().befriend(peers[2])
        peers[3].befriend(mallory)
    }

    private fun bob() = peers[1]

    private fun GroupNet.Envelope.sender(): Peer = when (this) {
        is GroupNet.Envelope.ToInbox -> from
        is GroupNet.Envelope.Direct -> from
    }

    private fun log(s: String) {
        if (debug) {
            println(s)
        }
    }

    /**
     * Runs the scenario. Null if every check passed. After the steps the adversary stops, and whatever is still held back
     * is lost (retention expiry); the network is fair from then on. Everything queued is delivered, each honest active
     * member sends one ordinary message, and everything is delivered again. Then the checks run.
     */
    fun run(ops: List<Op>): Failure? {
        ReceiveGuard.onDrop = { where, e -> drops += "$where: ${e.javaClass.simpleName}" }
        log((peers + sam).joinToString { "${it.name}=${it.id.takeLast(6)}" })
        try {
            alice.create(gid, "Trip", bob(), mallory)
            added += listOf(bob().id, mallory.id)
            for ((i, op) in ops.withIndex()) {
                now += 1000
                try {
                    apply(op)
                } catch (e: Throwable) {
                    return Failure("exception: step $i $op: ${e.javaClass.simpleName}: ${e.message}", e)
                }
                rolledBack()?.let { return it }
            }
            log("--- the adversary stops; held-back messages are lost")
            for (e in limbo) {
                when (e) {
                    is GroupNet.Envelope.ToInbox -> e.from.id to e.to.id
                    is GroupNet.Envelope.Direct -> e.from.id to e.to.id
                }.let { (a, b) ->
                    lostFrom += a
                    lostTo += b
                }
            }
            limbo.clear()
            net.counting = true
            // Mallory's messages already on their way are the attack's, not her engine's answers.
            net.queue.filter { it.sender() == mallory }.forEach { net.uncounted += it }
            try {
                now += GroupEngine.RESEND_AFTER
                quiesce()
                log("--- whoever is still waiting to be let in sends their acceptance again")
                for (p in honest) {
                    sendAgain(p)
                }
                quiesce()
                now += GroupEngine.RESEND_AFTER
                log("--- one message from each honest active member")
                for (p in honest) {
                    val m = joinedModel(p) ?: continue
                    if (m.view()?.isActive(p.id) == true) {
                        val body = "m${msg++} ${p.name}"
                        log("${p.name} says $body")
                        said += Said(p, body, p.say(gid, body, "w$msg"), last = true)
                    }
                }
                quiesce()
            } catch (e: Throwable) {
                return Failure("exception: delivering the rest: ${e.javaClass.simpleName}: ${e.message}", e)
            }
            rolledBack()?.let { return it }
            for (p in peers) {
                model(p)?.let { m -> log("${p.name}: state ${m.state}, ${m.view()?.let(::describe)}, cards ${m.cards.keys.map(::who)}") }
            }
            return drops.takeIf { it.isNotEmpty() }?.let { Failure("dropped: $it") } ?: check() ?: afterwards()
                ?: drops.takeIf { it.isNotEmpty() }?.let { Failure("dropped: $it") }
        } finally {
            ReceiveGuard.onDrop = null
        }
    }

    /** Delivers what the engines sent (nothing else is reset or retried) until nothing is left. */
    private fun quiesce() {
        net.deliverAll()
        if (net.queue.isNotEmpty()) {
            error("never quiet")
        }
    }

    /** Versions never go backwards, for any honest member. */
    private val highest = HashMap<String, Long>()

    private fun rolledBack(): Failure? {
        for (p in honest) {
            val v = model(p)?.roster?.roster?.ver ?: continue
            val was = highest[p.id] ?: 0
            if (v < was) {
                return Failure("rollback: ${p.name} went from v$was to v$v")
            }
            highest[p.id] = v
        }
        return null
    }

    private fun peer(i: Int) = peers[Math.floorMod(i, peers.size)]

    private fun model(p: Peer): GroupModel? = p.store.load(gid)

    private fun joinedModel(p: Peer): GroupModel? = model(p)?.takeIf { it.state == GroupModel.JOINED }

    fun apply(op: Op) {
        when (Math.floorMod(op.kind, 13)) {
            0 -> {
                val p = peer(op.a)
                val m = model(p) ?: return
                // Nobody can admit us while the group has no owner (everyone who could own it left).
                if (m.state == GroupModel.INVITED && m.roster?.roster?.role(p.id) == Role.INVITED && m.view()?.owner != null) {
                    log("${p.name} joins")
                    p.join(gid)
                    joined += p.id
                } else {
                    sendAgain(p)
                }
            }
            1 -> {
                val p = peer(op.a)
                val m = model(p) ?: return
                if (m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) {
                    return
                }
                if (p.engine.leave(m)) {
                    log("${p.name} leaves")
                    churned += p.id
                }
            }
            2 -> admin(op) { a, t ->
                if (t.id in a.contacts && a.publish(gid, RosterOp.Add(listOf(t.id))) != null) {
                    log("${a.name} adds ${t.name}")
                    added += t.id
                }
            }
            3 -> admin(op) { a, t ->
                if (a.publish(gid, RosterOp.Remove(listOf(t.id))) != null) {
                    log("${a.name} removes ${t.name}")
                    churned += t.id
                }
            }
            4 -> admin(op) { a, t ->
                if (op.c % 2 != 0 || t == mallory) {
                    return@admin
                }
                if (a.publish(gid, RosterOp.MakeOwner(t.id)) != null) {
                    log("${a.name} makes ${t.name} the owner")
                }
            }
            5 -> {
                val p = peer(op.a)
                joinedModel(p) ?: return
                val change = when (Math.floorMod(op.b, 3)) {
                    1 -> RosterOp.Meta(timer = listOf(0L, 30L, 3600L, 86400L)[Math.floorMod(op.c, 4)])
                    else -> RosterOp.Meta(name = "Trip ${Math.floorMod(op.c, 100)}")
                }
                if (p.publish(gid, change) != null) {
                    log("${p.name} sets $change")
                }
            }
            6 -> {
                val p = peer(op.a)
                val m = joinedModel(p) ?: return
                val prev = m.myCard ?: return
                log("${p.name} rotates")
                p.engine.updateCard(m, p.card(gid, prev.card.seq + 1, prev.card.bundle))
            }
            7 -> {
                val p = peer(op.a)
                joinedModel(p) ?: return
                val body = "m${msg++} ${p.name}"
                log("${p.name} says $body")
                said += Said(p, body, p.say(gid, body, "w$msg"))
            }
            8 -> deliverSome(1 + Math.floorMod(op.a, 8), op.b.toLong(), Math.floorMod(op.c, 40))
            9 -> {
                net.queue.addAll(limbo)
                limbo.clear()
            }
            10 -> hostile(op)
            12 -> forkAttack(op)
            else -> net.deliverAll()
        }
        for (p in peers) {
            p.runDeferred()
        }
    }

    /** Still waiting to be let in, [p]'s user waits until "Send again" is allowed, and taps it. */
    private fun sendAgain(p: Peer) {
        val m = model(p) ?: return
        val at = GroupEngine.sendAgainAt(m, p.id) ?: return
        now = maxOf(now, at)
        val queued = net.queue.size
        if (p.engine.sendAgain(m)) {
            log("${p.name} sends their acceptance again")
            // The user's, not an answer of the engine's: a copy that changes nothing isn't ping-pong (what it's answered with
            // still counts).
            net.queue.drop(queued).forEach { net.uncounted += it }
        }
    }

    private fun admin(op: Op, block: (Peer, Peer) -> Unit) {
        val a = peer(op.a)
        val t = peer(op.b)
        val m = joinedModel(a) ?: return
        if (a == t || m.view()?.isOwner(a.id) != true) {
            return
        }
        block(a, t)
    }

    /** Pushes in random order; some are held back (delivered later) or delivered twice. */
    private fun deliverSome(n: Int, rngSeed: Long, holdPercent: Int) {
        val rnd = java.util.Random(rngSeed)
        repeat(n) {
            if (net.queue.isEmpty()) {
                return
            }
            val e = net.queue.removeAt(rnd.nextInt(net.queue.size))
            val roll = rnd.nextInt(100)
            when {
                roll < holdPercent -> limbo += e
                else -> {
                    // A push can arrive twice (protocol.md: at-least-once). The 1:1 channel isn't modelled with crypto, so
                    // only group blobs, which libsignal deduplicates, are repeated.
                    if (roll < holdPercent + 8 && e is GroupNet.Envelope.ToInbox) {
                        net.queue.addLast(e)
                    }
                    net.deliver(e)
                }
            }
        }
    }

    // ---------- Mallory ----------

    /** Mallory keeps trying after she's out: her sessions and the old inboxes still work for a while. */
    private fun hostile(op: Op) {
        val m = model(mallory) ?: return
        val cur = m.roster ?: return
        val target = honest[Math.floorMod(op.b, honest.size)]
        when (Math.floorMod(op.a, 8)) {
            0 -> {
                val history = mallory.store.historySince(gid, 0)
                val facts = heard.toList()
                if (op.c % 2 == 1 && facts.isNotEmpty()) {
                    val f = facts[Math.floorMod(op.c / 2, facts.size)]
                    log("mallory replays ${who(f.fact.id)}'s ${f.fact.kind} (${f.fact.since}) to ${target.name}")
                    toTarget(target, factState(f))
                } else if (history.isNotEmpty()) {
                    val r = history[Math.floorMod(op.c, history.size)]
                    log("mallory replays v${r.roster.ver} by ${who(r.roster.by)} to ${target.name}")
                    toTarget(target, rosterState(r))
                }
            }
            1 -> forgeRoster(cur, target, op.c)
            2 -> {
                // Someone else's card pointing at Mallory's inbox, signed by Mallory.
                val card = mallory.store.routes[gid]?.get(target.id)?.card ?: return
                val forged = card.copy(inbox = m.myCard?.card?.inbox ?: return, seq = card.seq + 1)
                log("mallory forges ${target.name}'s card")
                toTarget(peer(op.c), cardState(GroupCrypto.signCard(mallory.identity.privateKey, forged)))
            }
            3 -> {
                // Mallory's session, but the hint names someone else.
                val claimed = peer(op.c)
                val card = mallory.store.routes[gid]?.get(target.id)?.card ?: return
                val content = Content.GText(gid, "f$msg", "forged ${msg++} as ${claimed.name}", now)
                val blob = GroupBlob.decode(mallory.engine.encryptTo(target.id, card, content.encode()))!!
                val mac = GroupCrypto.hint(B64.dec(card.hintKey), blob.nonce, claimed.identity.publicKey.serialize())
                log("mallory sends as ${claimed.name} to ${target.name}")
                net.queue.addLast(GroupNet.Envelope.ToInbox(target, card.inbox.sendSecret, GroupBlob(blob.type, blob.nonce, mac, blob.body).encode(), mallory))
            }
            4 -> {
                // Sam isn't in the group; Mallory gave him a member's card.
                val card = mallory.store.routes[gid]?.get(target.id)?.card ?: return
                log("sam writes to ${target.name}")
                sam.sendWithCard(card, Content.GText(gid, "s$msg", "stranger ${msg++}", now))
            }
            5 -> {
                val big = Content.GText(gid, "c$msg", "chunky ${msg++} " + "x".repeat(3000), now)
                val parts = Chunker.splitContent(big, Padding.MAX_PREKEY_PLAINTEXT).map { it as Content.Chunk }
                val rnd = java.util.Random(op.c.toLong())
                log("mallory sends junk chunks to ${target.name}")
                repeat(1 + rnd.nextInt(6)) {
                    val p = parts[rnd.nextInt(parts.size)]
                    val junk = when (rnd.nextInt(4)) {
                        0 -> p.copy(parts = rnd.nextInt(200) - 50)
                        1 -> p.copy(part = rnd.nextInt(70) - 2)
                        2 -> p.copy(data = "!!" + p.data.drop(2))
                        else -> p
                    }
                    toTarget(target, junk)
                }
            }
            6 -> {
                // A head she made up: whoever sees it thinks they differ from her.
                log("mallory shows ${target.name} a made-up head")
                toTarget(target, Content.GState(gid, app.goldfishsend.proto.Head(op.c.toLong() % 20, B64.enc(ByteArray(12) { op.c.toByte() }), "x$msg")))
            }
            else -> {
                // A card of Mallory's own with an old sequence number.
                log("mallory sends a stale card of hers to ${target.name}")
                toTarget(target, cardState(mallory.card(gid, 1, m.myCard?.card?.bundle)))
            }
        }
    }

    private fun forgeRoster(cur: SignedRoster, target: Peer, c: Int) {
        val base = cur.roster
        val change: Roster = when (Math.floorMod(c, 5)) {
            0 -> base.copy(members = base.members.filter { it.id != target.id })
            1 -> base.copy(members = base.members + RosterMember(sam.id, Role.MEMBER, base.ver + 1))
            2 -> base.copy(members = base.members.map { if (it.id == mallory.id) it.copy(role = Role.OWNER) else it })
            3 -> base.copy(members = base.members.map { if (it.role == Role.OWNER) it.copy(role = Role.MEMBER) else it } +
                listOf(RosterMember(mallory.id, Role.OWNER, base.ver + 1)).filter { base.role(mallory.id) == null })
            else -> base.copy(name = "Owned")
        }
        // Her own departure as "proof" that she's the successor: it isn't (it doesn't end anyone else's stint).
        val proof = listOfNotNull(myLeave(base)?.wire())
        val stamped = when (Math.floorMod(c / 5, 5)) {
            0 -> RosterRules.successor(cur, change, mallory.id, now / 1000, emptyList())
            1 -> change.copy(by = mallory.id, ts = now / 1000)
            2 -> RosterRules.successor(cur, change, mallory.id, now / 1000, emptyList()).copy(ver = base.ver + 3)
            3 -> RosterRules.successor(cur, change, mallory.id, now / 1000, proof)
            else -> RosterRules.successor(cur, change, alice.id, now / 1000, emptyList())
        }
        log("mallory forges v${stamped.ver} (${Math.floorMod(c, 5)}) to ${target.name}")
        toTarget(target, rosterState(GroupCrypto.signRoster(mallory.identity.privateKey, stamped)))
    }

    /**
     * Mallory goes back to a roster some versions old and, from there, either signs a change of her own on it as if she
     * were its owner (a fork she'd like to win), or her departure from the stint it lists, carrying that old roster as
     * the newest she knows (a successor taking over from it would fork). Either goes to everyone.
     */
    private fun forkAttack(op: Op) {
        model(mallory) ?: return
        var at = mallory.store.load(gid)?.roster ?: return
        repeat(1 + Math.floorMod(op.a, 4)) {
            at = mallory.store.history(gid, at.roster.prev)?.takeIf { it.roster.ver == at.roster.ver - 1 } ?: return@repeat
        }
        val base = at.roster
        val mine = base.member(mallory.id) ?: return
        val content: Content = if (op.c % 3 == 0) {
            val f = GroupCrypto.signFact(
                mallory.identity.privateKey,
                Fact(g = gid, kind = FactKind.LEAVE, id = mallory.id, since = mine.since, ts = now / 1000 + Math.floorMod(op.b, 8), last = base.ver),
            )
            if (model(mallory)?.roster?.roster?.member(mallory.id)?.since == mine.since) {
                churned += mallory.id
            }
            malloryLeftAt = minOf(malloryLeftAt ?: base.ver, base.ver)
            log("mallory leaves from v${base.ver} (stint ${mine.since})")
            factState(f)
        } else {
            val change = base.copy(name = "Fork ${msg++}")
            log("mallory forks at v${base.ver}")
            rosterState(GroupCrypto.signRoster(mallory.identity.privateKey, RosterRules.successor(at, change, mallory.id, now / 1000, emptyList())))
        }
        for (t in honest) {
            toTarget(t, content)
        }
    }

    /** A departure of Mallory's from her stint in [r], if she has one there. */
    private fun myLeave(r: Roster) = r.member(mallory.id)?.let {
        GroupCrypto.signFact(mallory.identity.privateKey, Fact(g = gid, kind = FactKind.LEAVE, id = mallory.id, since = it.since, ts = now / 1000))
    }

    /** Facts Mallory has seen (she's a member: they reach her), for replaying. */
    private val heard: List<app.goldfishsend.proto.SignedFact>
        get() = honest.flatMap { p -> model(p)?.facts.orEmpty() }.distinctBy { it.key }

    private fun toTarget(target: Peer, content: Content) {
        val card = mallory.store.routes[gid]?.get(target.id)?.card
        if (card != null && target != mallory) {
            mallory.sendWithCard(card, content)
        } else if (target.id in mallory.contacts) {
            net.queue.addLast(GroupNet.Envelope.Direct(target, mallory, content))
        }
    }

    private fun who(id: String) = (peers + sam).firstOrNull { it.id == id }?.name ?: "?"

    // ---------- invariants ----------

    private fun check(): Failure? {
        safety()?.let { return it }
        if (equivocated()) {
            // Mallory became the owner (next in line once others left) and equivocated, which members can't prevent
            // (docs/threat-model.md): only safety holds then.
            return null
        }
        // The honest active members: admitted (their roster says so), and not gone in their own view. Someone whose
        // acceptance the owner hasn't taken in yet is still outside delivery.
        val h = honest.filter { p -> joinedModel(p)?.let { it.roster!!.roster.role(p.id) != Role.INVITED && it.view()?.isActive(p.id) == true } == true }
        if (h.isEmpty()) {
            return null
        }
        val views = h.map { it.view(gid) }
        // The newest roster any honest peer holds (chains don't fork, so it's the truth so far), and its holder's view.
        val newest = honest.mapNotNull { p -> model(p)?.takeIf { it.roster != null } }.maxByOrNull { it.roster!!.roster.ver }?.view()
        if (views.all { it.owner == null } || newest?.owner == null) {
            // Nobody left to manage it, for everyone (or as of the newest roster: the owner who signed it left, and only
            // they could have told the rest): nobody can join or change anything any more, and who's still listed isn't
            // kept in step. Only safety holds then.
            return null
        }
        val parts = components(h)
        if (parts.size > 1) {
            return Failure("disconnected: ${parts.map { c -> c.map { it.name } }}")
        }
        val state = h.map { p -> p.roster(gid).hashB64 + " " + unfolded(p) + " " + describe(p.view(gid)) }
        if (state.toSet().size != 1) {
            return Failure("diverged: ${h.map { p -> "${p.name} ${describe(p.view(gid))} facts ${unfolded(p).size}" }}")
        }
        for (p in h) {
            for (q in h) {
                val want = model(q)?.myCard?.card?.seq
                val got = model(p)!!.cards[q.id]?.card?.seq
                if (q != p && got != want) {
                    return Failure("cards: ${p.name} has ${q.name}'s card $got, latest is $want")
                }
            }
        }
        net.states.entries.firstOrNull { it.value > MAX_STATE_EXCHANGES }?.let { (k, n) ->
            return Failure("ping-pong: $n state messages that changed nothing, from ${k.first.substringBefore(' ')} to ${k.second.substringBefore(' ')}, neither's head changing")
        }
        return members(views.first(), h)
    }

    /** The facts [p] holds that its roster doesn't show yet. */
    private fun unfolded(p: Peer): Set<String> {
        val m = model(p)!!
        return m.facts.filter { app.goldfishsend.proto.Membership.applies(m.roster!!.roster, it.fact) }.map { it.key }.toSet()
    }

    /** [p] can send to [q]: a card of [q]'s whose inbox still exists, or a 1:1 contact. */
    private fun route(p: Peer, q: Peer): Boolean {
        val card = model(p)?.cards?.get(q.id)?.card
        return (card != null && q.inboxes[gid]?.containsKey(card.inbox.sendSecret) == true) || q.id in p.contacts
    }

    /** The parts of [h] connected by routes both ways. */
    private fun components(h: List<Peer>): List<List<Peer>> {
        val left = h.toMutableList()
        val out = mutableListOf<List<Peer>>()
        while (left.isNotEmpty()) {
            val part = mutableListOf(left.removeAt(0))
            var i = 0
            while (i < part.size) {
                val p = part[i++]
                val next = left.filter { q -> route(p, q) && route(q, p) }
                part += next
                left.removeAll(next)
            }
            out += part
        }
        return out
    }

    /** The owner of [r] is Mallory or nobody, or has no route to [p]. */
    private fun ownerCantReach(p: Peer, r: View): Boolean {
        val o = honest.firstOrNull { it.id == r.owner } ?: return true
        return !route(o, p)
    }

    /** Waiting to be let in, [p] can send to whoever owns the group as far as they know ([GroupEngine.sendAgain]). */
    private fun reachesOwner(p: Peer, m: GroupModel): Boolean {
        val o = honest.firstOrNull { it.id == m.view()?.owner } ?: return false
        return route(p, o)
    }

    /** [p] joined, but their roster still lists them invited: their acceptance hasn't been taken in. */
    private fun pending(p: Peer, m: GroupModel): Boolean = m.state == GroupModel.JOINED && m.roster?.roster?.role(p.id) == Role.INVITED

    /** [p] is out of [r] or invited, and nobody honest still in it can reach them. */
    private fun unreachable(p: Peer, h: List<Peer>): Boolean = h.none { q -> q != p && route(q, p) }

    /**
     * Mallory, the owner at some point (next in line once others left), equivocated: two rosters of hers at one version,
     * or rosters signed after a departure of hers.
     */
    private fun equivocated(): Boolean {
        val hers = honest.flatMap { p -> p.store.historySince(gid, 0).filter { it.roster.by == mallory.id } }.distinctBy { it.hashB64 }
        if (hers.groupBy { it.roster.ver }.any { it.value.size > 1 }) {
            return true
        }
        val at = malloryLeftAt ?: return false
        return hers.any { it.roster.ver > at }
    }

    /** Everyone's state against the agreed view [r]; [h] are the honest active members. */
    private fun members(r: View, h: List<Peer>): Failure? {
        for (p in honest) {
            val m = model(p)
            val role = r.role(p.id)
            // Invitees are out of delivery: the owner and they exchange invitations, acceptances, declines and withdrawals
            // once, over 1:1 (or the card an acceptance brings). If one of those was lost (held back, or sent to an inbox
            // that was gone: an owner who has left since), or the owner has no route to
            // them, they may not agree: they find out when they act (the owner answers an acceptance), or stay waiting.
            val inviteeCut = p.id in lostTo || p.id in lostFrom || net.deadLetters.any { it.first == p.id } || ownerCantReach(p, r)
            // Joined and still waiting to be let in, after sending their acceptance again once the network was fair: what
            // was lost before doesn't excuse it any more, only having no way to the owner, or the owner none back.
            val waiting = m != null && pending(p, m)
            val waitingCut = m != null && (ownerCantReach(p, r) || unreachable(p, h) || !reachesOwner(p, m))
            val ok = when {
                // They know they're out, from a newer roster than the agreed one: what's agreed is behind.
                m != null && m.state == GroupModel.REMOVED && (m.roster?.roster?.ver ?: 0) > r.roster.ver -> true
                m == null -> role == null || (role == Role.INVITED && inviteeCut) || unreachable(p, h)
                // Someone who left knows they're out, whether or not their departure reached anyone (it can be lost).
                role == Role.OWNER || role == Role.MEMBER -> (m.state == GroupModel.JOINED && (!waiting || waitingCut)) || m.state == GroupModel.LEFT
                role == Role.INVITED && waiting -> waitingCut
                role == Role.INVITED -> m.state == GroupModel.INVITED || inviteeCut || unreachable(p, h)
                // Out: they know it, or nobody still in can reach them.
                else -> m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED || ((m.state == GroupModel.INVITED || pending(p, m)) && inviteeCut) ||
                    unreachable(p, h)
            }
            if (!ok) {
                return Failure("state: ${p.name} is ${m?.state} but $role in ${describe(r)}")
            }
        }
        for (p in honest) {
            if (p.id in joined && p.id !in churned && !r.isActive(p.id) && model(p)?.let { pending(p, it) } != true) {
                return Failure("lost member: ${p.name} joined and never left, but is ${r.role(p.id)} in ${describe(r)}")
            }
            if (p.id in added && p.id !in joined && p.id !in churned && r.role(p.id) != Role.INVITED) {
                return Failure("lost invitation: ${p.name} is ${r.role(p.id)} in ${describe(r)}")
            }
        }
        // The last round of messages, sent once the network was fair, reaches every active member it was sent to.
        for (s in said.filter { it.last }) {
            for (to in s.to) {
                val rcpt = honest.firstOrNull { it.id == to } ?: continue
                if (!r.isActive(s.from.id) || !r.isActive(to) || joinedModel(rcpt) == null) {
                    continue
                }
                if (rcpt.texts.none { it.first == gid && it.second == s.from.id && it.third == s.body }) {
                    return Failure("lost message: ${rcpt.name} never got \"${s.body}\" from ${s.from.name}")
                }
            }
        }
        return null
    }

    /**
     * Always: no forks between honest members (two rosters at one version) unless the owner equivocated; every honest
     * chain checks (each roster signed by the effective owner of the one before, given its proof: so the owner is who
     * the succession rule says); nobody added but by an owner; no forged or leaked texts.
     */
    private fun safety(): Failure? {
        val all = honest.flatMap { p -> p.store.historySince(gid, 0).map { p to it } }
        for ((ver, rs) in all.groupBy { it.second.roster.ver }) {
            if (rs.map { it.second.hashB64 }.toSet().size > 1 && !equivocated()) {
                return Failure("fork at v$ver: ${rs.map { "${it.first.name} by ${who(it.second.roster.by)}" }.distinct()}")
            }
        }
        for (p in honest) {
            val chain = p.store.historySince(gid, 0).sortedBy { it.roster.ver }
            for ((a, b) in chain.zipWithNext()) {
                if (b.roster.ver != a.roster.ver + 1 || b.roster.prev != a.hashB64) {
                    continue
                }
                val proof = b.roster.proof.mapNotNull { GroupCrypto.openFact(it)?.fact }
                if (!RosterRules.validChild(a.roster, b.roster, proof)) {
                    return Failure("authority: ${p.name} holds v${b.roster.ver} by ${who(b.roster.by)}, who wasn't the owner of v${a.roster.ver}")
                }
            }
            val r = model(p)?.view() ?: continue
            for (mem in r.members) {
                if (mem.id != alice.id && mem.id !in added) {
                    return Failure("authority: ${who(mem.id)} is in ${p.name}'s roster but nobody added them: ${describe(r)}")
                }
            }
        }
        val byBody = said.associateBy { it.body }
        for (p in peers) {
            for ((g, from, body) in p.texts) {
                if (g != gid) {
                    continue
                }
                val s = byBody[body]
                when {
                    s == null && from != mallory.id -> return Failure("forged: ${p.name} took \"$body\" from ${who(from)}")
                    s == null -> Unit
                    s.from.id != from -> return Failure("forged: ${p.name} took \"$body\" as from ${who(from)}")
                    p.id !in s.to -> return Failure("leak: ${p.name} read \"$body\", sent when they weren't a member to ${s.from.name}")
                }
            }
        }
        return null
    }

    /** Whoever is out now tries to post through every card they still have. Nobody may take it. */
    private fun afterwards(): Failure? {
        val inGroup = honest.filter { joinedModel(it) != null }
        val r = inGroup.firstOrNull()?.view(gid) ?: return null
        val before = honest.associateWith { it.texts.size }
        for (x in peers.filter { !r.isActive(it.id) && model(it) != null }) {
            for ((id, card) in x.store.routes[gid].orEmpty()) {
                if (id != x.id && r.isActive(id)) {
                    x.sendWithCard(card.card, Content.GText(gid, "late", "late ${x.name}", now))
                }
            }
        }
        net.deliverAll()
        for (p in honest) {
            // Only what their own view says is out: someone who never heard of a departure (it was lost, and nobody who
            // knows can reach them) takes the leaver for a member, as far as they know.
            val view = model(p)?.view()
            val got = p.texts.drop(before.getValue(p)).filter { it.third.startsWith("late ") && view?.isActive(it.second) != true }
            if (got.isNotEmpty()) {
                return Failure("posted after leaving: ${p.name} took ${got.map { it.third }}")
            }
        }
        return null
    }

    private fun describe(v: View) = "v${v.roster.ver} by ${who(v.roster.by)} " + v.members.joinToString(",", "[", "]") { "${who(it.id)}:${it.role.take(1)}" } +
        " \"${v.name}\""

    companion object {
        @Volatile
        var debug = System.getProperty("gf.groupFuzz.debug") != null

        /**
         * The same useless state exchange (same pair, same heads either side) after the adversary stopped: more is
         * ping-pong. A sender may send up to [GroupEngine.MAX_STATES] per head of its own (in flight, each answering a head
         * of ours it had just seen), and one more as it learns we're past them.
         */
        const val MAX_STATE_EXCHANGES = GroupEngine.MAX_STATES + 1


        /** A random scenario: mostly deliveries and messages, with membership changes and Mallory's tricks in between. */
        fun generate(seed: Long, length: Int): List<Op> {
            val rnd = java.util.Random(seed)
            // kind to weight
            val weights = listOf(0 to 8, 1 to 3, 2 to 7, 3 to 5, 4 to 5, 5 to 5, 6 to 3, 7 to 14, 8 to 24, 9 to 4, 10 to 12, 11 to 3, 12 to 4)
            val total = weights.sumOf { it.second }
            return List(length) {
                var x = rnd.nextInt(total)
                val kind = weights.first { (_, w) -> (x < w).also { if (!it) x -= w } }.first
                Op(kind, rnd.nextInt(256), rnd.nextInt(256), rnd.nextInt(256))
            }
        }

        /** Deletes steps (then zeroes numbers) while the same check still fails. */
        fun shrink(seed: Long, ops: List<Op>, failure: Failure, budget: Int = 400, millis: Long = 120_000): List<Op> {
            val until = System.currentTimeMillis() + millis
            var cur = ops
            var runs = 0
            fun fails(cand: List<Op>): Boolean {
                runs++
                if (System.currentTimeMillis() > until) {
                    return false
                }
                return GroupScenario(seed).run(cand)?.signature == failure.signature
            }
            var chunk = maxOf(1, cur.size / 2)
            while (chunk >= 1 && runs < budget) {
                var i = 0
                var progress = false
                while (i < cur.size && runs < budget) {
                    val cand = cur.subList(0, i) + cur.subList(minOf(i + chunk, cur.size), cur.size)
                    if (fails(cand)) {
                        cur = cand
                        progress = true
                    } else {
                        i += chunk
                    }
                }
                if (!progress) {
                    chunk /= 2
                }
            }
            for (i in cur.indices) {
                for (field in 0..2) {
                    if (runs >= budget) {
                        return cur
                    }
                    val o = cur[i]
                    val z = when (field) {
                        0 -> o.copy(a = 0)
                        1 -> o.copy(b = 0)
                        else -> o.copy(c = 0)
                    }
                    if (z != o && fails(cur.toMutableList().also { it[i] = z })) {
                        cur = cur.toMutableList().also { it[i] = z }
                    }
                }
            }
            return cur
        }
    }
}
