package app.goldfishsend.fuzz

import app.goldfishsend.GroupNet
import app.goldfishsend.Peer
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

    // What honest actions and Mallory's own did, for the invariants.
    private val added = mutableSetOf<String>()
    private val promoted = mutableSetOf(alice.id)

    /** An owner left at some point: someone took over by succession. */
    private var ownerLeft = false
    private val churned = mutableSetOf<String>()
    private val joined = mutableSetOf<String>()

    private class Said(val from: Peer, val body: String, val to: List<String>)

    private val said = mutableListOf<Said>()
    private var msg = 0
    private val drops = mutableListOf<String>()

    init {
        GroupEngine.forgetAsked()
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

    private fun log(s: String) {
        if (debug) {
            println(s)
        }
    }

    /** Runs the scenario. Null if every check passed. */
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
            }
            try {
                quiesce()
            } catch (e: Throwable) {
                return Failure("exception: delivering the rest: ${e.javaClass.simpleName}: ${e.message}", e)
            }
            return check() ?: afterwards() ?: drops.takeIf { it.isNotEmpty() }?.let { Failure("dropped: $it") }
        } finally {
            ReceiveGuard.onDrop = null
        }
    }

    private fun quiesce() {
        repeat(50) {
            net.queue.addAll(limbo)
            limbo.clear()
            net.deliverAll()
            if (net.queue.isEmpty() && limbo.isEmpty()) {
                return
            }
        }
        error("never quiet")
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
                }
            }
            1 -> {
                val p = peer(op.a)
                val m = model(p) ?: return
                if (m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED) {
                    return
                }
                if (m.view()?.isOwner(p.id) == true) {
                    ownerLeft = true
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
                    promoted += t.id
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
                    toTarget(target, GroupEngine.factContent(f))
                } else if (history.isNotEmpty()) {
                    val r = history[Math.floorMod(op.c, history.size)]
                    log("mallory replays v${r.roster.ver} by ${who(r.roster.by)} to ${target.name}")
                    toTarget(target, GroupEngine.rosterContent(r))
                }
            }
            1 -> forgeRoster(cur, target, op.c)
            2 -> {
                // Someone else's card pointing at Mallory's inbox, signed by Mallory.
                val card = mallory.store.routes[gid]?.get(target.id)?.card ?: return
                val forged = card.copy(inbox = m.myCard?.card?.inbox ?: return, seq = card.seq + 1)
                log("mallory forges ${target.name}'s card")
                toTarget(peer(op.c), GroupEngine.cardContent(GroupCrypto.signCard(mallory.identity.privateKey, forged)))
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
                log("mallory asks ${target.name} for a sync")
                toTarget(target, Content.GSync(gid, op.c.toLong() % 20))
            }
            else -> {
                // A card of Mallory's own with an old sequence number.
                log("mallory sends a stale card of hers to ${target.name}")
                toTarget(target, GroupEngine.cardContent(mallory.card(gid, 1, m.myCard?.card?.bundle)))
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
        toTarget(target, GroupEngine.rosterContent(GroupCrypto.signRoster(mallory.identity.privateKey, stamped)))
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
                Fact(g = gid, kind = FactKind.LEAVE, id = mallory.id, since = mine.since, ts = now / 1000 + Math.floorMod(op.b, 8), last = at.wire()),
            )
            if (model(mallory)?.roster?.roster?.member(mallory.id)?.since == mine.since) {
                churned += mallory.id
            }
            log("mallory leaves from v${base.ver} (stint ${mine.since})")
            GroupEngine.factContent(f)
        } else {
            val change = base.copy(name = "Fork ${msg++}")
            log("mallory forks at v${base.ver}")
            GroupEngine.rosterContent(GroupCrypto.signRoster(mallory.identity.privateKey, RosterRules.successor(at, change, mallory.id, now / 1000, emptyList())))
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
        val inGroup = honest.filter { joinedModel(it) != null }
        if (inGroup.isEmpty()) {
            return null
        }
        val views = inGroup.map { it.view(gid) }
        if (inGroup.map { it.roster(gid).hashB64 + " " + describe(it.view(gid)) }.toSet().size != 1) {
            return Failure("diverged: ${inGroup.map { p -> "${p.name} ${describe(p.view(gid))}" }}")
        }
        val r = views.first()
        // Nobody left to manage it (the owner left, and no member to take over): nobody can join, nothing changes, and
        // acceptances don't count (Membership.view). Then only agreement and safety are checked.
        return (if (r.owner == null) null else liveness(r)) ?: safety(r)
    }

    private fun liveness(r: View): Failure? {
        for (p in honest) {
            val m = model(p)
            val role = r.role(p.id)
            val ok = when {
                m == null -> role == null
                role == Role.OWNER || role == Role.MEMBER -> m.state == GroupModel.JOINED
                role == Role.INVITED -> m.state == GroupModel.INVITED
                else -> m.state == GroupModel.LEFT || m.state == GroupModel.REMOVED
            }
            if (!ok) {
                return Failure("state: ${p.name} is ${m?.state} but $role in ${describe(r)}")
            }
        }
        for (p in honest) {
            if (p.id in joined && p.id !in churned && !r.isActive(p.id)) {
                return Failure("lost member: ${p.name} joined and never left, but is ${r.role(p.id)} in ${describe(r)}")
            }
            if (p.id in added && p.id !in joined && p.id !in churned && r.role(p.id) != Role.INVITED) {
                return Failure("lost invitation: ${p.name} is ${r.role(p.id)} in ${describe(r)}")
            }
        }
        for (p in honest.filter { joinedModel(it) != null }) {
            val cards = model(p)!!.cards
            for (q in honest.filter { it != p && r.isActive(it.id) }) {
                val want = model(q)?.myCard?.card?.seq
                if (cards[q.id]?.card?.seq != want) {
                    return Failure("cards: ${p.name} has ${q.name}'s card ${cards[q.id]?.card?.seq}, latest is $want")
                }
            }
        }
        for (s in said) {
            for (to in s.to) {
                val rcpt = honest.firstOrNull { it.id == to } ?: continue
                if (s.from.id in churned || to in churned || !r.isActive(s.from.id) || !r.isActive(to)) {
                    continue
                }
                if (rcpt.texts.none { it.first == gid && it.second == s.from.id && it.third == s.body }) {
                    return Failure("lost message: ${rcpt.name} never got \"${s.body}\" from ${s.from.name}")
                }
            }
        }
        return null
    }

    private fun safety(r: View): Failure? {
        for (mem in r.members) {
            if (mem.id != alice.id && mem.id !in added) {
                return Failure("authority: ${who(mem.id)} is in the roster but nobody added them: ${describe(r)}")
            }
            if (mem.role == Role.OWNER && mem.id !in promoted && !ownerLeft) {
                return Failure("authority: ${who(mem.id)} is the owner but nobody made them one: ${describe(r)}")
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
            val got = p.texts.drop(before.getValue(p)).filter { it.third.startsWith("late ") }
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
