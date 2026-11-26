package app.goldfishsend

import app.goldfishsend.core.DecoyPrefs
import app.goldfishsend.core.KvStore
import app.goldfishsend.core.MapPreferences
import app.goldfishsend.core.PanicResponse
import app.goldfishsend.crypto.MessageVault
import app.goldfishsend.net.ApiException
import app.goldfishsend.net.GatewayState
import app.goldfishsend.net.ServerApi
import app.goldfishsend.net.ServerPin
import app.goldfishsend.proto.Rand
import app.goldfishsend.security.ClipboardGuard
import app.goldfishsend.security.PanicResponderActivity
import app.goldfishsend.security.Presence
import kotlinx.coroutines.runBlocking
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** Rotating the message root key after deletes (stale copies of deleted rows must not open with the next root). */
class MessageRootRotationTest {
    private fun opens(v: MessageVault, id: String, wk: ByteArray, ct: ByteArray): Boolean =
        runCatching { v.open(id, wk, ct) }.isSuccess

    @Test
    fun liveRowsFollowTheNewRootAndStaleCopiesDont() {
        val a = Rand.bytes(32)
        val v = MessageVault(a.copyOf())
        val kept = v.seal("kept", "still here".toByteArray())
        val deleted = v.seal("deleted", "gone".toByteArray())
        val b = Rand.bytes(32)
        // The rotation re-wraps what's live; the deleted row's key survives only as a stale copy.
        val rewrapped = v.rewrapUnder(b, "kept", kept.wrappedKey)!!
        v.replaceRoot(b.copyOf())
        assertEquals("still here", String(v.open("kept", rewrapped, kept.ciphertext)))

        // The next unlock knows only the new root (the old one's Keystore wrapper is gone).
        val next = MessageVault(b.copyOf())
        assertEquals("still here", String(next.open("kept", rewrapped, kept.ciphertext)))
        assertFalse(opens(next, "deleted", deleted.wrappedKey, deleted.ciphertext))
        assertFalse(opens(next, "kept", kept.wrappedKey, kept.ciphertext))
        // And the old root can't open what was re-wrapped.
        assertFalse(opens(MessageVault(a.copyOf()), "kept", rewrapped, kept.ciphertext))
    }

    @Test
    fun rowsReadJustBeforeTheSwapStillOpenUntilLock() {
        val v = MessageVault(Rand.bytes(32))
        val old = v.seal("m", "hi".toByteArray())
        v.replaceRoot(Rand.bytes(32))
        // Read before the rotation, opened after it: the retired root (in RAM only) still opens it.
        assertEquals("hi", String(v.open("m", old.wrappedKey, old.ciphertext)))
        // New rows go under the new root.
        val fresh = v.seal("n", "new".toByteArray())
        assertEquals("new", String(v.open("n", fresh.wrappedKey, fresh.ciphertext)))
        // Locking wipes every root, retired ones included.
        v.wipe()
        assertFalse(opens(v, "m", old.wrappedKey, old.ciphertext))
    }

    @Test
    fun blobsAreResealedUnderTheNewRoot() {
        val v = MessageVault(Rand.bytes(32))
        val blob = v.sealBlob("outbox", "queued".toByteArray())
        val b = Rand.bytes(32)
        val resealed = v.resealUnder(b, "outbox", blob)!!
        // The label is bound: a blob can't be moved to another slot.
        assertNull(v.resealUnder(b, "chunk/1/w/0", blob))
        val next = MessageVault(b)
        assertArrayEquals("queued".toByteArray(), next.openBlob("outbox", resealed))
        assertTrue(runCatching { next.openBlob("outbox", blob) }.isFailure)
    }

    @Test
    fun aSwapWhoseTransactionFailedIsUndone() {
        val a = Rand.bytes(32)
        val v = MessageVault(a.copyOf())
        val undo = v.replaceRoot(Rand.bytes(32))
        undo()
        val m = v.seal("m", "x".toByteArray())
        assertEquals("x", String(MessageVault(a).open("m", m.wrappedKey, m.ciphertext)))
    }

    @Test
    fun aKeyThatDoesntOpenIsLeftAlone() {
        val v = MessageVault(Rand.bytes(32))
        assertNull(v.rewrapUnder(Rand.bytes(32), "m", Rand.bytes(60)))
    }
}

class InactivityPresenceTest {
    private val day = 86_400_000L

    @Test
    fun comingBackAfterTheLimitWipesInsteadOfResettingTheClock() {
        val last = Presence.Mark(wallMs = 0, elapsedMs = 1000, bootCount = 2)
        // Opening a still-unlocked app 4 days later, with a 3-day limit.
        assertEquals(Presence.OnPresent.WIPE, Presence.onPresent(last, 3, 4 * day, 1000 + 4 * day, 2))
        assertEquals(Presence.OnPresent.RECORD, Presence.onPresent(last, 3, 2 * day, 1000 + 2 * day, 2))
    }

    @Test
    fun offOrFirstRunJustRecords() {
        assertEquals(Presence.OnPresent.RECORD, Presence.onPresent(null, 3, 100 * day, 100 * day, 2))
        assertEquals(Presence.OnPresent.RECORD, Presence.onPresent(Presence.Mark(0, 0, 2), 0, 100 * day, 100 * day, 2))
    }
}

class ClipboardClearTest {
    @Test
    fun onlyOurCopyIsCleared() {
        assertTrue(ClipboardGuard.shouldClear(seen = true, current = "m1", ours = "m1"))
        // The user copied something else since.
        assertFalse(ClipboardGuard.shouldClear(seen = true, current = null, ours = "m1"))
        assertFalse(ClipboardGuard.shouldClear(seen = true, current = "m2", ours = "m1"))
    }

    @Test
    fun aClipboardWeCantSeeIsClearedAnyway() {
        // In the background Android hides the clipboard; the user still asked for the copy to go.
        assertTrue(ClipboardGuard.shouldClear(seen = false, current = null, ours = "m1"))
    }
}

class PanicConnectTest {
    @Test
    fun aDecoyNeverShowsTheRealResponse() {
        // The dialog reads the open session's prefs; a decoy's start without the real panic settings.
        val real = MapPreferences(mapOf("panic_response" to PanicResponse.WIPE_EVERYTHING.name, "panic_trigger" to "org.example.ripple")) { }
        val decoy = DecoyPrefs.open(object : KvStore {
            val m = HashMap<String, ByteArray>()

            override fun get(k: String): ByteArray? = m[k]

            override fun put(k: String, v: ByteArray?) {
                if (v == null) m.remove(k) else m[k] = v
            }
        }) { DecoyPrefs.mirror(real.all, emptyMap()) }
        assertEquals(PanicResponse.LOCK, PanicResponderActivity.preselect(decoy.panicResponse))
        assertNull(decoy.panicTrigger)
    }

    @Test
    fun theRealSessionStartsFromTheCurrentResponse() {
        assertEquals(PanicResponse.WIPE_EVERYTHING, PanicResponderActivity.preselect(PanicResponse.WIPE_EVERYTHING))
        assertEquals(PanicResponse.LOCK, PanicResponderActivity.preselect(PanicResponse.OFF))
    }
}

/** After a wipe, a client made before it must neither send anything nor write anything back. */
class StoppedClientTest {
    private lateinit var server: MockWebServer
    private lateinit var gw: GatewayTestServer
    private lateinit var dispatch: GatewayTestServer.Dispatch

    @Before
    fun up() {
        gw = GatewayTestServer()
        dispatch = gw.Dispatch { GatewayTestServer.json(200, """{"challenge":"x"}""") }
        server = MockWebServer()
        server.dispatcher = dispatch
        server.start()
    }

    @After
    fun down() = server.close()

    @Test
    fun aStoppedClientSendsNothing() = runBlocking {
        var live = true
        val state = GatewayState.Memory()
        val api = ServerApi(server.url("/").toString(), OkHttpClient(), ServerPin(gw.fp), state, live = { live })
        live = false
        try {
            api.powChallenge()
            fail()
        } catch (e: ApiException) {
            assertEquals("stopped", e.code)
        }
        assertEquals(0, server.requestCount)
        assertNull(state.blob(gw.fp))
    }

    @Test
    fun aKeyArrivingAfterTheWipeIsNotRecorded() = runBlocking {
        var live = true
        var firstUse: String? = null
        val state = GatewayState.Memory()
        val api = ServerApi(
            server.url("/").toString(), OkHttpClient(), ServerPin(null, onFirstUse = { firstUse = it }), state, live = { live },
        )
        dispatch.override = { r ->
            if (r.url.encodedPath.endsWith("/v1/key")) {
                // The wipe happens while the key is on its way.
                live = false
            }
            null
        }
        try {
            api.powChallenge()
            fail()
        } catch (e: ApiException) {
            assertEquals("stopped", e.code)
        }
        assertEquals(1, dispatch.keyFetches)
        assertTrue(dispatch.received.isEmpty())
        assertNull(firstUse)
        assertNull(state.blob(gw.fp))
    }
}
