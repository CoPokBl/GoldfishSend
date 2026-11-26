package app.goldfishsend

import app.goldfishsend.core.DecoyPrefs
import app.goldfishsend.core.DuressAction
import app.goldfishsend.core.KvStore
import app.goldfishsend.core.MapPreferences
import app.goldfishsend.core.Prefs
import app.goldfishsend.core.ThemeMode
import app.goldfishsend.crypto.KeyVault
import app.goldfishsend.security.Attempt
import app.goldfishsend.security.DecoySecrets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The decoy profile's own settings and PINs, and the wrong-attempt rules the duress PIN must not get round. */
class DecoyProfileTest {
    private class MapKv : KvStore {
        val m = HashMap<String, ByteArray>()

        override fun get(k: String): ByteArray? = m[k]

        override fun put(k: String, v: ByteArray?) {
            if (v == null) m.remove(k) else m[k] = v
        }
    }

    private fun realPrefs(vararg kv: Pair<String, Any>) = MapPreferences(mapOf(*kv)) { }

    @Test
    fun aNewDecoyStartsFromWhatTheLockScreenShowsAndDefaultsForTheRest() {
        val real = realPrefs(
            "theme" to ThemeMode.DARK.ordinal, "scramble_pin" to true, "max_failed" to 5,
            "wipe_on_reboot" to true, "panic_trigger" to "org.example.ripple", "inactivity_days" to 7, "notif_content" to 2,
        )
        val p = DecoyPrefs.open(MapKv()) { DecoyPrefs.mirror(real.all, mapOf("biometric" to true, "decoy_proxy_mode" to "EMBEDDED_TOR")) }
        // Seen at the lock screen already: the same, so opening the decoy changes nothing visible.
        assertEquals(ThemeMode.DARK, p.themeMode)
        assertTrue(p.scramblePinPad)
        assertEquals(5, p.maxFailedAttempts)
        assertTrue(p.biometricUnlock)
        assertEquals("EMBEDDED_TOR", p.decoyProxyMode)
        // Not visible from outside: the real profile's choices don't show through.
        assertFalse(p.wipeOnReboot)
        assertNull(p.panicTrigger)
        assertEquals(0, p.inactivityWipeDays)
        assertEquals(0, p.notificationContent.ordinal)
    }

    @Test
    fun changesInTheDecoyStayInItAndPersist() {
        val realMap = realPrefs("lock_timeout" to 60, "server_url" to "https://real.example")
        val real = Prefs(realMap)
        val kv = MapKv()
        val p = DecoyPrefs.open(kv) { DecoyPrefs.mirror(realMap.all, emptyMap()) }
        assertEquals("https://real.example", p.serverUrl)
        p.lockTimeoutSecs = 3600
        p.serverUrl = "https://evil.example"
        p.lockOnScreenOff = false
        p.dismissFinding("biometric")
        p.panicTrigger = null
        // Never the real settings.
        assertEquals(60, real.lockTimeoutSecs)
        assertEquals("https://real.example", real.serverUrl)
        assertTrue(real.lockOnScreenOff)
        // And the decoy keeps them, stored only in its own database.
        val again = DecoyPrefs.open(kv) { error("a stored decoy is never seeded again") }
        assertEquals(3600, again.lockTimeoutSecs)
        assertEquals("https://evil.example", again.serverUrl)
        assertFalse(again.lockOnScreenOff)
        assertEquals(setOf("biometric"), again.dismissedFindings)
        assertEquals(setOf(DecoyPrefs.KEY), kv.m.keys)
    }

    @Test
    fun laterChangesToTheRealProfileDontShowInAnExistingDecoy() {
        val kv = MapKv()
        DecoyPrefs.open(kv) { DecoyPrefs.mirror(realPrefs("max_failed" to 10).all, emptyMap()) }
        val p = DecoyPrefs.open(kv) { DecoyPrefs.mirror(realPrefs("max_failed" to 20).all, emptyMap()) }
        assertEquals(10, p.maxFailedAttempts)
    }

    @Test
    fun storedSettingsRoundTripEveryType() {
        val m = mapOf<String, Any>("b" to true, "i" to 7, "l" to (1L shl 40), "f" to 1.5f, "s" to "x\"y", "S" to setOf("a", "b"))
        assertEquals(m, DecoyPrefs.decode(DecoyPrefs.encode(m)))
    }

    @Test
    fun aDecoyRecognisesItsOwnSecretAndNoOther() {
        val kv = MapKv()
        val d = DecoySecrets(kv)
        val salt = ByteArray(16) { 3 }
        val k = KeyVault.argon2("4321".toCharArray(), salt)
        d.rememberSecret(salt, KeyVault.decoySecretTag(k))
        assertTrue(d.checkSecret("4321".toCharArray()))
        assertFalse(d.checkSecret("123456".toCharArray()))
    }

    @Test
    fun aDecoysDuressAndHiddenPinsAreItsOwnAndEveryCheckCostsOneArgon2() {
        var runs = 0
        val counting = { pin: CharArray, salt: ByteArray ->
            runs++
            // A stand-in for Argon2: the cost is what's counted here, not the hash.
            app.goldfishsend.proto.Hash.sha256(String(pin).toByteArray(), salt)
        }
        val kv = MapKv()
        val d = DecoySecrets(kv, counting)
        // Off: the slots hold filler, yet a check still runs the KDF, as against the real vault's always-filled slots.
        assertFalse(d.isDuress("1111".toCharArray()))
        assertFalse(d.isHiddenPin("222222".toCharArray()))
        assertFalse(d.checkSecret("4321".toCharArray()))
        assertEquals(3, runs)
        d.setDuress("1111".toCharArray())
        d.setHiddenPin("222222".toCharArray())
        runs = 0
        assertTrue(d.isDuress("1111".toCharArray()))
        assertTrue(d.isHiddenPin("222222".toCharArray()))
        assertFalse(d.isDuress("222222".toCharArray()))
        assertEquals(3, runs)
        assertEquals(DuressAction.WIPE_ALL, d.duressAction)
        d.duressAction = DuressAction.DECOY
        assertEquals(DuressAction.DECOY, DecoySecrets(kv, counting).duressAction)
        d.setDuress(null)
        assertFalse(d.isDuress("1111".toCharArray()))
    }

    @Test
    fun theDuressPinNeverEarnsMoreGuessesAtTheRealSecret() {
        val p = Prefs(realPrefs("max_failed" to 10))
        // Nine wrong guesses, then the duress PIN, again and again: the tenth wrong guess still erases.
        repeat(9) { assertEquals(10 - (it + 1), Attempt(p).wrong()) }
        Attempt(p).duress()
        assertEquals(9, p.failedAttempts)
        assertEquals(Attempt.ERASE, Attempt(p).wrong())
    }

    @Test
    fun afterADuressUnlockTheWarningStartsOverAsAfterARealOne() {
        val p = Prefs(realPrefs("max_failed" to 10))
        repeat(8) { Attempt(p).wrong() }
        Attempt(p).duress()
        // A real unlock would leave no warning here; nor does the decoy (the erase still counts all nine).
        assertEquals(9, Attempt(p).wrong())
        assertEquals(9, p.failedAttempts)
    }

    @Test
    fun onlyTheRightSecretClearsTheCount() {
        val p = Prefs(realPrefs("max_failed" to 10))
        repeat(4) { Attempt(p).wrong() }
        Attempt(p).undo()
        assertEquals(4, p.failedAttempts)
        Attempt(p).right()
        assertEquals(0, p.failedAttempts)
        assertEquals(0, p.failedAttemptsShown)
    }

    @Test
    fun noLimitMeansNoErase() {
        val p = Prefs(realPrefs("max_failed" to 0))
        repeat(50) { assertNull(Attempt(p).wrong()) }
    }

    @Test
    fun aDecoysStoredSecretIsSaltAndTagOnly() {
        val kv = MapKv()
        val salt = ByteArray(16) { 9 }
        val tag = ByteArray(32) { 1 }
        DecoySecrets(kv).rememberSecret(salt, tag)
        assertArrayEquals(salt + tag, kv.m["decoy_secret"])
    }
}
