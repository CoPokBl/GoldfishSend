package app.goldfishsend

import app.goldfishsend.security.AuditRules
import app.goldfishsend.security.AuditRules.DnsState
import app.goldfishsend.security.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuditRulesTest {
    private val sec = 1000L
    private val min = 60_000L

    @Test
    fun shortLockDelaysAreFine() {
        assertNull(AuditRules.lockTimeoutSeverity(30 * sec, 5 * sec))
        assertNull(AuditRules.lockTimeoutSeverity(1 * min, 0))
        assertNull(AuditRules.lockTimeoutSeverity(2 * min, null))
    }

    @Test
    fun lockDelayIncludesTheLockAfterSetting() {
        // 2 minutes of screen plus 30 seconds before locking goes past the info threshold.
        assertEquals(Severity.INFO, AuditRules.lockTimeoutSeverity(2 * min, 30 * sec))
        assertEquals(Severity.WARNING, AuditRules.lockTimeoutSeverity(5 * min, 30 * min))
    }

    @Test
    fun longAndNeverAreWarnings() {
        assertEquals(Severity.INFO, AuditRules.lockTimeoutSeverity(5 * min, null))
        assertEquals(Severity.WARNING, AuditRules.lockTimeoutSeverity(10 * min, null))
        assertEquals(Severity.WARNING, AuditRules.lockTimeoutSeverity(Int.MAX_VALUE.toLong(), null))
    }

    @Test
    fun nonsenseValuesAreIgnored() {
        assertNull(AuditRules.lockTimeoutSeverity(0, null))
        assertNull(AuditRules.lockTimeoutSeverity(-1, null))
        assertEquals(Severity.INFO, AuditRules.lockTimeoutSeverity(3 * min, -5))
    }

    @Test
    fun durationsReadNaturally() {
        assertEquals("45 seconds", AuditRules.describeDuration(45 * sec))
        assertEquals("1 minute", AuditRules.describeDuration(1 * min))
        assertEquals("10 minutes", AuditRules.describeDuration(10 * min + 20 * sec))
        assertEquals("1 hour", AuditRules.describeDuration(60 * min))
        assertEquals("1 hour 30 minutes", AuditRules.describeDuration(90 * min))
        assertEquals("never", AuditRules.describeDuration(Int.MAX_VALUE.toLong()))
    }

    @Test
    fun dnsState() {
        assertEquals(DnsState.PRIVATE_DNS_ACTIVE, AuditRules.dnsState(privateDnsActive = true, onVpn = true))
        assertEquals(DnsState.THROUGH_VPN, AuditRules.dnsState(privateDnsActive = false, onVpn = true))
        assertEquals(DnsState.PLAIN, AuditRules.dnsState(privateDnsActive = false, onVpn = false))
    }

    @Test
    fun notesCostNothing() {
        assertEquals(0, Severity.NOTE.weight)
    }
}

class DismissalTest {
    private fun finding(id: String, severity: Severity, detail: String = "d") =
        app.goldfishsend.security.Finding(id, severity, "title $id", detail)

    @Test
    fun noJustificationFindingsCantBeDismissed() {
        for ((id, sev) in listOf(
            "screenlock" to Severity.CRITICAL, "tls" to Severity.CRITICAL, "encryption" to Severity.WARNING,
            "push" to Severity.CRITICAL, "ime" to Severity.CRITICAL, "patch" to Severity.CRITICAL, "os" to Severity.CRITICAL,
        )) {
            assertFalse("$id/$sev", AuditRules.isDismissible(id, sev))
        }
    }

    @Test
    fun choicesWithLegitimateReasonsCanBeDismissed() {
        for ((id, sev) in listOf(
            "root" to Severity.CRITICAL, "bootloader" to Severity.WARNING, "adb" to Severity.WARNING, "a11y" to Severity.WARNING,
            "push" to Severity.WARNING, "ime" to Severity.WARNING, "patch" to Severity.WARNING, "os" to Severity.WARNING,
            "autolock" to Severity.WARNING, "applock" to Severity.WARNING, "dns" to Severity.NOTE,
            "notif-listeners" to Severity.WARNING, "notif-listeners" to Severity.INFO, "timer" to Severity.INFO,
        )) {
            assertTrue("$id/$sev", AuditRules.isDismissible(id, sev))
        }
        assertFalse(AuditRules.isDismissible("dns", Severity.OK))
    }

    @Test
    fun dismissedFindingsLeaveTheScoreButStayRestorable() {
        val adb = finding("adb", Severity.WARNING)
        val report = app.goldfishsend.security.AuditReport(listOf(adb), setOf(adb.dismissKey))
        assertEquals(100, report.score)
        assertEquals("Looking good", report.headline)
        assertEquals(listOf(adb), report.dismissed)
        assertTrue(report.active.isEmpty())
    }

    @Test
    fun dismissingTheUndismissableHasNoEffect() {
        val lock = finding("screenlock", Severity.CRITICAL)
        val report = app.goldfishsend.security.AuditReport(listOf(lock), setOf(lock.dismissKey))
        assertEquals(listOf(lock), report.active)
        assertTrue(report.dismissed.isEmpty())
        assertEquals(75, report.score)
    }

    @Test
    fun aChangedSituationResurfaces() {
        val before = finding("notif-listeners", Severity.INFO, "App A can read notifications")
        val after = finding("notif-listeners", Severity.INFO, "App A, App B can read notifications")
        val report = app.goldfishsend.security.AuditReport(listOf(after), setOf(before.dismissKey))
        assertEquals(listOf(after), report.active)
        // The same finding again keeps the same key.
        assertEquals(before.dismissKey, finding("notif-listeners", Severity.INFO, "App A can read notifications").dismissKey)
    }
}
