package app.goldfishsend.security

/** Pure decision rules for the security audit, kept free of Android APIs so they can be unit-tested on the JVM. */
object AuditRules {
    /** Below this, the auto-lock delay is fine. */
    const val LOCK_INFO_MS = 2 * 60_000L

    /** Above this, the phone sits unlocked long enough to be a real risk if it's left lying around. */
    const val LOCK_WARNING_MS = 5 * 60_000L

    /**
     * How long the phone stays unlocked after the user stops touching it: the screen-off timeout plus the
     * "lock after screen off" delay.
     *
     * @param screenOffMs `Settings.System.SCREEN_OFF_TIMEOUT`. Integer.MAX_VALUE or larger means "never".
     * @param lockAfterMs the secure lock delay, or null if the platform doesn't let apps read it.
     * @return the severity, or null if it's within reasonable limits.
     */
    fun lockTimeoutSeverity(screenOffMs: Long, lockAfterMs: Long?): Severity? {
        if (screenOffMs <= 0) {
            return null
        }
        if (screenOffMs >= Int.MAX_VALUE) {
            return Severity.WARNING
        }
        val effective = screenOffMs + (lockAfterMs ?: 0L).coerceAtLeast(0L)
        return when {
            effective > LOCK_WARNING_MS -> Severity.WARNING
            effective > LOCK_INFO_MS -> Severity.INFO
            else -> null
        }
    }

    /** "45 seconds", "2 minutes", "1 hour 30 minutes", or "never". */
    fun describeDuration(ms: Long): String {
        if (ms >= Int.MAX_VALUE) {
            return "never"
        }
        val totalSeconds = ms / 1000
        if (totalSeconds < 60) {
            return plural(totalSeconds, "second")
        }
        val hours = totalSeconds / 3600
        val minutes = (totalSeconds % 3600) / 60
        return when {
            hours == 0L -> plural(minutes, "minute")
            minutes == 0L -> plural(hours, "hour")
            else -> "${plural(hours, "hour")} ${plural(minutes, "minute")}"
        }
    }

    private fun plural(n: Long, unit: String) = "$n $unit${if (n == 1L) "" else "s"}"

    /**
     * Findings that can't be dismissed, by id and severity: conditions with no legitimate reason to keep. Everything
     * else (notes, info, and warnings or criticals that people choose on purpose, such as root, an unlocked bootloader,
     * accessibility services, USB debugging, a Google push service or a keyboard their language needs) can be dismissed.
     */
    fun isDismissible(id: String, severity: Severity): Boolean = when {
        severity == Severity.OK -> false
        id == "screenlock" -> false // nothing protects the device or its storage keys
        id == "tls" -> false // plaintext connection to the server
        id == "server_identity" -> false // our server can't be verified, so nothing gets through until it's resolved
        id == "encryption" -> false // unencrypted device storage
        id == "push" && severity == Severity.CRITICAL -> false // push not working: messages won't arrive
        id == "ime" && severity == Severity.CRITICAL -> false // keyboard known to send keystrokes off the device
        id == "patch" && severity == Severity.CRITICAL -> false // over 6 months of unpatched vulnerabilities
        id == "os" && severity == Severity.CRITICAL -> false // no security updates at all
        else -> true
    }

    enum class DnsState { PRIVATE_DNS_ACTIVE, THROUGH_VPN, PLAIN }

    /** A VPN normally carries DNS itself (Tailscale MagicDNS, WireGuard, Orbot), so it counts as covered. */
    fun dnsState(privateDnsActive: Boolean, onVpn: Boolean): DnsState = when {
        privateDnsActive -> DnsState.PRIVATE_DNS_ACTIVE
        onVpn -> DnsState.THROUGH_VPN
        else -> DnsState.PLAIN
    }
}
