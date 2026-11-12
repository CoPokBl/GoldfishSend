package app.goldfishsend

import app.goldfishsend.security.KeyboardTrust
import app.goldfishsend.security.KeyboardTrust.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyboardTrustTest {
    private fun verdict(pkg: String, installer: String? = null, system: Boolean = false) =
        KeyboardTrust.classify(pkg, installer, system).verdict

    @Test
    fun gboardIsFlaggedEvenWhenPreinstalled() {
        val r = KeyboardTrust.classify("com.google.android.inputmethod.latin", null, isSystemApp = true)
        assertEquals(Verdict.CLOSED_SOURCE, r.verdict)
        assertEquals("Gboard", r.name)
        assertEquals(Verdict.CLOSED_SOURCE, verdict("com.google.android.inputmethod.latin", "com.android.vending"))
    }

    @Test
    fun otherClosedKeyboards() {
        for (pkg in listOf("com.touchtype.swiftkey", "com.samsung.android.honeyboard", "com.sec.android.inputmethod", "com.syntellia.fleksy.keyboard")) {
            assertEquals(pkg, Verdict.CLOSED_SOURCE, verdict(pkg, system = true))
        }
    }

    @Test
    fun cloudKeyboardsAreCritical_includingOemVariants() {
        for (pkg in listOf(
            "com.sohu.inputmethod.sogou", "com.sohu.inputmethod.sogou.xiaomi", "com.baidu.input", "com.baidu.input_mi",
            "com.baidu.input_huawei", "com.iflytek.inputmethod", "com.iflytek.inputmethod.miui", "com.tencent.qqpinyin",
            "com.huawei.ohos.inputmethod", "com.grammarly.android.keyboard",
        )) {
            assertEquals(pkg, Verdict.CLOSED_SOURCE_CLOUD, verdict(pkg, system = true))
        }
        // Prefix matching must not catch unrelated packages.
        assertEquals(Verdict.UNKNOWN, verdict("com.baidu.inputx"))
    }

    @Test
    fun knownOpenSourceKeyboards() {
        for (pkg in listOf(
            "helium314.keyboard", "dev.patrickgold.florisboard", "com.menny.android.anysoftkeyboard", "rkr.simplekeyboard.inputmethod",
            "org.fossify.keyboard", "juloo.keyboard2", "com.dessalines.thumbkey", "org.pocketworkstation.pckeyboard",
        )) {
            assertEquals(pkg, Verdict.OPEN_SOURCE, verdict(pkg, "com.android.vending"))
        }
        assertEquals(Verdict.SOURCE_AVAILABLE, verdict("org.futo.inputmethod.latin"))
    }

    @Test
    fun anythingFromFdroidIsTrusted() {
        for (installer in KeyboardTrust.FDROID_INSTALLERS) {
            val r = KeyboardTrust.classify("org.example.someboard", installer, isSystemApp = false)
            assertEquals(installer, Verdict.OPEN_SOURCE, r.verdict)
            assertTrue(r.viaFdroid)
        }
    }

    @Test
    fun unknownKeyboardsFromElsewhereAreFlagged() {
        val r = KeyboardTrust.classify("com.example.closedboard", "com.android.vending", isSystemApp = false)
        assertEquals(Verdict.UNKNOWN, r.verdict)
        assertFalse(r.viaFdroid)
        assertEquals(Verdict.UNKNOWN, verdict("com.example.oem.keyboard", system = true))
    }

    @Test
    fun aospKeyboardTrustedOnlyAsSystemApp() {
        assertEquals(Verdict.OPEN_SOURCE, verdict(KeyboardTrust.AOSP_KEYBOARD, system = true))
        // A sideloaded app borrowing the AOSP package name isn't the AOSP keyboard.
        assertEquals(Verdict.UNKNOWN, verdict(KeyboardTrust.AOSP_KEYBOARD, "com.android.vending", system = false))
    }
}
