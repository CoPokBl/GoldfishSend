package app.goldfishsend.security

/**
 * Decides how far to trust a keyboard (input method). A keyboard sees every character typed, including
 * messages before they're encrypted. GoldfishSend asks keyboards not to learn from its text fields
 * (IME_FLAG_NO_PERSONALIZED_LEARNING), but only open-source keyboards can be checked to honour that.
 *
 * This file is pure Kotlin with no Android dependencies, so it can be unit-tested on the JVM.
 *
 * Detection is a heuristic based on package names and the installer. A sideloaded app could reuse a known
 * open-source package name, but that requires the user to have installed a disguised keyboard on purpose.
 */
object KeyboardTrust {
    enum class Verdict {
        /** Known open-source keyboard, or installed by an F-Droid client (F-Droid only ships FOSS). */
        OPEN_SOURCE,
        /** Source is published, but not under an open-source licence. */
        SOURCE_AVAILABLE,
        /** Closed source. */
        CLOSED_SOURCE,
        /** Closed source, and known to send typed text to the vendor's servers or to have done so insecurely. */
        CLOSED_SOURCE_CLOUD,
        /** Not recognised and not from F-Droid, so it can't be confirmed open source. */
        UNKNOWN,
    }

    data class Known(val name: String, val verdict: Verdict, val note: String? = null)

    data class Result(val verdict: Verdict, val name: String?, val note: String?, val viaFdroid: Boolean)

    /** Installer package names of F-Droid and its clients. Apps installed by these come from FOSS-only repositories. */
    val FDROID_INSTALLERS: Set<String> = setOf(
        "org.fdroid.fdroid",
        "org.fdroid.fdroid.privileged",
        "org.fdroid.basic",
        "com.looker.droidify",
        "com.machiav3lli.fdroid",
        "eu.bubu1.fdroidclassic",
    )

    /** The AOSP LatinIME package. It counts as open source only when it's a system app (as on GrapheneOS and LineageOS). */
    const val AOSP_KEYBOARD = "com.android.inputmethod.latin"

    private const val CLOUD_INPUT_NOTE =
        "This keyboard uses cloud input: what you type can be sent to the vendor's servers. Several cloud keyboards " +
            "of this kind were found to transmit keystrokes in a way network observers could decrypt (Citizen Lab, 2023–2024)."

    val KNOWN: Map<String, Known> = mapOf(
        // Open source.
        "helium314.keyboard" to Known("HeliBoard", Verdict.OPEN_SOURCE),
        "org.dslul.openboard.inputmethod.latin" to Known("OpenBoard", Verdict.OPEN_SOURCE),
        "dev.patrickgold.florisboard" to Known("FlorisBoard", Verdict.OPEN_SOURCE),
        "dev.patrickgold.florisboard.beta" to Known("FlorisBoard Beta", Verdict.OPEN_SOURCE),
        "com.menny.android.anysoftkeyboard" to Known("AnySoftKeyboard", Verdict.OPEN_SOURCE),
        "rkr.simplekeyboard.inputmethod" to Known("Simple Keyboard", Verdict.OPEN_SOURCE),
        "org.fossify.keyboard" to Known("Fossify Keyboard", Verdict.OPEN_SOURCE),
        "juloo.keyboard2" to Known("Unexpected Keyboard", Verdict.OPEN_SOURCE),
        "com.dessalines.thumbkey" to Known("Thumb-Key", Verdict.OPEN_SOURCE),
        "inc.flide.vi8" to Known("8VIM", Verdict.OPEN_SOURCE),
        "org.pocketworkstation.pckeyboard" to Known("Hacker's Keyboard", Verdict.OPEN_SOURCE),
        "org.smc.inputmethod.indic" to Known("Indic Keyboard", Verdict.OPEN_SOURCE),
        // Open-source input methods for Chinese, Japanese and Korean, the usual reason people need a cloud keyboard.
        "org.fcitx.fcitx5.android" to Known("Fcitx5", Verdict.OPEN_SOURCE),
        "com.osfans.trime" to Known("Trime (Rime)", Verdict.OPEN_SOURCE),
        "keepass2android.keepass2android" to Known("Keepass2Android keyboard", Verdict.OPEN_SOURCE),
        "keepass2android.keepass2android_nonet" to Known("Keepass2Android Offline keyboard", Verdict.OPEN_SOURCE),

        // Source available (non-OSI licence).
        "org.futo.inputmethod.latin" to Known(
            "FUTO Keyboard", Verdict.SOURCE_AVAILABLE,
            "Its source is public under the FUTO Source First License, which isn't an open-source licence. It works offline.",
        ),

        // Closed source.
        "com.google.android.inputmethod.latin" to Known(
            "Gboard", Verdict.CLOSED_SOURCE,
            "Gboard is closed source and made by Google. It can share usage data, and voice typing can send audio to Google.",
        ),
        "com.google.android.inputmethod.japanese" to Known("Gboard Japanese", Verdict.CLOSED_SOURCE),
        "com.google.android.inputmethod.pinyin" to Known("Google Pinyin Input", Verdict.CLOSED_SOURCE),
        "com.google.android.inputmethod.korean" to Known("Google Korean Input", Verdict.CLOSED_SOURCE),
        "com.touchtype.swiftkey" to Known(
            "Microsoft SwiftKey", Verdict.CLOSED_SOURCE,
            "SwiftKey is closed source, and its cloud sync and personalisation send typing data to Microsoft.",
        ),
        "com.touchtype.swiftkey.beta" to Known("Microsoft SwiftKey Beta", Verdict.CLOSED_SOURCE),
        "com.samsung.android.honeyboard" to Known("Samsung Keyboard", Verdict.CLOSED_SOURCE),
        "com.sec.android.inputmethod" to Known("Samsung Keyboard", Verdict.CLOSED_SOURCE),
        "com.syntellia.fleksy.keyboard" to Known("Fleksy", Verdict.CLOSED_SOURCE),
        "com.cootek.smartinputv5" to Known("TouchPal", Verdict.CLOSED_SOURCE),
        "com.lge.ime" to Known("LG Keyboard", Verdict.CLOSED_SOURCE),
        "com.huawei.ohos.inputmethod" to Known("Celia Keyboard", Verdict.CLOSED_SOURCE_CLOUD, CLOUD_INPUT_NOTE),
        "com.grammarly.android.keyboard" to Known(
            "Grammarly Keyboard", Verdict.CLOSED_SOURCE_CLOUD,
            "Grammarly sends what you type to its servers for analysis.",
        ),
        "com.jb.gokeyboard" to Known("GO Keyboard", Verdict.CLOSED_SOURCE_CLOUD, "GO Keyboard has been reported collecting and transmitting personal data."),
        "com.tencent.qqpinyin" to Known("QQ Pinyin", Verdict.CLOSED_SOURCE_CLOUD, CLOUD_INPUT_NOTE),
    )

    /** Cloud keyboard families that ship under many OEM-specific package names (…_mi, …_huawei, .vivo, etc.). */
    private val CLOUD_PREFIXES: List<Pair<String, String>> = listOf(
        "com.sohu.inputmethod.sogou" to "Sogou Keyboard",
        "com.baidu.input" to "Baidu Keyboard",
        "com.iflytek.inputmethod" to "iFlytek Keyboard",
    )

    /**
     * @param packageName the keyboard's package.
     * @param installer the package that installed it (null for preinstalled or unknown).
     * @param isSystemApp whether it's part of the system image.
     */
    fun classify(packageName: String, installer: String?, isSystemApp: Boolean): Result {
        val viaFdroid = installer != null && installer in FDROID_INSTALLERS

        // Recognised keyboards keep their verdict whatever installed them: closed source stays closed source.
        KNOWN[packageName]?.let { known ->
            return Result(known.verdict, known.name, known.note, viaFdroid)
        }
        CLOUD_PREFIXES.firstOrNull { (prefix, _) ->
            packageName == prefix || packageName.startsWith("$prefix.") || packageName.startsWith("${prefix}_")
        }?.let { (_, name) ->
            return Result(Verdict.CLOSED_SOURCE_CLOUD, name, CLOUD_INPUT_NOTE, viaFdroid)
        }

        if (packageName == AOSP_KEYBOARD) {
            // The open-source AOSP keyboard is always preinstalled. A user-installed app with this name is suspicious.
            return if (isSystemApp) {
                Result(Verdict.OPEN_SOURCE, "Android Keyboard (AOSP)", null, viaFdroid)
            } else {
                Result(Verdict.UNKNOWN, null, null, viaFdroid)
            }
        }

        return if (viaFdroid) Result(Verdict.OPEN_SOURCE, null, null, true) else Result(Verdict.UNKNOWN, null, null, false)
    }

    /** A short suggestion naming open-source alternatives, shown on warnings. */
    const val ALTERNATIVES = "Open-source options include HeliBoard, FlorisBoard and AnySoftKeyboard, all on F-Droid."

    /** For cloud keyboards, usually installed for CJK input. These open-source input methods cover it, offline. */
    const val CJK_ALTERNATIVES = "For Chinese, Japanese or Korean input, Fcitx5 and Trime (Rime) are open source and work offline, both on F-Droid."

    /** Where the "get an open-source keyboard" fix sends the user. */
    const val SUGGESTED_KEYBOARD_URL = "https://f-droid.org/packages/helium314.keyboard/"
}
