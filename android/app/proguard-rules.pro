# libsignal's native code finds Java classes by name: store callbacks, and exception classes it constructs and throws
# (duplicate message, untrusted identity, invalid key id...). An exception the app never names in Java would be removed
# by a narrower rule and only crash on that error path, which the benchmark seed's happy path can't catch. So keep all of
# it; it costs about 330 KB of DEX.
-keep class org.signal.libsignal.** { *; }
# SQLCipher and kotlinx.serialization ship their own rules (consumer rules, META-INF/com.android.tools/r8).
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
# UnifiedPush connector (Tink inside)
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn org.bouncycastle.**
# Built-in Tor (tor-android): JNI entry points and the control-port library must keep their names.
-keep class org.torproject.jni.** { *; }
-keep class net.freehaven.tor.control.** { *; }
-dontwarn net.freehaven.tor.control.**
