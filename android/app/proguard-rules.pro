# libsignal's native code calls back into its Java classes by name (its bundled rules alone aren't enough: the store
# callbacks go missing). Every libsignal class the app uses keeps its name and all its members, but classes nothing
# uses are removed (keeping all of libsignal added about 0.5 MB to classes.dex). The benchmark build is minified with
# these rules and runs a real PQXDH handshake, safety numbers and HPKE when it seeds its data (app/src/benchmark).
-keepnames class org.signal.libsignal.**
-keepclassmembers class org.signal.libsignal.** { *; }
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
