# libsignal uses JNI callbacks into Java classes.
-keep class org.signal.libsignal.** { *; }
# SQLCipher JNI
-keep class net.zetetic.database.** { *; }
# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class app.goldfishsend.** {
    *** Companion;
}
-keepclasseswithmembers class app.goldfishsend.** {
    kotlinx.serialization.KSerializer serializer(...);
}
# UnifiedPush connector (Tink inside)
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn org.bouncycastle.**
# Built-in Tor (tor-android): JNI entry points and the control-port library must keep their names.
-keep class org.torproject.jni.** { *; }
-keep class net.freehaven.tor.control.** { *; }
-dontwarn net.freehaven.tor.control.**
