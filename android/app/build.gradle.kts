import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// Release signing is optional: it's configured from an untracked android/keystore.properties, or from
// environment variables (see docs/RELEASING.md). Without either, assembleRelease produces an unsigned APK,
// which is what reproducible-build verifiers and F-Droid's build server use.
val signingProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.isFile) {
        f.inputStream().use { load(it) }
    }
}

fun signingValue(key: String, env: String): String? =
    (signingProps.getProperty(key) ?: providers.environmentVariable(env).orNull)?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingValue("storeFile", "GF_KEYSTORE_FILE")

android {
    namespace = "app.goldfishsend"
    // 37.1 is required by tor-android. targetSdk (runtime behaviour) stays at 36.
    compileSdk {
        version = release(37) {
            minorApiLevel = 1
        }
    }
    // Pinned for reproducible builds: the build tools (aapt2, zipalign, d8) and the NDK (it strips the
    // prebuilt libsignal/sqlcipher .so files, so its version changes the packaged bytes).
    buildToolsVersion = "37.0.0"
    ndkVersion = "27.1.12297006"

    defaultConfig {
        applicationId = "app.goldfishsend"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // Deterministic: the APK depends only on this value, never on the build time or the VCS state.
        // Verifiers must build with the same -Pgf.defaultServer as the release (or none for the default).
        val defaultServer = (project.findProperty("gf.defaultServer") as String?) ?: "https://relay.goldfishsend.app"
        buildConfigField("String", "DEFAULT_SERVER_URL", "\"$defaultServer\"")
        // The default server's identity fingerprint (b64u, from the server's `fingerprint` command). Empty means the app
        // trusts that server's key on first use. Verifiers must use the same value as the release.
        val defaultServerKey = (project.findProperty("gf.defaultServerKey") as String?) ?: ""
        require(defaultServerKey.isEmpty() || Regex("^[A-Za-z0-9_-]{43}$").matches(defaultServerKey)) {
            "gf.defaultServerKey must be a 43-character base64url fingerprint"
        }
        buildConfigField("String", "DEFAULT_SERVER_KEY", "\"$defaultServerKey\"")
        // Only the arm64 / x86_64 native libs (libsignal, sqlcipher) are shipped.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            // -Pgf.abis=x86_64 builds a smaller APK for emulator testing. Releases use the default.
            abiFilters += ((project.findProperty("gf.abis") as String?)?.split(",") ?: listOf("arm64-v8a", "x86_64"))
        }
    }

    signingConfigs {
        if (releaseStoreFile != null) {
            create("release") {
                storeFile = file(releaseStoreFile)
                storePassword = signingValue("storePassword", "GF_KEYSTORE_PASSWORD")
                keyAlias = signingValue("keyAlias", "GF_KEY_ALIAS")
                keyPassword = signingValue("keyPassword", "GF_KEY_PASSWORD")
                // minSdk 29: v2+v3 cover every supported device. v3 enables future key rotation.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            buildConfigField("boolean", "ALLOW_HTTP", "true")
            // Install several debug copies side by side for multi-party testing on one device: -Pgf.debugIdSuffix=.a
            applicationIdSuffix = (project.findProperty("gf.debugIdSuffix") as String?) ?: ""
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("boolean", "ALLOW_HTTP", "false")
            if (releaseStoreFile != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            // No git commit/branch/state in the APK: it would differ between source tarballs and checkouts.
            vcsInfo.include = false
        }
    }

    // F-Droid rejects the "dependency metadata" block AGP otherwise embeds (encrypted with a Google key and
    // useless to anyone else). Leaving it out also removes a source of difference between builds.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/{AL2.0,LGPL2.1}",
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                // Desktop natives bundled in libsignal-client's jar.
                "libsignal_jni*.so",
                "libsignal_jni*.dylib",
                "signal_jni*.dll",
            )
        }
        jniLibs {
            useLegacyPackaging = false
            // libsignal ships a large test-only JNI library; never package it.
            excludes += setOf("**/libsignal_jni_testing.so")
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.animation:animation")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-process:2.11.0")
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    implementation("androidx.biometric:biometric:1.1.0")
    // biometric 1.1.0 pulls in fragment 1.2.5, whose FragmentActivity rejects the 32-bit request codes of the
    // Activity Result API (crash on the notification-permission request in onboarding). Pin a current fragment.
    implementation("androidx.fragment:fragment-ktx:1.9.1")
    implementation("androidx.datastore:datastore-preferences:1.2.1")

    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.4")

    implementation("org.signal:libsignal-android:0.107.0")
    implementation("org.unifiedpush.android:connector:3.3.5")
    implementation("net.zetetic:sqlcipher-android:4.20.0@aar")
    implementation("androidx.sqlite:sqlite:2.7.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    // Built-in Tor (optional, off by default). In-process TorService. It requests only INTERNET.
    implementation("info.guardianproject:tor-android:0.4.9.14")
    implementation("androidx.localbroadcastmanager:localbroadcastmanager:1.1.0")

    implementation("com.squareup.okhttp3:okhttp:5.5.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.5.1")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}

// libsignal-client's desktop classes (used by JVM unit tests) target Java 21.
tasks.withType<Test>().configureEach {
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) })
}
