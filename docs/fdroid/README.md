# Distributing GoldfishSend through F-Droid

`app.goldfishsend.yml` is a draft fdroiddata recipe. The app has **no proprietary dependencies**. The resolved
`releaseRuntimeClasspath` contains only AndroidX, Kotlin/KotlinX, OkHttp/Okio, BouncyCastle, ZXing, Guava and
friends, Tink (inside the UnifiedPush connector), protobuf, gson, SQLCipher, the UnifiedPush connector, and
libsignal. None of it is Google Play Services, Firebase, ML Kit, analytics or ad SDKs, and no permission requires
Google services. Notifications use UnifiedPush.

The app builds **reproducibly** (see `android/README.md`, "Reproducible builds"), so F-Droid can verify its build against
the developer-signed APK and publish the developer's signature (`Binaries:` + `AllowedAPKSigningKeys:`).

## The blocker: prebuilt native libraries

| Library | Where it comes from | Native code in the APK |
|---|---|---|
| `org.signal:libsignal-android` | Signal's Maven repository (`build-artifacts.signal.org`), not allowlisted by F-Droid | `libsignal_jni.so` (Rust, AGPL-3.0, prebuilt) |
| `net.zetetic:sqlcipher-android` | Maven Central | `libsqlcipher.so` (C, BSD-style, prebuilt) |
| AndroidX (graphics-path, datastore, camera) | Google Maven (allowlisted) | small helper `.so` files, built by Google from AOSP sources |

F-Droid's inclusion policy requires that everything, native code included, is built from source on its build
server. Its scanner will flag the Signal repository and the prebuilt `.so` files. Ways forward:

1. **Main F-Droid repository: build libsignal (and SQLCipher) from source.**
   Add `libsignal` as a srclib pinned to the same tag as the Gradle dependency (`v0.107.0`). Install the Rust
   toolchain from libsignal's `rust-toolchain` file and `cargo-ndk`, build the Android JNI library, and publish
   the resulting AAR to a local Maven repo used in place of Signal's. Do the same for SQLCipher's
   `sqlcipher-android` (its repo has an NDK build). This is the most work, and Rust builds make reproducibility
   harder: both Rust and the NDK must be pinned exactly. Signal itself isn't on F-Droid, and Molly ships through its
   own F-Droid repository partly for this reason.
2. **Own F-Droid repository.** Run `fdroid` yourself, publish the reproducibly built, developer-signed APK, and give
   users the repo URL and fingerprint. Users still get F-Droid's update mechanism, and anyone can verify the APK
   against the source.
3. **IzzyOnDroid.** It distributes developer-built APKs, scans them for proprietary libraries and trackers, and
   runs its own reproducible-build verification. Prebuilt FOSS native libraries are generally accepted there.
   It's the quickest path to F-Droid clients.

Recommendation: start with 2 or 3, which works today because the build is already reproducible, and work towards 1.

## Fastlane metadata

Store texts are in `android/fastlane/metadata/android/en-US/` (title, short and full description, changelogs named
by `versionCode`). F-Droid reads fastlane metadata from the repository. If it isn't picked up from `android/`,
move the `fastlane/` directory to the repository root. Add screenshots under `images/phoneScreenshots/` when
there are any.

## Before submitting

- Replace the placeholders in `app.goldfishsend.yml` (repository URL, default relay, signing-key SHA-256).
- Tag the release commit (`v<versionName>`) and attach the signed APK at the `Binaries:` URL.
- Run `fdroid lint app.goldfishsend` and `fdroid build -v -l app.goldfishsend` in an fdroiddata checkout.
- Check F-Droid's category list. The "Internet" and "Security" choices may need updating to the current taxonomy.
