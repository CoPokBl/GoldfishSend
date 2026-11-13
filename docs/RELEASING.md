# Releasing the Android app

The release build is reproducible. Anyone can rebuild an unsigned APK from the tagged source and check that it
matches the published one byte for byte, apart from the signature. The signing key is therefore the only thing users
have to trust, and its fingerprint must be published widely and never change casually.

## 1. Generate the release key (once, offline)

Do this on an offline or freshly installed machine, or keep the key on a hardware token. Never on a CI runner.

```bash
keytool -genkeypair -v \
  -keystore goldfishsend-release.jks -storetype PKCS12 \
  -alias goldfishsend -keyalg RSA -keysize 4096 -sigalg SHA256withRSA \
  -validity 18250 \
  -dname "CN=GoldfishSend"
```

- Use a long random store password (PKCS12 uses the same password for the key).
- `-validity 18250` is 50 years. Android requires certificates to stay valid for the app's lifetime.
- Keep at least two **encrypted, offline** backups (for example a LUKS USB stick and a password-manager attachment).
  Losing the key means existing users can never receive updates. Leaking it means someone else can.
- Never commit `*.jks`, `*.keystore` or `keystore.properties`. They are in `.gitignore`.

## 2. Configure signing (optional and local)

The Gradle build signs releases **only if** signing is configured. Otherwise `assembleRelease` produces
`app-release-unsigned.apk`, which is what verifiers and F-Droid's build server use.

Either create `android/keystore.properties` (untracked):

```properties
storeFile=/absolute/path/to/goldfishsend-release.jks
storePassword=...
keyAlias=goldfishsend
keyPassword=...
```

or set environment variables: `GF_KEYSTORE_FILE`, `GF_KEYSTORE_PASSWORD`, `GF_KEY_ALIAS` and `GF_KEY_PASSWORD`.
The release is signed with APK Signature Scheme v3. v1 is off, and AGP omits v2 because minSdk 29 means every device verifies v3.

## 3. Build

```bash
cd android
./gradlew clean :app:assembleRelease -Pgf.defaultServer=https://your.relay.example
# app/build/outputs/apk/release/app-release.apk
```

Record the exact `-Pgf.defaultServer` value in the release notes. Verifiers need it to reproduce the build.

## 4. Print and publish the signing-certificate fingerprint

```bash
$ANDROID_HOME/build-tools/37.0.0/apksigner verify --print-certs --verbose app/build/outputs/apk/release/app-release.apk \
  | grep -E 'certificate SHA-256 digest'
# or, from the keystore:
keytool -list -v -keystore goldfishsend-release.jks -alias goldfishsend | grep SHA256
```

Publish the SHA-256 (it never changes between releases) in:

- `android/README.md`, "Verifying your download"
- the project website and every release note
- a signed git tag (`git tag -s v0.1.0`)
- the F-Droid recipe's `AllowedAPKSigningKeys` (lower-case hex, no colons)

## 5. How users verify an APK

- **AppVerifier** (open source, on F-Droid and Accrescent): share the APK or the installed app to it and compare it with the
  published fingerprint.
- **apksigner**: `apksigner verify --print-certs app.apk`, then compare the SHA-256 digest.
- **Obtainium and F-Droid** check the signature on every update and refuse a key change. Pin the fingerprint in Obtainium.

## 6. Verifying a release is reproducible

From the tagged commit, with JDK 21 for Gradle and a JDK 17 toolchain installed, Android build-tools 37.0.0 and
NDK 27.1.12297006 (both pinned in `app/build.gradle.kts`):

```bash
cd android
./gradlew --no-build-cache clean :app:assembleRelease -Pgf.defaultServer=<value from the release notes>
# compare the published signed APK with your unsigned one, ignoring only the signature:
pip install apksigcopier          # needs apksigner on PATH, e.g. export PATH=$ANDROID_HOME/build-tools/37.0.0:$PATH
apksigcopier compare goldfishsend-0.1.0.apk --unsigned app/build/outputs/apk/release/app-release-unsigned.apk && echo REPRODUCIBLE
```

`apksigcopier` copies the signature from the published APK onto your unsigned build and compares the result. If
they differ, `diffoscope goldfishsend-0.1.0.apk app/build/outputs/apk/release/app-release-unsigned.apk` shows where.

## 7. Updating dependencies

All artifacts and their SHA-256 checksums are pinned in `android/gradle/verification-metadata.xml`. Builds fail if a
downloaded artifact doesn't match. After changing a dependency version:

```bash
cd android
./gradlew --write-verification-metadata sha256 \
  :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest :app:lintDebug :app:lintRelease :app:assembleDebugAndroidTest
git diff gradle/verification-metadata.xml   # review: only the artifacts you changed should appear
```

Never regenerate the file just to make an unexplained mismatch go away. A changed checksum for an existing version
means the artifact was altered.

There is deliberately no dependency lock file. Every version in `app/build.gradle.kts` is fixed (no ranges or
`+`), so resolution is already deterministic, and the verification metadata pins the exact bytes.

## 8. Key rotation (only if the key is compromised or weak)

APK Signature Scheme v3 supports rotation on Android 9+ (all supported devices). Create a lineage that proves the old
key authorised the new one, then sign with both:

```bash
apksigner rotate --out lineage.bin \
  --old-signer --ks old.jks --ks-key-alias goldfishsend \
  --new-signer --ks new.jks --ks-key-alias goldfishsend2
apksigner sign --ks old.jks --next-signer --ks new.jks --lineage lineage.bin app-release-unsigned.apk
```

AGP can't sign with a lineage, so sign these releases manually with `apksigner`. Publish the new fingerprint
alongside the old one, explain why it changed, and update `AllowedAPKSigningKeys`.
