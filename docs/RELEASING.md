# Releasing the Android app

The release build is reproducible. Anyone can rebuild an unsigned APK from the tagged source and check that it
matches the published one byte for byte, apart from the signature. The signing key is therefore the only thing users
have to trust, and its fingerprint must be published widely and never change casually.

## 1. Generate the release key (once, offline)

Generate it on an offline or freshly installed machine, never on a CI runner. GitHub Actions only receives a copy as
an environment secret so it can sign automatic releases (section 3).

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

## 3. Automatic releases (GitHub Actions and Obtainium)

`.github/workflows/ci.yml` runs on pull requests and on pushes to any branch except `main`. It runs the server's
formatting check and tests against MySQL and Redis, a short load test, and a build of the server image. For the app it
runs the unit tests, lint, the debug and (unsigned) release builds, compiles the baseline-profile generator, and runs
the device tests on an emulator.

`.github/workflows/release.yml` runs on every push to `main`. It reruns CI, then:

- publishes the server image to `ghcr.io/<owner>/goldfishsend` as `latest`, `<version>` and `sha-<commit>`, for
  `linux/amd64` and `linux/arm64`, with a build provenance attestation;
- if anything under `android/` or `.github/` changed since the last `v*` tag (or when you run it by hand with
  **force**), builds the signed APK, checks it was signed with the expected certificate, attests its build provenance,
  and creates a GitHub release `v<version>` with `goldfishsend-<version>.apk` and its SHA-256. The release notes list
  the commits since the previous release, the signing fingerprint, and the exact command to reproduce the build.

The version is `0.1.<number of commits on main>`, and the version code is that commit count, so every release is
higher than the last. Change `VERSION_BASE` in `release.yml` for a new minor or major version.

### One-time setup

In the repository settings, under **Environments**, create an environment named `release` and limit its
deployment branches to `main`. Add these **secrets** to it:

| Secret | Value |
|---|---|
| `GF_KEYSTORE_BASE64` | `base64 -w0 goldfishsend-release.jks` |
| `GF_KEYSTORE_PASSWORD` | the store password |
| `GF_KEY_PASSWORD` | optional; the key password if it differs from the store password (PKCS12 keys normally don't) |

and these **variables** (to the environment, or as repository variables):

| Variable | Value |
|---|---|
| `GF_SIGNING_CERT_SHA256` | the certificate fingerprint from section 5, with or without colons. The release fails if the APK was signed with any other key. |
| `GF_DEFAULT_SERVER` | the app's default server, e.g. `https://push.example.com` |
| `GF_DEFAULT_SERVER_KEY` | that server's identity fingerprint (`docker compose run --rm --no-deps api fingerprint` on the server; see "Server identity" in `server/README.md`). Leave it empty to trust the server's key on first use; the release then warns. |
| `GF_KEY_ALIAS` | optional, default `goldfishsend` |

The release job fails with a list of what's missing until all of these are set. Server image publishing needs no setup.
After the first image push, the package is private: under the package's settings, make it public if others should
pull it.

Putting the key in GitHub means anyone who takes over the GitHub account, or a compromised action in the release job,
could sign an update. The environment's branch rule keeps the secrets away from pull requests and other branches. Turn
on two-factor authentication. If you'd rather keep the key offline, delete the `app` job from `release.yml` and build
and upload releases by hand (section 4).

### Installing with Obtainium

In Obtainium, add the app from `https://github.com/<owner>/<repo>`. The defaults work: each release has one APK, and
the tag (`v0.1.123`) matches the app's version (`0.1.123`). Obtainium checks that every update is signed by the same key
as the installed app. Compare the fingerprint in the release notes with the published one when you first install.

## 4. Build by hand

```bash
cd android
./gradlew clean :app:assembleRelease -Pgf.defaultServer=https://push.example.com \
  -Pgf.defaultServerKey=<fingerprint> -Pgf.versionCode=<n> -Pgf.versionName=0.1.<n>
# app/build/outputs/apk/release/app-release.apk
```

Record every `-P` value in the release notes. Verifiers need them to reproduce the build.

## 5. Print and publish the signing-certificate fingerprint

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

## 6. How users verify an APK

- **AppVerifier** (open source, on F-Droid and Accrescent): share the APK or the installed app to it and compare it with the
  published fingerprint.
- **apksigner**: `apksigner verify --print-certs app.apk`, then compare the SHA-256 digest.
- **Obtainium and F-Droid** check the signature on every update and refuse a key change. Pin the fingerprint in Obtainium.

## 7. Verifying a release is reproducible

From the tagged commit, with JDK 21 for Gradle and a JDK 17 toolchain installed, Android build-tools 37.0.0 and
NDK 27.1.12297006 (both pinned in `app/build.gradle.kts`):

```bash
cd android
./gradlew --no-build-cache clean :app:assembleRelease <the -P values from the release notes>
# compare the published signed APK with your unsigned one, ignoring only the signature:
pip install apksigcopier          # needs apksigner on PATH, e.g. export PATH=$ANDROID_HOME/build-tools/37.0.0:$PATH
apksigcopier compare goldfishsend-0.1.0.apk --unsigned app/build/outputs/apk/release/app-release-unsigned.apk && echo REPRODUCIBLE
```

`apksigcopier` copies the signature from the published APK onto your unsigned build and compares the result. If
they differ, `diffoscope goldfishsend-0.1.0.apk app/build/outputs/apk/release/app-release-unsigned.apk` shows where.

## 8. Updating dependencies

All artifacts and their SHA-256 checksums are pinned in `android/gradle/verification-metadata.xml`. Builds fail if a
downloaded artifact doesn't match. After changing a dependency version:

```bash
cd android
./gradlew --write-verification-metadata sha256 \
  :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest :app:lintDebug :app:lintRelease :app:assembleDebugAndroidTest \
  :app:assembleBenchmarkRelease :app:assembleNonMinifiedRelease \
  :baselineprofile:assembleBenchmarkRelease :baselineprofile:assembleNonMinifiedRelease
git diff gradle/verification-metadata.xml   # review: only the artifacts you changed should appear
```

Never regenerate the file just to make an unexplained mismatch go away. A changed checksum for an existing version
means the artifact was altered.

There is deliberately no dependency lock file. Every version in `app/build.gradle.kts` is fixed (no ranges or
`+`), so resolution is already deterministic, and the verification metadata pins the exact bytes.

## 9. Key rotation (only if the key is compromised or weak)

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
