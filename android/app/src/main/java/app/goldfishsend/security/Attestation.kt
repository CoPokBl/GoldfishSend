package app.goldfishsend.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.goldfishsend.proto.Rand
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject

/**
 * Keystore key attestation, used as the primary verified-boot signal in the Security tab.
 *
 * `ro.boot.verifiedbootstate` and friends are ordinary system properties, which root hiders (Magisk, KernelSU,
 * resetprop) routinely spoof. Key attestation instead asks the secure hardware (TEE or StrongBox) to sign a statement
 * that includes the boot state and bootloader lock as the hardware saw them at boot. No permission is needed.
 *
 * Limits: this check runs on the device itself and doesn't verify the certificate chain up to Google's root, so a fully
 * compromised OS could still lie to the app. It's far stronger than reading properties, but it's not remote attestation.
 * Software-only (emulator) attestation is ignored.
 */
object Attestation {
    data class RootOfTrust(val verifiedBootState: Int, val deviceLocked: Boolean) {
        companion object {
            const val VERIFIED = 0
            const val SELF_SIGNED = 1
            const val UNVERIFIED = 2
            const val FAILED = 3
        }
    }

    private const val ALIAS = "gf_attest"
    private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val TAG_ROOT_OF_TRUST = 704

    @Volatile
    private var cached: RootOfTrust? = null

    @Volatile
    private var tried = false

    /** Null when attestation isn't available or isn't hardware-backed. The result is cached per process. */
    fun rootOfTrust(): RootOfTrust? {
        if (tried) {
            return cached
        }
        cached = runCatching { attest() }.getOrNull()
        tried = true
        return cached
    }

    private fun attest(): RootOfTrust? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            gen.initialize(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(Rand.bytes(16))
                    .build(),
            )
            gen.generateKeyPair()
            val leaf = ks.getCertificateChain(ALIAS)?.firstOrNull() as? X509Certificate ?: return null
            val ext = leaf.getExtensionValue(KEY_DESCRIPTION_OID) ?: return null
            return parse(ASN1OctetString.getInstance(ext).octets)
        } finally {
            runCatching { ks.deleteEntry(ALIAS) }
        }
    }

    /**
     * KeyDescription ::= SEQUENCE { attestationVersion, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel,
     * attestationChallenge, uniqueId, softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }.
     * RootOfTrust ([704] in hardwareEnforced) ::= SEQUENCE { verifiedBootKey, deviceLocked BOOLEAN, verifiedBootState ENUMERATED, ... }
     */
    internal fun parse(keyDescription: ByteArray): RootOfTrust? {
        val seq = ASN1Primitive.fromByteArray(keyDescription) as? ASN1Sequence ?: return null
        val securityLevel = (seq.getObjectAt(1) as? ASN1Enumerated)?.value?.toInt() ?: return null
        if (securityLevel == 0) {
            // Software keystore: says nothing about the real boot state.
            return null
        }
        val hw = seq.getObjectAt(7) as? ASN1Sequence ?: return null
        for (entry in hw) {
            val tagged = entry as? ASN1TaggedObject ?: continue
            if (tagged.tagNo != TAG_ROOT_OF_TRUST) {
                continue
            }
            val rot = tagged.baseObject.toASN1Primitive() as? ASN1Sequence ?: return null
            val locked = (rot.getObjectAt(1) as? ASN1Boolean)?.isTrue ?: return null
            val state = (rot.getObjectAt(2) as? ASN1Enumerated)?.value?.toInt() ?: return null
            return RootOfTrust(state, locked)
        }
        return null
    }
}
