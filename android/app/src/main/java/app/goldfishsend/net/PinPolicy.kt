package app.goldfishsend.net

import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.Base64

/**
 * Trust-on-first-use pinning of a server's TLS key. The pin is the SHA-256 of the leaf certificate's
 * SubjectPublicKeyInfo, which is what this command prints:
 *
 *     openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null \
 *       | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
 *       | openssl dgst -sha256 -binary | openssl enc -base64
 *
 * Only the leaf key is pinned. Pinning the intermediate as well would accept any certificate from the same CA
 * (for Let's Encrypt, millions of sites), which defeats the purpose. Servers should keep their key across
 * renewals (Caddy: `reuse_private_keys`).
 */
object PinPolicy {
    sealed interface Decision {
        /** Pinning is off, or the server is an onion service (the onion address is already the key). */
        data object Skip : Decision

        /** First contact with this server: remember [pin] and continue. */
        data class RecordFirst(val pin: String) : Decision

        data object Accept : Decision

        /** The key changed. Fail closed and ask the user. */
        data class Mismatch(val expected: Set<String>, val presented: String) : Decision
    }

    /**
     * @param stored pins previously recorded for this host, or null/empty if none.
     * @param presented the pin of the certificate presented now.
     */
    fun decide(enabled: Boolean, onion: Boolean, stored: Set<String>?, presented: String): Decision = when {
        !enabled || onion -> Decision.Skip
        stored.isNullOrEmpty() -> Decision.RecordFirst(presented)
        presented in stored -> Decision.Accept
        else -> Decision.Mismatch(stored, presented)
    }

    fun pinOf(cert: Certificate): String = pinOfSpki(cert.publicKey.encoded)

    /** `sha256/<base64>`, the same format OkHttp's CertificatePinner uses. */
    fun pinOfSpki(spkiDer: ByteArray): String =
        "sha256/" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(spkiDer))

    /** The base64 part only, matching the openssl command's output for comparison by eye. */
    fun displayFingerprint(pin: String): String = pin.removePrefix("sha256/")

    /** The key used for a server in the pin store: host plus port, lower-cased. */
    fun hostKey(host: String, port: Int): String = "${host.lowercase()}:$port"
}
