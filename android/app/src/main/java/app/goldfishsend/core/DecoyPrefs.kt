package app.goldfishsend.core

import android.content.SharedPreferences
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.float
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** A small key-value store: a profile database's kv table, or a map in tests. */
interface KvStore {
    fun get(k: String): ByteArray?

    fun put(k: String, v: ByteArray?)
}

/**
 * The decoy profile's own settings. The decoy is a separate profile, so it gets its own copy of every setting: changes
 * made in it look real and stay in it, but never reach the real profile's preferences, network settings or vault.
 *
 * They're kept inside the decoy's encrypted database (kv [KEY]), not in a preference file, so nothing on disk says that a
 * decoy exists. A new decoy starts with defaults, except for the settings someone at the lock screen can already see or
 * feel (theme, keypad, auto-lock, the attempts-left warning, fingerprint unlock, connection mode): those start as the
 * real profile's, so opening the decoy doesn't visibly change anything.
 */
object DecoyPrefs {
    const val KEY = "decoy_prefs"

    /** gf_prefs keys copied into a new decoy. Everything else (wipe triggers, panic app, timers…) starts at its default. */
    val MIRRORED = setOf(
        "theme", "amoled", "dynamic_color", "flag_secure", "scramble_pin", "lock_timeout", "lock_screen_off", "max_failed",
        "wipe_memory_on_lock", "server_url", "server_key", "server_key_tofu",
    )

    /**
     * Opens the decoy's settings from [kv]. The first time, [seed] supplies the starting values (see [mirror]) and they
     * are saved straight away, so later changes to the real profile never show through.
     */
    fun open(kv: KvStore, seed: () -> Map<String, Any?>): Prefs {
        val stored = kv.get(KEY)?.let { runCatching { decode(it) }.getOrNull() }
        val store = MapPreferences(stored ?: seed().filterValues { it != null }.mapValues { it.value!! }) { kv.put(KEY, encode(it)) }
        if (stored == null) {
            store.edit().commit()
        }
        return Prefs(store)
    }

    /** The real settings a new decoy starts with: [MIRRORED] keys from [real], plus [extra] (computed elsewhere). */
    fun mirror(real: Map<String, *>, extra: Map<String, Any?>): Map<String, Any?> =
        real.filterKeys { it in MIRRORED } + extra

    internal fun encode(m: Map<String, Any>): ByteArray {
        val o = JsonObject(
            m.mapValues { (_, v) ->
                when (v) {
                    is Boolean -> JsonArray(listOf(JsonPrimitive("b"), JsonPrimitive(v)))
                    is Int -> JsonArray(listOf(JsonPrimitive("i"), JsonPrimitive(v)))
                    is Long -> JsonArray(listOf(JsonPrimitive("l"), JsonPrimitive(v)))
                    is Float -> JsonArray(listOf(JsonPrimitive("f"), JsonPrimitive(v)))
                    is String -> JsonArray(listOf(JsonPrimitive("s"), JsonPrimitive(v)))
                    is Set<*> -> JsonArray(listOf(JsonPrimitive("S"), JsonArray(v.map { JsonPrimitive(it as String) })))
                    else -> error("unsupported preference type")
                }
            },
        )
        return o.toString().toByteArray(Charsets.UTF_8)
    }

    internal fun decode(b: ByteArray): Map<String, Any> {
        val o = app.goldfishsend.proto.ProtoJson.parseToJsonElement(b.toString(Charsets.UTF_8)).jsonObject
        return o.mapValues { (_, e) ->
            val a = e.jsonArray
            val v = a[1]
            when (a[0].jsonPrimitive.content) {
                "b" -> v.jsonPrimitive.boolean
                "i" -> v.jsonPrimitive.int
                "l" -> v.jsonPrimitive.long
                "f" -> v.jsonPrimitive.float
                "s" -> v.jsonPrimitive.content
                "S" -> v.jsonArray.map { it.jsonPrimitive.content }.toSet()
                else -> error("unknown preference type")
            }
        }
    }
}

/** SharedPreferences over a map, saved through [persist] on every change. Only what [Prefs] needs is meaningful. */
class MapPreferences(initial: Map<String, Any>, private val persist: (Map<String, Any>) -> Unit) : SharedPreferences {
    private val values = HashMap(initial)
    private val listeners = mutableSetOf<SharedPreferences.OnSharedPreferenceChangeListener>()

    @Synchronized
    override fun getAll(): Map<String, *> = HashMap(values)

    @Synchronized
    override fun getString(key: String, defValue: String?): String? = values[key] as? String ?: defValue

    @Suppress("UNCHECKED_CAST")
    @Synchronized
    override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? = (values[key] as? Set<String>)?.toSet() ?: defValues

    @Synchronized
    override fun getInt(key: String, defValue: Int): Int = values[key] as? Int ?: defValue

    @Synchronized
    override fun getLong(key: String, defValue: Long): Long = values[key] as? Long ?: defValue

    @Synchronized
    override fun getFloat(key: String, defValue: Float): Float = values[key] as? Float ?: defValue

    @Synchronized
    override fun getBoolean(key: String, defValue: Boolean): Boolean = values[key] as? Boolean ?: defValue

    @Synchronized
    override fun contains(key: String): Boolean = key in values

    override fun edit(): SharedPreferences.Editor = Editor()

    override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) {
        listeners += l
    }

    override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) {
        listeners -= l
    }

    private inner class Editor : SharedPreferences.Editor {
        private val puts = HashMap<String, Any?>()
        private var clear = false

        override fun putString(key: String, value: String?): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun putStringSet(key: String, values: Set<String>?): SharedPreferences.Editor {
            puts[key] = values?.toSet()
            return this
        }

        override fun putInt(key: String, value: Int): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun putLong(key: String, value: Long): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun putFloat(key: String, value: Float): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun remove(key: String): SharedPreferences.Editor {
            puts[key] = null
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }

        override fun commit(): Boolean {
            val snapshot = synchronized(this@MapPreferences) {
                if (clear) {
                    values.clear()
                }
                for ((k, v) in puts) {
                    if (v == null) values.remove(k) else values[k] = v
                }
                HashMap(values)
            }
            // The decoy's database may already be closed (a late write after locking): the change is simply dropped.
            return runCatching { persist(snapshot) }.isSuccess
        }

        override fun apply() {
            commit()
        }
    }
}

/** A profile database's kv table as a [KvStore]. */
class RepoKv(private val repo: app.goldfishsend.db.Repo) : KvStore {
    override fun get(k: String): ByteArray? = repo.kvGet(k)

    override fun put(k: String, v: ByteArray?) = repo.kvPut(k, v)
}
