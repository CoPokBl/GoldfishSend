package app.goldfishsend.db

import android.database.Cursor

/** [Tables] over the SQLCipher database. Table and column names are the code's own, never input. */
class DbTables(private val db: Db) : Tables {
    private fun row(c: Cursor): Row {
        val out = LinkedHashMap<String, Any?>()
        for (i in 0 until c.columnCount) {
            out[c.getColumnName(i)] = when (c.getType(i)) {
                Cursor.FIELD_TYPE_NULL -> null
                Cursor.FIELD_TYPE_INTEGER -> c.getLong(i)
                Cursor.FIELD_TYPE_FLOAT -> c.getDouble(i)
                Cursor.FIELD_TYPE_BLOB -> c.getBlob(i)
                else -> c.getString(i)
            }
        }
        return out
    }

    /** The WHERE clauses for [w]: more than one when an IN list has to be split (SQLite takes at most 999 arguments). */
    private fun clauses(w: Where): List<Pair<String, Array<Any?>>> = when (w) {
        Where.All -> listOf("1" to emptyArray())
        is Where.Prefix -> listOf("substr(${w.col}, 1, ?) = ?" to arrayOf(w.prefix.length, w.prefix))
        is Where.In -> w.values.toList().chunked(500).map { part ->
            "${w.col} IN (${part.joinToString(",") { "?" }})" to part.toTypedArray<Any?>()
        }
    }

    override fun select(table: String, where: Where): List<Row> =
        clauses(where).flatMap { (clause, args) -> db.query("SELECT * FROM $table WHERE $clause", *args, map = ::row) }

    override fun delete(table: String, where: Where) {
        for ((clause, args) in clauses(where)) {
            db.exec("DELETE FROM $table WHERE $clause", *args)
        }
    }

    override fun insert(table: String, row: Row, orIgnore: Boolean): Long? {
        val cols = row.keys.toList()
        val id = db.insert(
            "INSERT ${if (orIgnore) "OR IGNORE " else ""}INTO $table (${cols.joinToString(",")}) VALUES (${cols.joinToString(",") { "?" }})",
            *cols.map { row[it] }.toTypedArray(),
        )
        return id.takeIf { it != -1L }
    }
}
