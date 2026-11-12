package app.goldfishsend.ui.components

import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView

enum class FieldKind { TEXT, MESSAGE, PASSWORD, NUMBER_PASSWORD, URI }

/**
 * Text input that sets IME_FLAG_NO_PERSONALIZED_LEARNING ("incognito keyboard"), which Compose text fields can't do.
 * It's a themed platform EditText, so all of GoldfishSend's text entry asks the keyboard not to learn or store typing.
 */
@Composable
fun SecureTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    hint: String = "",
    kind: FieldKind = FieldKind.TEXT,
    maxLines: Int = 1,
    shape: Shape = MaterialTheme.shapes.medium,
    container: Color = MaterialTheme.colorScheme.surfaceContainerHigh,
    imeAction: Int = EditorInfo.IME_ACTION_DONE,
    onImeAction: (() -> Unit)? = null,
    requestFocus: Boolean = false,
) {
    val textColor = MaterialTheme.colorScheme.onSurface.toArgb()
    val hintColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f).toArgb()
    val accent = MaterialTheme.colorScheme.primary.toArgb()
    val holder = remember { arrayOfNulls<EditText>(1) }
    Box(
        modifier
            .background(container, shape)
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 4.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        AndroidView(
            modifier = Modifier.fillMaxWidth(),
            factory = { ctx ->
                EditText(ctx).apply {
                    holder[0] = this
                    background = null
                    setPadding(0, 18, 0, 18)
                    setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
                    gravity = Gravity.CENTER_VERTICAL or Gravity.START
                    importantForAutofill = if (kind == FieldKind.PASSWORD || kind == FieldKind.NUMBER_PASSWORD) {
                        View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                    } else {
                        View.IMPORTANT_FOR_AUTOFILL_NO
                    }
                    inputType = when (kind) {
                        FieldKind.TEXT -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
                        FieldKind.MESSAGE -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                            InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
                        FieldKind.PASSWORD -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or
                            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                        FieldKind.NUMBER_PASSWORD -> InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
                        FieldKind.URI -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or
                            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                    }
                    imeOptions = (if (kind == FieldKind.MESSAGE) EditorInfo.IME_ACTION_NONE else imeAction) or
                        EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
                    if (maxLines > 1) {
                        isSingleLine = false
                        this.maxLines = maxLines
                    } else {
                        isSingleLine = true
                    }
                    setText(value)
                    addTextChangedListener(object : TextWatcher {
                        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
                        override fun afterTextChanged(s: Editable?) {
                            val t = s?.toString().orEmpty()
                            if (t != (tag as? String)) {
                                tag = t
                                onValueChange(t)
                            }
                        }
                    })
                    setOnEditorActionListener { _, _, _ ->
                        onImeAction?.invoke()
                        onImeAction != null
                    }
                    if (requestFocus) {
                        post {
                            requestFocus()
                            val imm = ctx.getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                            imm.showSoftInput(this, 0)
                        }
                    }
                }
            },
            update = { et ->
                et.setTextColor(textColor)
                et.setHintTextColor(hintColor)
                et.hint = hint
                if (android.os.Build.VERSION.SDK_INT >= 29) {
                    et.textCursorDrawable?.setTint(accent)
                }
                et.highlightColor = (accent and 0x00FFFFFF) or 0x55000000
                if (et.text.toString() != value) {
                    et.tag = value
                    et.setText(value)
                    et.setSelection(value.length)
                }
            },
        )
    }
    DisposableEffect(Unit) {
        onDispose {
            // Don't leave secrets in the EditText's buffer.
            if (kind == FieldKind.PASSWORD || kind == FieldKind.NUMBER_PASSWORD) {
                holder[0]?.text?.clear()
            }
            holder[0] = null
        }
    }
}
