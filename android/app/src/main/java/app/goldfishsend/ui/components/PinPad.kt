package app.goldfishsend.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Backspace
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import java.security.SecureRandom

/**
 * Holds PIN digits outside of Compose strings, so they can be zeroed. Strings are immutable and can't be wiped.
 */
class PinBuffer(private val maxLength: Int = 32) {
    private val digits = CharArray(maxLength)
    var length by mutableIntStateOf(0)
        private set

    fun push(c: Char) {
        if (length < maxLength) {
            digits[length] = c
            length++
        }
    }

    fun pop() {
        if (length > 0) {
            length--
            digits[length] = '\u0000'
        }
    }

    /** A copy for the caller (which must wipe it). The buffer is cleared. */
    fun take(): CharArray {
        val out = digits.copyOf(length)
        clear()
        return out
    }

    fun clear() {
        digits.fill('\u0000')
        length = 0
    }
}

/**
 * GoldfishSend's own PIN keypad. The system keyboard (which may be closed source) never sees what's typed.
 *
 * @param scrambled shuffles the digit positions each time the pad appears (against shoulder-surfing and smudge
 *   attacks). Off by default, because it slows down entry.
 * @param minLength the shortest PIN the confirm key accepts.
 */
@Composable
fun PinPad(
    buffer: PinBuffer,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
    scrambled: Boolean = false,
    minLength: Int = 6,
    enabled: Boolean = true,
) {
    val haptics = LocalHapticFeedback.current
    val order = remember(scrambled) {
        val d = ('0'..'9').toMutableList()
        if (scrambled) {
            d.shuffle(SecureRandom())
            d
        } else {
            "1234567890".toMutableList()
        }
    }
    DisposableEffect(Unit) {
        onDispose { buffer.clear() }
    }

    Column(modifier.widthIn(max = 340.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        // Dots only, never the digits themselves.
        Row(
            Modifier.height(24.dp).semantics { contentDescription = "${buffer.length} digits entered" },
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            repeat(maxOf(buffer.length, minLength)) { i ->
                val filled = i < buffer.length
                Box(
                    Modifier.size(if (filled) 14.dp else 10.dp).background(
                        if (filled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                        CircleShape,
                    ),
                )
            }
        }
        Spacer(Modifier.height(20.dp))
        val rows = listOf(order.subList(0, 3), order.subList(3, 6), order.subList(6, 9))
        for (row in rows) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                for (d in row) {
                    Key(d.toString(), enabled) {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        buffer.push(d)
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly, verticalAlignment = Alignment.CenterVertically) {
            FilledTonalIconButton(
                onClick = { buffer.pop() },
                enabled = enabled && buffer.length > 0,
                modifier = Modifier.size(72.dp),
            ) { Icon(Icons.AutoMirrored.Rounded.Backspace, "Delete") }
            Key(order[9].toString(), enabled) {
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                buffer.push(order[9])
            }
            FilledTonalIconButton(
                onClick = onSubmit,
                enabled = enabled && buffer.length >= minLength,
                modifier = Modifier.size(72.dp),
                colors = IconButtonDefaults.filledTonalIconButtonColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            ) { Icon(Icons.Rounded.Check, "Done") }
        }
    }
}

@Composable
private fun Key(label: String, enabled: Boolean, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = CircleShape,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.size(72.dp).aspectRatio(1f),
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(label, style = MaterialTheme.typography.headlineMedium)
        }
    }
}
