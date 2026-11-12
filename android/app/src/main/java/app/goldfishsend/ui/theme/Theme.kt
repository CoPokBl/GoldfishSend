package app.goldfishsend.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import app.goldfishsend.core.ThemeMode

// Fallback palette (no Material You): warm goldfish orange with a deep teal accent.
private val LightFallback = lightColorScheme(
    primary = Color(0xFF9A4A00),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFFFDCC4),
    onPrimaryContainer = Color(0xFF321300),
    secondary = Color(0xFF755846),
    secondaryContainer = Color(0xFFFFDCC4),
    onSecondaryContainer = Color(0xFF2B1709),
    tertiary = Color(0xFF00696E),
    tertiaryContainer = Color(0xFF9CF0F6),
    onTertiaryContainer = Color(0xFF002022),
    background = Color(0xFFFFFBF7),
    surface = Color(0xFFFFFBF7),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFFFF1E9),
    surfaceContainer = Color(0xFFFAEBE2),
    surfaceContainerHigh = Color(0xFFF4E5DC),
    surfaceContainerHighest = Color(0xFFEFE0D7),
    error = Color(0xFFBA1A1A),
)

private val DarkFallback = darkColorScheme(
    primary = Color(0xFFFFB781),
    onPrimary = Color(0xFF532200),
    primaryContainer = Color(0xFF763300),
    onPrimaryContainer = Color(0xFFFFDCC4),
    secondary = Color(0xFFE5BFA9),
    secondaryContainer = Color(0xFF5B4130),
    onSecondaryContainer = Color(0xFFFFDCC4),
    tertiary = Color(0xFF80D4DA),
    tertiaryContainer = Color(0xFF004F53),
    onTertiaryContainer = Color(0xFF9CF0F6),
    background = Color(0xFF1A120D),
    surface = Color(0xFF1A120D),
    surfaceContainerLowest = Color(0xFF140D08),
    surfaceContainerLow = Color(0xFF221A14),
    surfaceContainer = Color(0xFF271E18),
    surfaceContainerHigh = Color(0xFF322822),
    surfaceContainerHighest = Color(0xFF3D332C),
    error = Color(0xFFFFB4AB),
)

private fun ColorScheme.amoled(): ColorScheme = copy(
    background = Color.Black,
    surface = Color.Black,
    surfaceContainerLowest = Color.Black,
    surfaceContainerLow = Color(0xFF0B0B0B),
    surfaceContainer = Color(0xFF111111),
    surfaceContainerHigh = Color(0xFF181818),
    surfaceContainerHighest = Color(0xFF202020),
)

private val AppTypography = Typography().let { t ->
    t.copy(
        headlineLarge = t.headlineLarge.copy(fontWeight = FontWeight.SemiBold),
        headlineMedium = t.headlineMedium.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = t.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = t.titleMedium.copy(fontWeight = FontWeight.Medium),
        bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 22.sp, letterSpacing = 0.15.sp),
    )
}

private val AppShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

@Composable
fun GoldfishTheme(mode: ThemeMode, amoled: Boolean, dynamic: Boolean, content: @Composable () -> Unit) {
    val dark = when (mode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    val ctx = LocalContext.current
    val base = when {
        dynamic && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> DarkFallback
        else -> LightFallback
    }
    val scheme = if (dark && amoled) base.amoled() else base
    MaterialTheme(colorScheme = scheme, typography = AppTypography, shapes = AppShapes, content = content)
}
