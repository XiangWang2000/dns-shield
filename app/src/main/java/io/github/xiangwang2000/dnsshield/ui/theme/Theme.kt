package io.github.xiangwang2000.dnsshield.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// DNS Shield currently ships a dark interface. Define every role used by Material controls.
private val DarkColorScheme = darkColorScheme(
    primary = CyberEmeraldGlow,
    onPrimary = DarkBackground,
    primaryContainer = Color(0xFF064E3B),
    onPrimaryContainer = Color(0xFFD1FAE5),
    secondary = CyberSky,
    onSecondary = DarkBackground,
    secondaryContainer = Color(0xFF0C4A6E),
    onSecondaryContainer = Color(0xFFE0F2FE),
    tertiary = CyberAmber,
    onTertiary = DarkBackground,
    tertiaryContainer = Color(0xFF451A03),
    onTertiaryContainer = Color(0xFFFFEDD5),
    background = DarkBackground,
    onBackground = ColorTextPrimary,
    surface = DarkSurface,
    onSurface = ColorTextPrimary,
    surfaceVariant = DarkSurface,
    onSurfaceVariant = ColorTextSecondary,
    surfaceDim = DarkBackground,
    surfaceBright = Color(0xFF334155),
    surfaceContainerLowest = Color(0xFF020617),
    surfaceContainerLow = Color(0xFF172033),
    surfaceContainer = DarkSurface,
    surfaceContainerHigh = Color(0xFF293548),
    surfaceContainerHighest = Color(0xFF334155),
    outline = ColorTextSecondary,
    outlineVariant = ColorBorder,
    inverseSurface = ColorTextPrimary,
    inverseOnSurface = DarkSurface,
    inversePrimary = Color(0xFF047857),
    error = CyberCrimson,
    onError = Color(0xFF4C1725),
    errorContainer = Color(0xFF4C1725),
    onErrorContainer = Color(0xFFFFE4E8)
)

@Composable
fun MyApplicationTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkColorScheme, typography = Typography, content = content)
}
