package io.github.xiangwang2000.dnsshield.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme =
  darkColorScheme(
    primary = CyberEmerald,
    onPrimary = ColorWhite,
    secondary = CyberSky,
    onSecondary = DarkBackground,
    background = DarkBackground,
    onBackground = ColorTextPrimary,
    surface = DarkSurface,
    onSurface = ColorTextPrimary,
    surfaceVariant = DarkSurface,
    onSurfaceVariant = ColorTextSecondary,
    outline = ColorBorder,
    error = CyberCrimson
  )

@Composable
fun MyApplicationTheme(
  content: @Composable () -> Unit,
) {
  MaterialTheme(colorScheme = DarkColorScheme, typography = Typography, content = content)
}
