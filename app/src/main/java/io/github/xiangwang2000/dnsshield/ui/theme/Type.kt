package io.github.xiangwang2000.dnsshield.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private fun uiText(size: Int, height: Int, weight: FontWeight = FontWeight.Normal) = TextStyle(
    fontFamily = FontFamily.Default,
    fontWeight = weight,
    fontSize = size.sp,
    lineHeight = height.sp,
    letterSpacing = 0.sp
)

val Typography = Typography(
    titleLarge = uiText(22, 30, FontWeight.SemiBold),
    titleMedium = uiText(18, 26, FontWeight.SemiBold),
    titleSmall = uiText(16, 24, FontWeight.Medium),
    bodyLarge = uiText(16, 24),
    bodyMedium = uiText(14, 22),
    bodySmall = uiText(12, 18),
    labelLarge = uiText(14, 20, FontWeight.Medium),
    labelMedium = uiText(12, 18, FontWeight.Medium),
    labelSmall = uiText(11, 16, FontWeight.Medium)
)
