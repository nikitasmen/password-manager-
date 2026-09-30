package dev.pwvault

// Visual language, shared with the desktop app (src/gui/Theme.h): the ESP32 box on the desk. Quiet cool-grey panes,
// one accent (solder-mask green), and the board's own OLED, drawn in its 5x7 font, as the only bold element.

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Shapes
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Immutable
class Palette(
    val enclosure: Color, // screen background
    val surface: Color, // rows, fields, sheets
    val line: Color, // 1 px dividers and borders
    val ink: Color,
    val muted: Color, // secondary text
    val accent: Color, // the primary action, focus
    val onAccent: Color,
    val danger: Color, // delete, errors
    val oledOn: Color, // a lit OLED pixel; the glass is always black
)

private val Light = Palette(
    enclosure = Color(0xFFE4E7E3), surface = Color(0xFFF6F7F5), line = Color(0xFFC9CEC9), ink = Color(0xFF1A201C),
    muted = Color(0xFF68716B), accent = Color(0xFF1E6A45), onAccent = Color(0xFFF6F7F5), danger = Color(0xFFA5392A),
    oledOn = Color(0xFFE6EEF3),
)

// The same hues on graphite; the green is lifted to keep its contrast against the dark panes
private val Dark = Palette(
    enclosure = Color(0xFF161A18), surface = Color(0xFF1F2421), line = Color(0xFF343B37), ink = Color(0xFFE3E8E4),
    muted = Color(0xFF9AA39D), accent = Color(0xFF6CC196), onAccent = Color(0xFF0E1F16), danger = Color(0xFFE38A79),
    oledOn = Color(0xFFE6EEF3),
)

val LocalPalette = staticCompositionLocalOf { Light }
val palette: Palette @Composable get() = LocalPalette.current

@Composable
fun PwTheme(content: @Composable () -> Unit) {
    val p = if (isSystemInDarkTheme()) Dark else Light
    val base = if (p === Dark) darkColorScheme() else lightColorScheme()
    val colors = base.copy(
        primary = p.accent, onPrimary = p.onAccent, background = p.enclosure, onBackground = p.ink,
        surface = p.surface, onSurface = p.ink, onSurfaceVariant = p.muted, outline = p.line, outlineVariant = p.line,
        error = p.danger, surfaceContainerLow = p.surface, surfaceContainer = p.surface, surfaceContainerHigh = p.surface,
        surfaceContainerHighest = p.surface,
    )
    // A small scale (Bringhurst's 13/15/17/22) and two weights: regular for reading, medium for names and actions
    val t = Typography()
    val type = t.copy(
        headlineSmall = t.headlineSmall.copy(fontSize = 22.sp, lineHeight = 28.sp, fontWeight = FontWeight.Medium),
        titleMedium = t.titleMedium.copy(fontSize = 17.sp, lineHeight = 22.sp, fontWeight = FontWeight.Medium),
        bodyLarge = t.bodyLarge.copy(fontSize = 15.sp, lineHeight = 22.sp),
        bodyMedium = t.bodyMedium.copy(fontSize = 15.sp, lineHeight = 21.sp),
        bodySmall = t.bodySmall.copy(fontSize = 13.sp, lineHeight = 18.sp),
        labelLarge = t.labelLarge.copy(fontSize = 15.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.sp),
    )
    val shapes = Shapes(small = RoundedCornerShape(4.dp), medium = RoundedCornerShape(6.dp), large = RoundedCornerShape(10.dp))
    CompositionLocalProvider(LocalPalette provides p) {
        MaterialTheme(colorScheme = colors, typography = type, shapes = shapes, content = content)
    }
}

val Mono = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 16.sp, letterSpacing = 0.5.sp)

// ---- the OLED ----

/** One run of text on the OLED, in its pixels: [x] from the left (or from the right when [right]), [y] from the top. */
class OledText(val text: String, val x: Int = 0, val y: Int = 0, val size: Int = 1, val right: Boolean = false)

private const val OLED_W = 128

/**
 * The board's screen: 128 pixels wide, [rows] tall (64 is the whole SSD1306), black glass with lit dots. [rules]
 * are y positions of 1-pixel horizontal lines, like the one under the board's headers.
 */
@Composable
fun Oled(texts: List<OledText>, rows: Int = 64, rules: List<Int> = emptyList(), modifier: Modifier = Modifier) {
    val lit = palette.oledOn
    Box(
        modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(Color.Black).padding(14.dp)
            .semantics { contentDescription = texts.joinToString(". ") { it.text } },
    ) {
        Canvas(Modifier.fillMaxWidth().aspectRatio(OLED_W / rows.toFloat())) {
            val dot = size.width / OLED_W
            val gap = dot * 0.14f // the space between an OLED's pixels, just visible
            fun pixel(x: Int, y: Int, n: Int) =
                drawRect(lit, Offset(x * dot, y * dot), Size(n * dot - gap, n * dot - gap))
            for (y in rules) for (x in 0 until OLED_W) pixel(x, y, 1)
            for (t in texts) {
                val width = t.text.length * 6 * t.size
                val x0 = if (t.right) OLED_W - width - t.x else t.x
                t.text.forEachIndexed { i, ch ->
                    val glyph = OLED_FONT[(ch.code - 32).takeIf { it in 0..94 } ?: ('?'.code - 32)]
                    for (col in 0 until 5) for (row in 0 until 7)
                        if (glyph[col] shr row and 1 == 1)
                            pixel(x0 + (i * 6 + col) * t.size, t.y + row * t.size, t.size)
                }
            }
        }
    }
}

// ---- controls ----

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, enabled: Boolean = true, modifier: Modifier = Modifier) =
    Button(onClick, modifier.fillMaxWidth().height(52.dp), enabled = enabled, shape = RoundedCornerShape(6.dp),
        colors = ButtonDefaults.buttonColors(containerColor = palette.accent, contentColor = palette.onAccent)) {
        Text(text, style = MaterialTheme.typography.labelLarge)
    }

@Composable
fun QuietButton(text: String, onClick: () -> Unit, color: Color = palette.accent, enabled: Boolean = true,
                modifier: Modifier = Modifier) =
    TextButton(onClick, modifier.height(48.dp), enabled = enabled) {
        Text(text, color = if (enabled) color else palette.muted, style = MaterialTheme.typography.labelLarge)
    }

/**
 * A text field in the house style; [onDone] runs from the keyboard's action key. A [secret] field is hidden, with
 * its own Show/Hide toggle: each field starts hidden and is revealed on its own. Pass [visible] to control that
 * state from outside (e.g. showing a generated password).
 */
@Composable
fun Field(
    value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier,
    secret: Boolean = false, digits: Boolean = false, caps: Boolean = false,
    enabled: Boolean = true, onDone: (() -> Unit)? = null, visible: MutableState<Boolean>? = null,
) {
    val own = rememberSaveable { mutableStateOf(false) }
    val show = visible ?: own
    val shown = secret && show.value
    TextField(value, onChange, label, modifier, secret, shown, digits, caps, enabled, onDone,
        trailing = if (secret) ({
            QuietButton(if (shown) "Hide" else "Show", { show.value = !show.value }, color = palette.muted,
                modifier = Modifier.semantics { contentDescription = if (shown) "Hide $label" else "Show $label" })
        }) else null)
}

@Composable
private fun TextField(
    value: String, onChange: (String) -> Unit, label: String, modifier: Modifier, secret: Boolean, shown: Boolean,
    digits: Boolean, caps: Boolean, enabled: Boolean, onDone: (() -> Unit)?, trailing: (@Composable () -> Unit)?,
) = OutlinedTextField(
    value, onChange, modifier.fillMaxWidth().padding(vertical = 4.dp), enabled = enabled, singleLine = true,
    label = { Text(label) },
    textStyle = if (secret && shown) Mono else MaterialTheme.typography.bodyLarge,
    visualTransformation = if (secret && !shown) PasswordVisualTransformation() else VisualTransformation.None,
    keyboardOptions = KeyboardOptions(
        keyboardType = when { digits -> KeyboardType.NumberPassword; secret -> KeyboardType.Password; else -> KeyboardType.Text },
        capitalization = if (caps) KeyboardCapitalization.Characters else KeyboardCapitalization.None,
        autoCorrectEnabled = false,
        imeAction = if (onDone != null) ImeAction.Done else ImeAction.Next,
    ),
    keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
    trailingIcon = trailing,
    shape = RoundedCornerShape(6.dp),
    colors = OutlinedTextFieldDefaults.colors(
        focusedContainerColor = palette.surface, unfocusedContainerColor = palette.surface,
        disabledContainerColor = palette.surface, unfocusedBorderColor = palette.line,
    ),
)
