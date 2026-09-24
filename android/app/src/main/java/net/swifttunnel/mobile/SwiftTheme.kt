package net.swifttunnel.mobile

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Native equivalents of the desktop's monochrome design tokens. */
class SwiftTheme(private val context: Context) {
    private val regular = context.resources.getFont(R.font.geist_regular)
    private val semibold = context.resources.getFont(R.font.geist_semibold)
    private val mono = context.resources.getFont(R.font.geist_mono)

    fun dp(value: Int) = (value * context.resources.displayMetrics.density).toInt()
    fun color(id: Int) = context.getColor(id)

    fun text(value: String, size: Int, bold: Boolean = false) = TextView(context).apply {
        text = value
        textSize = size.toFloat()
        typeface = if (bold) semibold else regular
        setTextColor(color(if (bold) R.color.text_primary else R.color.text_secondary))
        setLineSpacing(dp(3).toFloat(), 1f)
        setPadding(0, dp(4), 0, dp(4))
        includeFontPadding = false
    }

    fun caption(value: String) = text(value, 11).apply {
        typeface = mono
        letterSpacing = 0.06f
        setTextColor(color(R.color.text_muted))
    }

    fun surface(fill: Int = R.color.bg_card, radius: Int = 18, border: Int = R.color.border_default) =
        GradientDrawable().apply {
            setColor(color(fill))
            cornerRadius = dp(radius).toFloat()
            setStroke(dp(1), color(border))
        }

    fun card() = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(20), dp(20), dp(20))
        background = surface()
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) }
    }

    fun button(value: String, primary: Boolean = false, action: () -> Unit) = Button(context).apply {
        text = value
        textSize = 15f
        typeface = semibold
        isAllCaps = false
        minHeight = dp(52)
        minimumHeight = dp(52)
        setPadding(dp(16), dp(12), dp(16), dp(12))
        backgroundTintList = null
        val fill = if (primary) R.color.accent_primary else R.color.bg_elevated
        val border = if (primary) R.color.accent_primary else R.color.border_default
        background = RippleDrawable(
            ColorStateList.valueOf(if (primary) 0x22000000 else 0x22ffffff),
            surface(fill, 7, border), null,
        )
        setTextColor(ColorStateList(
            arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf()),
            intArrayOf(color(R.color.text_muted), if (primary) Color.BLACK else color(R.color.text_primary)),
        ))
        stateListAnimator = null
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) }
    }
}
