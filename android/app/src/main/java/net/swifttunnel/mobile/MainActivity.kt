package net.swifttunnel.mobile

import android.app.AlertDialog
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.drawable.RippleDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.view.Gravity
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.core.content.edit
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : ComponentActivity() {
    private val model: CatalogViewModel by viewModels()
    private val uiTheme by lazy { SwiftTheme(this) }
    private val preferences by lazy { getSharedPreferences("mobile", MODE_PRIVATE) }
    private var selectedId: String? = null
    private lateinit var regionList: LinearLayout
    private lateinit var selectedLabel: TextView
    private lateinit var catalogMessage: TextView
    private lateinit var refreshButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        selectedId = preferences.getString("region", null)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(32))
        }
        val scroll = ScrollView(this).apply {
            setBackgroundColor(uiTheme.color(R.color.bg_base))
            isFillViewport = true
            addView(content)
            ViewCompat.setOnApplyWindowInsetsListener(this) { view, insets ->
                val bars = insets.getInsets(
                    WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
                )
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
        }
        setContentView(scroll)
        val branding = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        branding.addView(ImageView(this).apply {
            setImageResource(R.drawable.swift_logo)
            scaleType = ImageView.ScaleType.CENTER_CROP
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LinearLayout.LayoutParams(dp(42), dp(42)).apply { marginEnd = dp(8) })
        branding.addView(label(getString(R.string.brand), 21, true), LinearLayout.LayoutParams(0, -2, 1f))
        branding.addView(uiTheme.caption(getString(R.string.preview_badge)).apply {
            background = uiTheme.surface(R.color.bg_sidebar, 6, R.color.border_subtle)
            setPadding(dp(9), dp(7), dp(9), dp(7))
        })
        content.addView(branding)
        content.addView(uiTheme.caption(getString(R.string.eyebrow)).apply { setPadding(0, dp(32), 0, dp(10)) })
        content.addView(label(getString(R.string.headline), 34, true))
        content.addView(label(getString(R.string.intro), 16).apply { setPadding(0, dp(12), 0, dp(24)) })
        val status = card()
        status.addView(uiTheme.caption(getString(R.string.connection_label)))
        status.addView(label(getString(R.string.not_connected), 24, true))
        selectedLabel = label(getString(R.string.none_selected), 15)
        status.addView(selectedLabel)
        status.addView(label(getString(R.string.preview_notice), 14).apply { setPadding(0, dp(12), 0, dp(12)) })
        status.addView(uiTheme.button(getString(R.string.check_setup), primary = true) { showChecklist() })
        content.addView(status)
        content.addView(label(getString(R.string.regions_title), 22, true).apply { setPadding(0, dp(28), 0, dp(8)) })
        catalogMessage = label("", 14).apply { accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        content.addView(catalogMessage)
        regionList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(regionList)
        refreshButton = button(getString(R.string.refresh)) { model.refresh() }
        content.addView(refreshButton)
        val scope = card().apply {
            addView(uiTheme.caption(getString(R.string.roblox_only)))
            addView(label(getString(R.string.scope_title), 18, true))
            addView(label(getString(R.string.scope_body), 14))
        }
        content.addView(scope)
        model.state.observe(this) { render(it) }
    }

    private fun render(state: CatalogState) {
        refreshButton.isEnabled = !state.loading
        refreshButton.setText(if (state.loading) R.string.refreshing else R.string.refresh)
        catalogMessage.text = when {
            state.loading -> getString(R.string.refreshing)
            state.failed -> getString(R.string.list_error) + if (state.regions.isEmpty()) "" else
                "\n" + getString(R.string.cached_list)
            state.regions.isEmpty() -> getString(R.string.no_regions)
            else -> ""
        }
        selectedLabel.text = state.regions.firstOrNull { it.id == selectedId }?.let {
            getString(R.string.selection, it.name)
        } ?: getString(R.string.none_selected)
        regionList.removeAllViews()
        state.regions.forEach { region ->
            val status = when {
                !region.available -> getString(R.string.unavailable)
                region.busy -> getString(R.string.busy)
                region.activeUsers == null -> getString(R.string.unknown_load)
                else -> getString(R.string.available)
            }
            val selected = selectedId == region.id
            val enabled = region.available && !state.loading && !state.failed
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                minimumHeight = dp(80)
                setPadding(dp(16), dp(16), dp(16), dp(16))
                background = RippleDrawable(ColorStateList.valueOf(0x22ffffff),
                    uiTheme.surface(
                        if (selected) R.color.bg_elevated else R.color.bg_card,
                        12,
                        if (selected) R.color.accent_primary else R.color.border_subtle,
                    ), null)
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }
                isEnabled = enabled
                isSelected = selected
                alpha = if (enabled) 1f else 0.5f
                contentDescription = getString(R.string.region_row_description, region.name, status)
                accessibilityDelegate = object : View.AccessibilityDelegate() {
                    override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
                        super.onInitializeAccessibilityNodeInfo(host, info)
                        info.className = RadioButton::class.java.name
                        info.isCheckable = true
                        info.isChecked = selected
                    }
                }
            }
            row.addView(uiTheme.caption(region.countryCode).apply {
                gravity = Gravity.CENTER
                background = uiTheme.surface(R.color.bg_sidebar, 7, R.color.border_default)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }, LinearLayout.LayoutParams(dp(40), dp(40)).apply { marginEnd = dp(14) })
            row.addView(LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                addView(label(region.name, 16, true))
                addView(label(status, 12))
            }, LinearLayout.LayoutParams(0, -2, 1f))
            row.addView(RadioButton(this).apply {
                isChecked = selected
                buttonTintList = ColorStateList.valueOf(uiTheme.color(
                    if (selected) R.color.accent_primary else R.color.text_muted))
                isClickable = false
                isFocusable = false
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            })
            row.setOnClickListener {
                selectedId = region.id
                preferences.edit { putString("region", region.id) }
                render(model.state.value!!)
            }
            row.isClickable = enabled
            row.isFocusable = enabled
            regionList.addView(row)
        }
    }

    private fun showChecklist() {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val capabilities = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        val online = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val robloxInstalled = try {
            @Suppress("DEPRECATION")
            packageManager.getApplicationInfo(MobileReadiness.ROBLOX_PACKAGE, 0).enabled
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
        val state = model.state.value!!
        val checks = MobileReadiness.check(
            online, robloxInstalled, selectedId, state.regions,
            state.loadedAtMs, SystemClock.elapsedRealtime(),
        )
        val lines = listOf(
            if (checks.internetAvailable) R.string.check_online else R.string.check_offline,
            if (checks.robloxInstalled) R.string.check_roblox_present else R.string.check_roblox_missing,
            if (checks.regionAvailable) R.string.check_region_ready else R.string.check_region_missing,
            if (checks.catalogFresh) R.string.check_catalog_fresh else R.string.check_catalog_stale,
            R.string.check_transport_pending,
        )
        AlertDialog.Builder(this)
            .setTitle(R.string.check_title)
            .setMessage(lines.joinToString("\n\n") { getString(it) })
            .setPositiveButton(R.string.close, null)
            .show()
    }

    private fun label(value: String, size: Int, bold: Boolean = false) = uiTheme.text(value, size, bold)
    private fun button(value: String, action: () -> Unit) = uiTheme.button(value, action = action)
    private fun card() = uiTheme.card()
    private fun dp(value: Int) = uiTheme.dp(value)
}
