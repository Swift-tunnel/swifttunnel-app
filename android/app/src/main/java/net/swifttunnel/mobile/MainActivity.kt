package net.swifttunnel.mobile

import android.app.AlertDialog
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.core.content.edit
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : ComponentActivity() {
    private val model: CatalogViewModel by viewModels()
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
            setBackgroundColor(Color.rgb(6, 6, 6))
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
        content.addView(label(getString(R.string.brand), 22, true))
        content.addView(label(getString(R.string.eyebrow), 11).apply { setPadding(0, dp(30), 0, dp(10)) })
        content.addView(label(getString(R.string.headline), 34, true))
        content.addView(label(getString(R.string.intro), 16).apply { setPadding(0, dp(12), 0, dp(24)) })
        val status = card()
        status.addView(label(getString(R.string.not_connected), 24, true))
        selectedLabel = label(getString(R.string.none_selected), 15)
        status.addView(selectedLabel)
        status.addView(label(getString(R.string.preview_notice), 14).apply { setPadding(0, dp(12), 0, dp(12)) })
        status.addView(button(getString(R.string.check_setup)) { showChecklist() })
        content.addView(status)
        content.addView(label(getString(R.string.regions_title), 22, true).apply { setPadding(0, dp(28), 0, dp(8)) })
        catalogMessage = label("", 14).apply { accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        content.addView(catalogMessage)
        regionList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(regionList)
        refreshButton = button(getString(R.string.refresh)) { model.refresh() }
        content.addView(refreshButton)
        val scope = card().apply {
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
            val selected = if (selectedId == region.id) "  /  ${getString(R.string.selected)}" else ""
            regionList.addView(button("${region.name}  /  ${region.countryCode}\n$status$selected") {
                selectedId = region.id
                preferences.edit { putString("region", region.id) }
                render(model.state.value!!)
            }.apply {
                isEnabled = region.available && !state.loading && !state.failed
                isSelected = selectedId == region.id
                contentDescription = text
            })
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

    private fun label(value: String, size: Int, bold: Boolean = false) = TextView(this).apply {
        text = value
        textSize = size.toFloat()
        setTextColor(if (bold) Color.rgb(245, 245, 245) else Color.rgb(180, 180, 184))
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setLineSpacing(dp(3).toFloat(), 1f)
        setPadding(0, dp(4), 0, dp(4))
    }

    private fun button(value: String, action: () -> Unit) = Button(this).apply {
        text = value
        isAllCaps = false
        minHeight = dp(56)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
    }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(20), dp(20), dp(20))
        background = GradientDrawable().apply {
            setColor(Color.rgb(27, 27, 29))
            cornerRadius = dp(20).toFloat()
            setStroke(dp(1), Color.rgb(52, 52, 58))
        }
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(16) }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
