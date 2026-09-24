package net.swifttunnel.mobile

import org.json.JSONObject

data class RelayRegion(
    val id: String,
    val name: String,
    val countryCode: String,
    val available: Boolean,
    val busy: Boolean,
    val activeUsers: Int?,
)

object RelayCatalog {
    const val MAX_BYTES = 128 * 1024
    private const val MAX_REGIONS = 128
    private val regionId = Regex("[a-z0-9][a-z0-9-]{0,63}")
    private val country = Regex("[A-Z]{2}")

    fun parse(json: String): List<RelayRegion> {
        require(json.toByteArray(Charsets.UTF_8).size <= MAX_BYTES) { "Catalog too large" }
        val rows = JSONObject(json).getJSONArray("servers")
        require(rows.length() <= MAX_REGIONS) { "Too many regions" }
        val ids = mutableSetOf<String>()
        return buildList {
            for (index in 0 until rows.length()) {
                val row = rows.getJSONObject(index)
                val id = row.opt("region") as? String
                val name = row.opt("name") as? String
                val code = row.opt("country_code") as? String
                require(id != null && regionId.matches(id)) { "Invalid region" }
                require(ids.add(id)) { "Duplicate region" }
                require(name != null && name.isNotBlank() && name.length <= 80 &&
                    name.none { it.isISOControl() }) { "Invalid region name" }
                require(code != null && country.matches(code)) { "Invalid country" }
                // Missing or string-valued availability must never become true.
                val port = row.opt("relay_port")
                val usablePort = port is Int && port in 1..65535
                val load = row.opt("active_users")
                add(RelayRegion(
                    id, name, code,
                    row.opt("relay_available") == true && usablePort,
                    row.opt("busy") == true,
                    (load as? Int)?.takeIf { it >= 0 },
                ))
            }
        }
    }
}

data class SetupChecklist(
    val internetAvailable: Boolean,
    val robloxInstalled: Boolean,
    val regionAvailable: Boolean,
    val catalogFresh: Boolean,
)

object MobileReadiness {
    const val ROBLOX_PACKAGE = "com.roblox.client"
    const val CATALOG_FRESH_MS = 60_000L

    fun check(
        online: Boolean,
        robloxInstalled: Boolean,
        selectedId: String?,
        regions: List<RelayRegion>,
        loadedAtMs: Long?,
        nowMs: Long,
    ) = SetupChecklist(
        online,
        robloxInstalled,
        regions.any { it.id == selectedId && it.available },
        loadedAtMs != null && nowMs >= loadedAtMs && nowMs - loadedAtMs < CATALOG_FRESH_MS,
    )

    // A live catalog advertises desktop relays, not Android transport capability.
    // There is intentionally no connect operation until encrypted transport and
    // mobile authentication are implemented and tested together.
}
