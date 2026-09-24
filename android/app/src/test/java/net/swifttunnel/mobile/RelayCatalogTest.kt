package net.swifttunnel.mobile

import org.junit.Assert.*
import org.junit.Test

class RelayCatalogTest {
    private val row = """{"region":"singapore","name":"Singapore","country_code":"SG","relay_available":true,"relay_port":51820,"active_users":12,"busy":false}"""
    private fun parse(value: String = row) = RelayCatalog.parse("""{"servers":[$value]}""")
    private fun fails(value: String) {
        assertThrows(Exception::class.java) { parse(value) }
    }

    @Test fun readsExistingServerContractWithoutInventingMobileSupport() {
        assertEquals(RelayRegion("singapore", "Singapore", "SG", true, false, 12), parse().single())
    }

    @Test fun missingAvailabilityIsUnavailable() {
        assertFalse(parse(row.replace("\"relay_available\":true,", "")).single().available)
    }

    @Test fun stringBooleanDoesNotEnableRelay() {
        assertFalse(parse(row.replace(":true", ":\"true\"")).single().available)
    }

    @Test fun disabledRelayStaysUnavailable() {
        assertFalse(parse(row.replace(":true", ":false")).single().available)
    }

    @Test fun invalidPortsCannotEnableRelay() {
        for (value in listOf("null", "0", "65536", "-1", "1.5", "\"51820\"")) {
            assertFalse(parse(row.replace("51820", value)).single().available)
        }
    }

    @Test fun unknownOrMalformedOccupancyIsNotZero() {
        for (value in listOf("null", "-1", "1.5", "\"0\"", "2147483648")) {
            assertNull(parse(row.replace("\"active_users\":12", "\"active_users\":$value")).single().activeUsers)
        }
    }

    @Test fun zeroOccupancyRemainsKnown() {
        assertEquals(0, parse(row.replace("\"active_users\":12", "\"active_users\":0")).single().activeUsers)
    }

    @Test fun duplicateRegionIdentityRejectsWholeSnapshot() { fails("$row,$row") }
    @Test fun missingIdentityRejectsSnapshot() { fails(row.replace("\"region\":\"singapore\",", "")) }
    @Test fun controlCharactersInDisplayNameRejectSnapshot() { fails(row.replace("Singapore", "Singapore\\nother")) }
    @Test fun malformedCountryRejectsSnapshot() { fails(row.replace("\"SG\"", "\"SG123\"")) }

    @Test fun boundedRegionCount() {
        fails((0..128).joinToString(",") { row.replace("singapore", "region-$it") })
    }

    @Test fun boundedDocumentSize() {
        assertThrows(IllegalArgumentException::class.java) {
            RelayCatalog.parse(" ".repeat(RelayCatalog.MAX_BYTES + 1))
        }
    }

    @Test fun emptyListIsValidButNoInventedFallback() {
        assertTrue(RelayCatalog.parse("""{"servers":[]}""").isEmpty())
    }

    @Test fun missingServerArrayIsNotSuccessfulEmptyList() {
        assertThrows(Exception::class.java) { RelayCatalog.parse("{}") }
    }

    @Test fun readinessUsesAvailabilityAndMonotonicFreshness() {
        val ready = MobileReadiness.check(true, true, "singapore", parse(), 100L, 101L)
        assertEquals(SetupChecklist(true, true, true, true), ready)
        val stale = MobileReadiness.check(true, true, "singapore", parse(), 100L, 60_100L)
        assertFalse(stale.catalogFresh)
        assertFalse(MobileReadiness.check(true, true, "singapore", parse(), 100L, 99L).catalogFresh)
        assertFalse(MobileReadiness.check(true, true, "singapore", parse(), null, 101L).catalogFresh)
    }

    @Test fun removedOrDisabledSelectionCannotPassReadiness() {
        assertFalse(MobileReadiness.check(true, true, "old-region", parse(), 0L, 1L).regionAvailable)
        assertFalse(MobileReadiness.check(true, true, "singapore", parse(row.replace(":true", ":false")), 0L, 1L).regionAvailable)
    }

    @Test fun missingRobloxAndOfflineAreReportedIndependently() {
        val checks = MobileReadiness.check(false, false, null, emptyList(), null, 1L)
        assertEquals(SetupChecklist(false, false, false, false), checks)
    }
}
