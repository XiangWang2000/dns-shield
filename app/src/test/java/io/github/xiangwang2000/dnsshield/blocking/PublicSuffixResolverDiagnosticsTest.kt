package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class PublicSuffixResolverDiagnosticsTest {
    @Test
    fun notLoadedDoesNotEmitPublicSuffixDiagnostic() {
        assertNull(
            DomainPolicyDiagnostics.publicSuffixMessage(PublicSuffixResolverStatus.NotLoaded)
        )
    }

    @Test
    fun loadedReportsRuleCounts() {
        assertEquals(
            "[攔截規則] Public Suffix 邊界已啟用：9950/281/8",
            DomainPolicyDiagnostics.publicSuffixMessage(
                PublicSuffixResolverStatus.Loaded(
                    exactRules = 9_950,
                    wildcardRules = 281,
                    exceptionRules = 8
                )
            )
        )
    }

    @Test
    fun rejectedReportsExactOnlyFallback() {
        assertEquals(
            "[攔截規則] Public Suffix 無法載入，compiled blocklist 維持 exact-only：synthetic failure",
            DomainPolicyDiagnostics.publicSuffixMessage(
                PublicSuffixResolverStatus.Rejected("synthetic failure")
            )
        )
    }
}
