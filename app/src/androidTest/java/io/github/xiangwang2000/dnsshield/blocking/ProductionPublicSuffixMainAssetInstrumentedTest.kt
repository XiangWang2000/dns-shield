package io.github.xiangwang2000.dnsshield.blocking

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies the checked-in production PSL through the same AssetManager boundary used by runtime. */
@RunWith(AndroidJUnit4::class)
class ProductionPublicSuffixMainAssetInstrumentedTest {
    @Test
    fun loadsAndReusesPackagedProductionAsset() {
        val targetAssets = InstrumentationRegistry.getInstrumentation().targetContext.assets
        val owner = PublicSuffixResolverOwner.fromAssets(targetAssets)

        assertEquals(PublicSuffixResolverStatus.NotLoaded, owner.status())

        val first = checkNotNull(owner.resolverOrNull()) {
            "Packaged production Public Suffix asset was rejected"
        }
        val second = checkNotNull(owner.resolverOrNull()) {
            "Previously loaded production Public Suffix resolver disappeared"
        }

        assertSame(first, second)
        assertEquals(
            PublicSuffixResolverStatus.Loaded(
                exactRules = 9_950,
                wildcardRules = 281,
                exceptionRules = 8
            ),
            owner.status()
        )
        assertEquals(
            "72d07fea544b74d920be2394d4c5fbb38dd3f5f3ccac299e27809009bac1c550",
            first.sourceSha256Hex
        )

        for ((query, expected) in LOOKUP_CASES) {
            assertEquals(query, expected, first.registrableDomain(query))
        }
    }

    companion object {
        private val LOOKUP_CASES = listOf(
            "www.example.com" to "example.com",
            "a.b.example.co.uk" to "example.co.uk",
            "ads.tenant.github.io" to "tenant.github.io",
            "cdn.site.blogspot.com" to "site.blogspot.com",
            "a.b.ck" to "a.b.ck",
            "a.www.ck" to "www.ck",
            "a.city.kawasaki.jp" to "city.kawasaki.jp",
            "www.xn--55qx5d.cn" to "www.xn--55qx5d.cn"
        )
    }
}
