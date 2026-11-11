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
                exactRules = 10_076,
                wildcardRules = 312,
                exceptionRules = 8
            ),
            owner.status()
        )
        assertEquals(
            "bd72f205259fc1565b71b559732e13a1c857c3389bf15cd40589cd59c1967354",
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
            "db.aivencloud.com" to null,
            "www.tenant.db.aivencloud.com" to "tenant.db.aivencloud.com",
            "a.b.ck" to "a.b.ck",
            "a.www.ck" to "www.ck",
            "a.city.kawasaki.jp" to "city.kawasaki.jp",
            "www.xn--55qx5d.cn" to "www.xn--55qx5d.cn"
        )
    }
}
