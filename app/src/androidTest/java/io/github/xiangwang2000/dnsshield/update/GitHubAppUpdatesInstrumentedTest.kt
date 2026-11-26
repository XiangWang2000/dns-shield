package io.github.xiangwang2000.dnsshield.update

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class GitHubAppUpdatesInstrumentedTest {
    private lateinit var cacheDir: File

    @Before
    fun setUp() {
        cacheDir = File(
            InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
            "github-update-test-" + UUID.randomUUID()
        )
        assertTrue(cacheDir.mkdirs())
    }

    @After
    fun tearDown() {
        cacheDir.deleteRecursively()
    }

    @Test
    fun olderAndEqualStableReleasesAreIgnored() = runBlocking {
        for (tag in listOf("v1.4.9", "v1.5.0")) {
            assertNull(updates(releaseJson(tag = tag, includeAssets = false)).check("1.5.0"))
        }
    }

    @Test
    fun newerStableReleaseProvidesVersionAndSize() = runBlocking {
        val result = updates(releaseJson()).check("1.5.0")

        assertEquals("1.6.0", result?.versionName)
        assertEquals(APK_BYTES.size.toLong(), result?.sizeBytes)
    }

    @Test
    fun draftsAndPrereleasesAreIgnored() = runBlocking {
        assertNull(updates(releaseJson(tag = "v2.0.0", draft = true, includeAssets = false)).check("1.5.0"))
        assertNull(updates(releaseJson(tag = "v2.0.0-rc.1", prerelease = true, includeAssets = false)).check("1.5.0"))
    }

    @Test
    fun newerReleaseWithoutApkAssetFails() {
        assertThrows(IOException::class.java) {
            runBlocking {
                updates(releaseJson(assetName = "other.apk")).check("1.5.0")
            }
        }
    }

    @Test
    fun nonOfficialOrHttpAssetUrlFails() {
        val invalidUrls = listOf(
            "http://github.com/XiangWang2000/dns-shield/releases/download/v1.6.0/app-release.apk",
            "https://example.com/XiangWang2000/dns-shield/releases/download/v1.6.0/app-release.apk",
            "https://github.com/XiangWang2000/dns-shield/releases/download/v1.6.0/other.apk"
        )
        for (url in invalidUrls) {
            assertThrows(IOException::class.java) {
                runBlocking {
                    updates(releaseJson(assetUrl = url)).check("1.5.0")
                }
            }
        }
    }

    @Test
    fun malformedSha256FailsBeforeDownload() {
        assertThrows(IOException::class.java) {
            runBlocking {
                updates(releaseJson(digest = "sha256:xyz")).check("1.5.0")
            }
        }
    }

    @Test
    fun verifiedApkBytesAreWrittenToCache() = runBlocking {
        val service = updates(releaseJson())
        val update = service.check("1.5.0")!!
        val file = service.download(update, cacheDir)

        assertArrayEquals(APK_BYTES, file.readBytes())
        assertEquals(update.sizeBytes, file.length())
        assertEquals(1, cacheDir.listFiles()?.size)
        assertTrue(file.name.endsWith(".apk"))
    }

    @Test
    fun sha256MismatchDeletesPartialDownload() = runBlocking {
        val service = updates(releaseJson(digest = "sha256:" + "0".repeat(64)))
        val update = service.check("1.5.0")!!

        assertThrows(IOException::class.java) {
            runBlocking { service.download(update, cacheDir) }
        }
        assertTrue(cacheDir.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun oversizedDownloadIsStoppedAndDeleted() = runBlocking {
        val service = updates(
            releaseJson(size = (APK_BYTES.size - 1).toLong()),
            assetBytes = APK_BYTES
        )
        val update = service.check("1.5.0")!!

        assertThrows(IOException::class.java) {
            runBlocking { service.download(update, cacheDir) }
        }
        assertTrue(cacheDir.listFiles().orEmpty().isEmpty())
    }

    private fun updates(release: String, assetBytes: ByteArray = APK_BYTES): GitHubAppUpdates {
        val interceptor = Interceptor { chain ->
            val request = chain.request()
            assertTrue("Requests must use HTTPS", request.url.isHttps)
            assertNull(request.header("Authorization"))
            assertNull(request.header("Proxy-Authorization"))
            assertNull(request.header("Cookie"))
            val body = when (request.url.encodedPath) {
                LATEST_PATH -> release.toResponseBody(JSON_MEDIA_TYPE)
                APK_PATH -> assetBytes.toResponseBody(APK_MEDIA_TYPE)
                else -> throw AssertionError("Unexpected request URL: " + request.url)
            }
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(body)
                .build()
        }
        return GitHubAppUpdates(OkHttpClient.Builder().addInterceptor(interceptor).build())
    }

    private fun releaseJson(
        tag: String = "v1.6.0",
        draft: Boolean = false,
        prerelease: Boolean = false,
        assetName: String = "app-release.apk",
        assetUrl: String = officialUrl(tag),
        digest: String = "sha256:" + sha256(APK_BYTES),
        size: Long = APK_BYTES.size.toLong(),
        includeAssets: Boolean = true
    ): String {
        val release = JSONObject()
            .put("tag_name", tag)
            .put("draft", draft)
            .put("prerelease", prerelease)
        if (includeAssets) {
            release.put(
                "assets",
                JSONArray().put(
                    JSONObject()
                        .put("name", assetName)
                        .put("size", size)
                        .put("digest", digest)
                        .put("browser_download_url", assetUrl)
                )
            )
        }
        return release.toString()
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private companion object {
        const val LATEST_PATH = "/repos/XiangWang2000/dns-shield/releases/latest"
        const val APK_PATH = "/XiangWang2000/dns-shield/releases/download/v1.6.0/app-release.apk"
        val APK_BYTES = "fake apk payload".toByteArray(Charsets.UTF_8)
        val JSON_MEDIA_TYPE = "application/json".toMediaType()
        val APK_MEDIA_TYPE = "application/octet-stream".toMediaType()

        fun officialUrl(tag: String): String =
            "https://github.com/XiangWang2000/dns-shield/releases/download/" + tag + "/app-release.apk"
    }
}