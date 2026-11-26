package io.github.xiangwang2000.dnsshield.update

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.SocketTimeoutException
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Authenticator
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

internal data class AppUpdate(
    val versionName: String,
    val sizeBytes: Long,
    internal val downloadUrl: String,
    internal val sha256: String
)

/** Checks the public release metadata and downloads its verified APK into app-private cache. */
internal class GitHubAppUpdates(client: OkHttpClient = OkHttpClient()) {
    private val httpClient = client.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .authenticator(Authenticator.NONE)
        .proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES)
        .build()

    suspend fun check(currentVersion: String): AppUpdate? {
        val current = parseVersion(currentVersion)
            ?: throw IllegalArgumentException("Current version must be a canonical numeric version")
        val request = Request.Builder()
            .url(LATEST_RELEASE_URL)
            .header("Accept", "application/vnd.github+json")
            .get()
            .build()

        return execute(request) { response ->
            response.use {
                if (!it.isSuccessful) throw IOException("GitHub release check returned HTTP " + it.code)
                val body = it.body
                val json = try {
                    JSONObject(readBounded(body.byteStream(), MAX_RELEASE_JSON_BYTES).toString(Charsets.UTF_8))
                } catch (e: JSONException) {
                    throw IOException("GitHub release metadata was malformed", e)
                }
                if (json.requireBoolean("draft") || json.requireBoolean("prerelease")) return@use null

                val tag = json.requireString("tag_name")
                if (tag.contains('-')) return@use null
                val latest = parseTag(tag)
                    ?: throw IOException("GitHub release tag was not a canonical numeric version")
                if (latest <= current) return@use null

                val assets = json.opt("assets") as? JSONArray
                    ?: throw IOException("GitHub release did not include asset metadata")
                val apkAssets = (0 until assets.length())
                    .mapNotNull { assets.optJSONObject(it) }
                    .filter { it.opt("name") == APK_ASSET_NAME }
                if (apkAssets.size != 1) {
                    throw IOException("GitHub release must contain exactly one " + APK_ASSET_NAME + " asset")
                }

                val asset = apkAssets.single()
                val size = asset.requireLong("size")
                if (size <= 0L) throw IOException("GitHub APK asset size was invalid")
                val digest = SHA256_DIGEST_PATTERN.matchEntire(asset.requireString("digest"))
                    ?: throw IOException("GitHub APK asset did not include a SHA-256 digest")
                val downloadUrl = asset.requireString("browser_download_url")
                val expectedUrl = officialAssetUrl(tag)
                if (downloadUrl != expectedUrl) {
                    throw IOException("GitHub APK asset URL was not the official HTTPS release URL")
                }

                AppUpdate(
                    versionName = tag.removePrefix("v"),
                    sizeBytes = size,
                    downloadUrl = downloadUrl,
                    sha256 = digest.groupValues[1].lowercase(Locale.ROOT)
                )
            }
        }
    }

    suspend fun download(update: AppUpdate, cacheDir: File): File {
        validateUpdate(update)
        withContext(Dispatchers.IO) {
            if (!cacheDir.isDirectory && !cacheDir.mkdirs()) {
                throw IOException("Could not create the update cache directory")
            }
            if (!cacheDir.canWrite()) throw IOException("Update cache directory is not writable")
        }

        return suspendCancellableCoroutine { continuation ->
            val deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MAX_APK_DOWNLOAD_TIMEOUT_MILLIS)
            val activeCall = AtomicReference<Call?>()
            val partialFile = AtomicReference<File?>()
            continuation.invokeOnCancellation {
                activeCall.get()?.cancel()
                partialFile.getAndSet(null)?.delete()
            }

            fun enqueue(url: String, redirects: Int) {
                if (!continuation.isActive) return
                val request = try {
                    Request.Builder()
                        .url(url)
                        .header("Accept", "application/octet-stream")
                        .get()
                        .build()
                } catch (e: IllegalArgumentException) {
                    if (continuation.isActive) {
                        continuation.resumeWithException(IOException("Invalid APK URL", e))
                    }
                    return
                }
                val call = httpClient.newCall(request)
                val remainingMillis = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime())
                if (remainingMillis <= 0L) {
                    if (continuation.isActive) continuation.resumeWithException(SocketTimeoutException("APK download timed out"))
                    return
                }
                call.timeout().timeout(remainingMillis, TimeUnit.MILLISECONDS)
                activeCall.set(call)
                if (!continuation.isActive) {
                    call.cancel()
                    return
                }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (continuation.isActive) continuation.resumeWithException(e)
                    }

                    override fun onResponse(call: Call, response: Response) {
                        try {
                            if (!continuation.isActive) return
                            if (response.code in REDIRECT_CODES) {
                                val location = response.header("Location")
                                val redirected = location?.let { response.request.url.resolve(it) }
                                response.close()
                                if (redirects >= MAX_REDIRECTS ||
                                    redirected == null ||
                                    !isAllowedAssetRedirect(redirected)
                                ) {
                                    throw IOException("GitHub APK download returned an unsafe redirect")
                                }
                                enqueue(redirected.toString(), redirects + 1)
                                return
                            }

                            response.use {
                                if (!it.isSuccessful || !it.request.url.isHttps) {
                                    throw IOException("GitHub APK download returned HTTP " + it.code)
                                }
                                val body = it.body
                                val contentLength = body.contentLength()
                                if (contentLength >= 0L && contentLength != update.sizeBytes) {
                                    throw IOException("GitHub APK size did not match release metadata")
                                }

                                val partial = File.createTempFile(CACHE_PREFIX, ".part", cacheDir)
                                partialFile.set(partial)
                                if (!continuation.isActive) {
                                    partial.delete()
                                    return
                                }
                                val digest = MessageDigest.getInstance("SHA-256")
                                var written = 0L
                                FileOutputStream(partial).use { output ->
                                    val input = body.byteStream()
                                    val buffer = ByteArray(COPY_BUFFER_BYTES)
                                    while (true) {
                                        if (!continuation.isActive) throw IOException("APK download was cancelled")
                                        val count = input.read(buffer)
                                        if (count < 0) break
                                        if (count.toLong() > update.sizeBytes - written) {
                                            throw IOException("GitHub APK exceeded its declared size")
                                        }
                                        output.write(buffer, 0, count)
                                        digest.update(buffer, 0, count)
                                        written += count
                                    }
                                }
                                if (written != update.sizeBytes) {
                                    throw IOException("GitHub APK size did not match release metadata")
                                }
                                if (!digest.digest().toHex().equals(update.sha256, ignoreCase = true)) {
                                    throw IOException("GitHub APK SHA-256 did not match release metadata")
                                }

                                val completed = File(cacheDir, partial.name.removeSuffix(".part") + ".apk")
                                if (!partial.renameTo(completed)) {
                                    throw IOException("Could not publish verified APK to cache")
                                }
                                partialFile.set(null)
                                if (!continuation.isActive) {
                                    completed.delete()
                                    return
                                }
                                continuation.resume(completed) { _, file, _ -> file.delete() }
                            }
                        } catch (e: Throwable) {
                            partialFile.getAndSet(null)?.delete()
                            if (continuation.isActive) continuation.resumeWithException(e)
                        } finally {
                            response.close()
                        }
                    }
                })
            }

            enqueue(update.downloadUrl, 0)
        }
    }

    private suspend fun <T> execute(request: Request, readResponse: (Response) -> T): T =
        suspendCancellableCoroutine { continuation ->
            val call = httpClient.newCall(request)
            call.timeout().timeout(MAX_RELEASE_CHECK_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(e)
                }

                override fun onResponse(call: Call, response: Response) {
                    try {
                        val value = readResponse(response)
                        if (continuation.isActive) continuation.resume(value)
                    } catch (e: Throwable) {
                        if (continuation.isActive) continuation.resumeWithException(e)
                    } finally {
                        response.close()
                    }
                }
            })
        }

    private fun validateUpdate(update: AppUpdate) {
        val version = parseVersion(update.versionName)
            ?: throw IOException("Update version was not canonical")
        if (version.toString() != update.versionName || update.sizeBytes <= 0L) {
            throw IOException("Update metadata was invalid")
        }
        if (update.downloadUrl != officialAssetUrl("v" + update.versionName)) {
            throw IOException("Update URL was not the official HTTPS release URL")
        }
        if (!SHA256_HEX_PATTERN.matches(update.sha256)) throw IOException("Update SHA-256 was invalid")
    }

    private fun isAllowedAssetRedirect(url: HttpUrl): Boolean =
        url.isHttps &&
            url.host in ALLOWED_ASSET_REDIRECT_HOSTS &&
            url.port == 443 &&
            url.username.isEmpty() &&
            url.password.isEmpty() &&
            url.fragment == null

    private data class Version(val parts: List<BigInteger>) : Comparable<Version> {
        override fun compareTo(other: Version): Int {
            for (index in parts.indices) {
                val comparison = parts[index].compareTo(other.parts[index])
                if (comparison != 0) return comparison
            }
            return 0
        }

        override fun toString(): String = parts.joinToString(".")
    }

    private fun parseVersion(value: String): Version? {
        val match = VERSION_PATTERN.matchEntire(value) ?: return null
        return Version(match.groupValues.drop(1).map(::BigInteger))
    }

    private fun parseTag(tag: String): Version? {
        val match = TAG_PATTERN.matchEntire(tag) ?: return null
        return Version(match.groupValues.drop(1).map(::BigInteger))
    }

    private fun officialAssetUrl(tag: String): String =
        "$OFFICIAL_RELEASE_DOWNLOAD_BASE/$tag/$APK_ASSET_NAME"

    private fun readBounded(input: java.io.InputStream, maximumBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > maximumBytes) throw IOException("GitHub release metadata was too large")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun JSONObject.requireString(name: String): String =
        opt(name) as? String ?: throw IOException("GitHub release metadata is missing " + name)

    private fun JSONObject.requireBoolean(name: String): Boolean =
        opt(name) as? Boolean ?: throw IOException("GitHub release metadata is missing " + name)

    private fun JSONObject.requireLong(name: String): Long {
        val value = opt(name)
        if (value is Int) return value.toLong()
        if (value is Long) return value
        throw IOException("GitHub release metadata has invalid " + name)
    }

    private companion object {
        const val LATEST_RELEASE_URL = "https://api.github.com/repos/XiangWang2000/dns-shield/releases/latest"
        const val OFFICIAL_RELEASE_DOWNLOAD_BASE = "https://github.com/XiangWang2000/dns-shield/releases/download"
        const val APK_ASSET_NAME = "app-release.apk"
        const val MAX_RELEASE_JSON_BYTES = 1024 * 1024
        const val MAX_RELEASE_CHECK_TIMEOUT_MILLIS = 30_000L
        const val MAX_APK_DOWNLOAD_TIMEOUT_MILLIS = 5 * 60 * 1000L
        const val COPY_BUFFER_BYTES = 16 * 1024
        const val MAX_REDIRECTS = 5
        const val CACHE_PREFIX = "dns-shield-update-"
        val VERSION_PATTERN = Regex("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)")
        val TAG_PATTERN = Regex("v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)")
        val SHA256_DIGEST_PATTERN = Regex("sha256:([0-9a-fA-F]{64})")
        val SHA256_HEX_PATTERN = Regex("[0-9a-fA-F]{64}")
        val REDIRECT_CODES = setOf(300, 301, 302, 303, 307, 308)
        val ALLOWED_ASSET_REDIRECT_HOSTS =
            setOf("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
    }
}