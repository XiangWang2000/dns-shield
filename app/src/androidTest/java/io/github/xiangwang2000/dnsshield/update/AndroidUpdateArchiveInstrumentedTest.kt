package io.github.xiangwang2000.dnsshield.update

import android.content.pm.PackageManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidUpdateArchiveInstrumentedTest {
    @Suppress("DEPRECATION")
    @Test
    fun updateArchiveExposesSameSignersAsInstalledApp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val archive = requireNotNull(AndroidUpdateInstaller(context).readUpdateArchive(context.applicationInfo.sourceDir))
        assertEquals(context.packageName, archive.packageName)
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val installed = context.packageManager.getPackageInfo(context.packageName, flags)
        val installedSigners = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            requireNotNull(installed.signingInfo).apkContentsSigners
        } else {
            requireNotNull(installed.signatures)
        }
        val archiveSigners = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            requireNotNull(archive.signingInfo).apkContentsSigners
        } else {
            requireNotNull(archive.signatures)
        }
        assertFalse(archiveSigners.isEmpty())
        assertEquals(installedSigners.toSet(), archiveSigners.toSet())
    }
}
