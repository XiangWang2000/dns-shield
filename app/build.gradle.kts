Exit code: 0
Wall time: 0.5 seconds
Output:
import java.util.Base64
import java.util.Properties

plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.kotlin.compose)
  alias(libs.plugins.google.devtools.ksp)
}

val keystoreProperties = Properties().apply {
  val propertiesFile = rootProject.file("keystore.properties")
  if (propertiesFile.isFile) {
    propertiesFile.inputStream().use(::load)
  }
}

fun signingValue(environmentName: String, propertyName: String): String? =
  System.getenv(environmentName)?.takeIf { it.isNotBlank() }
    ?: keystoreProperties.getProperty(propertyName)?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingValue("KEYSTORE_PATH", "storeFile")
val releaseStorePassword = signingValue("STORE_PASSWORD", "storePassword")
val releaseKeyAlias = signingValue("KEY_ALIAS", "keyAlias")
val releaseKeyPassword = signingValue("KEY_PASSWORD", "keyPassword")
val releaseSigningReady = listOf(
  releaseStoreFile,
  releaseStorePassword,
  releaseKeyAlias,
  releaseKeyPassword
).all { it != null }
val releaseRequested = gradle.startParameter.taskNames.any {
  it.contains("release", ignoreCase = true)
}

if (releaseRequested && !releaseSigningReady) {
  throw GradleException(
    "Release signing is incomplete. Configure keystore.properties or " +
      "KEYSTORE_PATH, STORE_PASSWORD, KEY_ALIAS and KEY_PASSWORD."
  )
}

android {
  namespace = "io.github.xiangwang2000.dnsshield"
  compileSdk = 37

  defaultConfig {
    applicationId = "io.github.xiangwang2000.dnsshield"
    minSdk = 24
    targetSdk = 37
    versionCode = 2
    versionName = "1.1.0"
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  }

  signingConfigs {
    if (releaseSigningReady) {
      create("release") {
        storeFile = rootProject.file(requireNotNull(releaseStoreFile))
        storePassword = requireNotNull(releaseStorePassword)
        keyAlias = requireNotNull(releaseKeyAlias)
        keyPassword = requireNotNull(releaseKeyPassword)
      }
    }
    create("debugConfig") {
      val keystoreFile = file("${rootDir}/debug.keystore")
      if (!keystoreFile.exists()) {
        val base64File = file("${rootDir}/debug.keystore.base64")
        if (base64File.exists()) {
          try {
            val bytes = Base64.getDecoder().decode(base64File.readText().trim())
            keystoreFile.writeBytes(bytes)
          } catch (e: Exception) {
            e.printStackTrace()
          }
        }
      }
      if (keystoreFile.exists()) {
        storeFile = keystoreFile
        storePassword = "android"
        keyAlias = "androiddebugkey"
        keyPassword = "android"
      }
    }
  }

  buildTypes {
    release {
      isCrunchPngs = false
      isMinifyEnabled = false
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
      if (releaseSigningReady) {
        signingConfig = signingConfigs.getByName("release")
      }
    }
    debug {
      if (file("${rootDir}/debug.keystore").exists()) {
        signingConfig = signingConfigs.getByName("debugConfig")
      }
    }
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }
  buildFeatures {
    compose = true
  }
  sourceSets {
    getByName("androidTest") {
      assets.directories.add(layout.buildDirectory.dir("generated/publicSuffixAndroidTestAssets").get().asFile.absolutePath)
    }
  }
  packaging {
    jniLibs {
      keepDebugSymbols.add("**/libandroidx.graphics.path.so")
    }
  }
}

dependencies {
  implementation(platform(libs.androidx.compose.bom))
  implementation(libs.androidx.activity.compose)
  implementation(libs.androidx.compose.material.icons.core)
  implementation(libs.androidx.compose.material.icons.extended)
  implementation(libs.androidx.compose.material3)
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.graphics)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.lifecycle.viewmodel.compose)
  implementation(libs.androidx.room.ktx)
  implementation(libs.androidx.room.runtime)
  implementation(libs.kotlinx.coroutines.android)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.okhttp)
  testImplementation(libs.kotlin.test)
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  debugImplementation(libs.androidx.compose.ui.tooling)
  "ksp"(libs.androidx.room.compiler)
}

