import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.0"
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.0"
}

android {
    namespace = "dev.pwvault"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.pwvault"
        minSdk = 28 // ChaCha20-Poly1305
        targetSdk = 35
        // The version is the release tag without its "v", shared with the desktop release; the updater compares the two.
        // versionCode must grow with every release for Android to install it over the old one.
        versionName = "2.0"
        versionCode = versionName!!.split(".").map(String::toInt).let { v -> v[0] * 10000 + v.getOrElse(1) { 0 } * 100 + v.getOrElse(2) { 0 } }
        buildConfigField("String", "UPDATE_REPO", "\"nikitasmen/password-manager-\"")
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    // Release signing from ~/.gradle/gradle.properties (never the repo): pwvaultKeystore, pwvaultKeystorePassword,
    // pwvaultKeyAlias, pwvaultKeyPassword. Every release must use the same key, or Android refuses the update.
    val keystore = providers.gradleProperty("pwvaultKeystore").orNull
    signingConfigs {
        if (keystore != null) create("release") {
            storeFile = file(keystore)
            storePassword = providers.gradleProperty("pwvaultKeystorePassword").get()
            keyAlias = providers.gradleProperty("pwvaultKeyAlias").get()
            keyPassword = providers.gradleProperty("pwvaultKeyPassword").get()
        }
    }
    buildTypes {
        getByName("release") { if (keystore != null) signingConfig = signingConfigs.getByName("release") }
        all { buildConfigField("boolean", "DEMO", "false") }
        // A second app for UI work: its own local-only vault, no board, screenshots allowed
        create("demo") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".demo"
            buildConfigField("boolean", "DEMO", "true")
            matchingFallbacks += "debug"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.06.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.1")
    // The pairing QR: Google's scanner UI runs in Play services, on the device, and needs no camera permission
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517") // Android's org.json is a stub in JVM tests
}
