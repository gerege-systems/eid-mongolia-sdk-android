// eID client-side PAdES — native Kotlin signing path (prepare / complete), byte-identical to the Go reference
// (gerege-systems/eid-mongolia-sdk-go `pades`, profile pades-client/1). No native library, no BouncyCastle —
// java.security + a minimal DER writer. Conformance: src/test/resources/golden (scripts/sync-pades-golden.sh) — JVM
// unit tests, no device needed.
plugins {
    id("com.android.library")
    kotlin("android")
    `maven-publish`
}

android {
    namespace = "mn.eidmongolia.eid.pades"
    compileSdk = 34
    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
    // The same golden/error tests also run on a device (Conscrypt / ART crypto, org.json):
    // ./gradlew :pades:connectedDebugAndroidTest
    sourceSets.getByName("androidTest") {
        kotlin.srcDir("src/test/kotlin")
        resources.srcDir("src/test/resources")
    }
    publishing {
        singleVariant("release") { withSourcesJar() }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303") // org.json is a stub on the unit-test classpath
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("junit:junit:4.13.2")
}

// JitPack: com.github.gerege-systems:eid-mongolia-sdk-android:<tag> (JitPack sets VERSION to the git tag).
publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.github.gerege-systems"
            artifactId = "eid-mongolia-sdk-android"
            version = System.getenv("VERSION") ?: "0.0.0-SNAPSHOT"
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("eID Mongolia PAdES SDK (Android)")
                description.set("Client-side PAdES signing for eID Mongolia (pades-client/1)")
                url.set("https://github.com/gerege-systems/eid-mongolia-sdk-android")
                licenses { license { name.set("MIT"); url.set("https://opensource.org/licenses/MIT") } }
            }
        }
    }
}
