pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version "8.5.2"
        id("org.jetbrains.kotlin.android") version "1.9.24"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "eid-mongolia-sdk-android"

// mn.eidmongolia.eid.pades — client-side PAdES (JitPack: com.github.gerege-systems:eid-mongolia-sdk-android)
include(":pades")
