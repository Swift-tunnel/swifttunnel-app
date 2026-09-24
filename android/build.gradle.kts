plugins {
    id("com.android.application") version "9.1.1" apply false
}

// Keep Android build output outside OneDrive, independently of Cargo's config.
val outputRoot = providers.gradleProperty("swiftAndroidBuildDir").orNull
    ?: if (System.getProperty("os.name").startsWith("Windows")) {
        "C:/cargo-target/swifttunnel-android"
    } else {
        "${System.getProperty("user.home")}/.cache/swifttunnel-android"
    }
layout.buildDirectory.set(file("$outputRoot/root"))
subprojects {
    layout.buildDirectory.set(file("$outputRoot/${project.name}"))
}
