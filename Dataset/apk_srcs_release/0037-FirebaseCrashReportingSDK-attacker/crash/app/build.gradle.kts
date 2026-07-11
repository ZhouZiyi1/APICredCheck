import com.android.build.gradle.internal.tasks.factory.dependsOn

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.google.services)
    alias(libs.plugins.firebase.crashlytics)
}

tasks {
    check.dependsOn("assembleDebugAndroidTest")
}

android {
    namespace = "com.firebase.crash.attacker"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.firebase.crash.attacker"
        minSdk = 23
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        multiDexEnabled = true
    }

    signingConfigs {
        create("attacker") {
            storeFile = rootProject.file("../../attacker.jks")
            storePassword = "lawgeek"
            keyAlias = "key0"
            keyPassword = "lawgeek"
        }
    }

    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("attacker")
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        getByName("debug") {
            signingConfig = signingConfigs.getByName("attacker")
            isMinifyEnabled = false
            testProguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "test-proguard-rules.pro")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalizedVariantName = variant.name.replaceFirstChar { it.uppercaseChar() }
        val fixedApkName = "0037-FirebaseCrashReportingSDK-attacker.apk"
        val copyTask = tasks.register<Copy>("copy${capitalizedVariantName}ApkWithFixedName") {
            from(variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.APK))
            into(rootProject.file("../../../apks"))
            include("*.apk")
            exclude(fixedApkName)
            rename { fixedApkName }
        }
        tasks.matching { it.name == "assemble$capitalizedVariantName" }.configureEach {
            finalizedBy(copyTask)
        }
    }
}

dependencies {
    implementation(project(":internal:lintchecks"))
    implementation(project(":internal:chooserx"))
    implementation("com.google.android.material:material:1.13.0")
    implementation("androidx.activity:activity-ktx:1.13.0")

    // Import the Firebase BoM (see: https://firebase.google.com/docs/android/learn-more#bom)
    implementation(platform("com.google.firebase:firebase-bom:34.12.0"))

    // Firebase Crashlytics
    implementation("com.google.firebase:firebase-crashlytics")

    // For an optimal experience using Crashlytics, add the Firebase SDK
    // for Google Analytics. This is recommended, but not required.
    implementation("com.google.firebase:firebase-analytics")

    // For use in the CustomKeySamples -- for testing Google Api Availability.
    implementation("com.google.android.gms:play-services-base:18.10.0")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
