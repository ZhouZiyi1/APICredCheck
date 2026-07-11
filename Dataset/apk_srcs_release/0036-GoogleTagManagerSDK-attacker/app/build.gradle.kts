plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.gms.google-services")
}

android {
    namespace = "com.google.tagmanager.attacker"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.google.tagmanager.attacker"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("attacker") {
            storeFile = rootProject.file("../attacker.jks")
            storePassword = "lawgeek"
            keyAlias = "key0"
            keyPassword = "lawgeek"
        }
    }

    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("attacker")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        getByName("debug") {
            signingConfig = signingConfigs.getByName("attacker")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalizedVariantName = variant.name.replaceFirstChar { it.uppercaseChar() }
        val fixedApkName = "0036-GoogleTagManagerSDK-attacker.apk"
        val copyTask = tasks.register<Copy>("copy${capitalizedVariantName}ApkWithFixedName") {
            from(variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.APK))
            into(rootProject.file("../../apks"))
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
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.0")
    implementation("androidx.activity:activity-ktx:1.9.3")

    implementation(platform("com.google.firebase:firebase-bom:34.13.0"))
    implementation("com.google.firebase:firebase-analytics")

    implementation("com.google.android.gms:play-services-tagmanager:18.1.1")

}
