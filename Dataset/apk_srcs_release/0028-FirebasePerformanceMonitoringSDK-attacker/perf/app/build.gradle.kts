
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.google.services)
    alias(libs.plugins.firebase.perf)
}

android {
    namespace = "com.firebase.perf.attacker"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.firebase.perf.attacker"
        minSdk = 23
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
//            configure<FirebasePerfExtension> {
//                 Set this flag to 'false' to disable @AddTrace annotation processing and
//                 automatic HTTP/S network request monitoring
//                 for a specific build variant at compile time.
//                setInstrumentationEnabled(true)
//            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
    }
    lint {
        // TODO(thatfiredev): Remove this once
        //  https://github.com/bumptech/glide/issues/4940 is fixed
        disable.add("NotificationPermission")
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalizedVariantName = variant.name.replaceFirstChar { it.uppercaseChar() }
        val fixedApkName = "0028-FirebasePerformanceMonitoringSDK-attacker.apk"
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

    // Import the Firebase BoM (see: https://firebase.google.com/docs/android/learn-more#bom)
    implementation(platform("com.google.firebase:firebase-bom:34.12.0"))

    // Firebase Performance Monitoring
    implementation("com.google.firebase:firebase-perf")

    implementation("com.google.android.material:material:1.13.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")

    implementation("com.github.bumptech.glide:glide:4.12.0")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
}
