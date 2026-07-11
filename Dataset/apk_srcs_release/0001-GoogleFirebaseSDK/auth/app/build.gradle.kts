import com.android.build.gradle.internal.tasks.factory.dependsOn

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.google.services)
}

tasks {
    check.dependsOn("assembleDebugAndroidTest")
}

android {
    namespace = "com.google.firebase.demo"
    compileSdk = 35

    flavorDimensions += "minSdkVersion"

    defaultConfig {
        applicationId = "com.google.firebase.demo"
        minSdk = 23
        targetSdk = 35

        versionCode = 1
        versionName = "1.0"
        multiDexEnabled = true
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("demo") {
            storeFile = rootProject.file("../../lawgeek.jks")
            storePassword = "lawgeek"
            keyAlias = "key0"
            keyPassword = "lawgeek"
        }
    }

    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("demo")
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    lint {
        baseline = file("lint-baseline.xml")
        disable += "InvalidFragmentVersionForActivityResult"
    }
}

androidComponents {
    onVariants(selector().withBuildType("release")) { variant ->
        val fixedApkName = "0001-GoogleFirebaseSDK-demo.apk"
        val copyTask = tasks.register<Copy>("copyReleaseApkWithFixedName") {
            from(variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.APK))
            into(layout.buildDirectory.dir("outputs/renamed-apk/release"))
            include("*.apk")
            exclude(fixedApkName)
            rename { fixedApkName }
        }
        tasks.matching { it.name == "assembleRelease" }.configureEach {
            finalizedBy(copyTask)
        }
    }
}

dependencies {
    implementation(project(":internal:chooserx"))
    implementation(project(":internal:lintchecks"))

    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation("androidx.fragment:fragment:1.8.5")
    implementation("androidx.activity:activity:1.10.0")


    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.vectordrawable:vectordrawable-animated:1.2.0")
    implementation("com.google.android.material:material:1.13.0")
    implementation("androidx.navigation:navigation-fragment-ktx:2.9.8")
    implementation("androidx.navigation:navigation-ui-ktx:2.9.8")

    // Import the Firebase BoM (see: https://firebase.google.com/docs/android/learn-more#bom)
    implementation(platform("com.google.firebase:firebase-bom:34.12.0"))

    // Firebase Authentication
    implementation("com.google.firebase:firebase-auth")

    // Google Identity Services SDK (only required for Auth with Google)
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")
    implementation("com.google.android.libraries.identity.googleid:googleid:1.2.0")

    // Firebase UI
    // Used in FirebaseUIActivity.
    implementation("com.firebaseui:firebase-ui-auth:9.1.1")

    // Facebook Android SDK (only required for Facebook Login)
    // Used in FacebookLoginActivity.
    implementation("com.facebook.android:facebook-login:13.2.0")
    implementation("androidx.browser:browser:1.5.0")

    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
