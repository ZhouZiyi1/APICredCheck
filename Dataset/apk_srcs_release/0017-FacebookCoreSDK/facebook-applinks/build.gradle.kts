/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */


@file:Suppress("UnstableApiUsage")

plugins {
    id("com.android.library")
    id("kotlin-android")
}

group = "com.facebook.android"

extra["name"] = "Facebook-Applinks-Android-SDK"

extra["artifactId"] = "facebook-applinks"

extra["description"] = "Facebook Applinks Android SDK"

extra["url"] = "https://github.com/facebook/facebook-android-sdk"

dependencies {
    // Facebook Dependencies
    api(project(":facebook-core"))
    // Support Dependencies
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.legacy.support.core.utils)
}

android {
    buildToolsVersion = libs.versions.buildToolsVersion.get()
    namespace = "com.facebook.applinks"
    compileSdk = libs.versions.compileSdk.get().toInt()


    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        consumerProguardFiles("proguard-rules.pro")
    }

    sourceSets {
        getByName("test")
        { java.srcDir("src/test/kotlin") }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
        }
    }
    
    compileOptions {
        sourceCompatibility(JavaVersion.VERSION_1_8)
        targetCompatibility(JavaVersion.VERSION_1_8)
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }
}

if (file("${rootDir}/internal/safekit-build.gradle").exists()) {
    project.apply(from = "${rootDir}/internal/safekit-build.gradle")
}

apply(from = "${rootDir}/maven.gradle")


