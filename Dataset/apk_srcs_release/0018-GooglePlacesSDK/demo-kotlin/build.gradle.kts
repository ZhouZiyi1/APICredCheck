/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    id("places-demo.android.application")
    alias(libs.plugins.jetbrains.kotlin.android)
    id("places-demo.secrets")
    alias(libs.plugins.jetbrains.kotlin.parcelize)
    kotlin("kapt")
}

android {
    namespace = "com.google.places.demo"

    defaultConfig {
        applicationId = "com.google.places.demo"
        versionCode = 1
        versionName = "1.0"

        multiDexEnabled = true
    }

    signingConfigs {
        create("demo") {
            storeFile = rootProject.file("../lawgeek.jks")
            storePassword = "lawgeek"
            keyAlias = "key0"
            keyPassword = "lawgeek"
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("demo")
        }
        getByName("release") {
            signingConfig = signingConfigs.getByName("demo")
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    kotlin {
        compilerOptions {
            freeCompilerArgs.addAll(
                "-opt-in=kotlin.RequiresOptIn",
                "-Xannotation-default-target=param-property",
                "-Xskip-metadata-version-check"
            )
        }
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.core.ktx)
    implementation(libs.material)

    implementation(libs.volley)
    implementation(libs.glide)
    kapt(libs.glide.compiler)
    implementation(libs.viewbinding)
    implementation(libs.multidex)

    // Google Places
    implementation(libs.places)
    implementation(libs.maps.utils.ktx)
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalizedVariantName = variant.name.replaceFirstChar { it.uppercaseChar() }
        val fixedApkName = "0018-GooglePlacesSDK-demo.apk"
        val copyTask = tasks.register<Copy>("copy${capitalizedVariantName}ApkWithFixedName") {
            from(variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.APK))
            into(layout.buildDirectory.dir("outputs/renamed-apk/${variant.name}"))
            include("*.apk")
            exclude(fixedApkName)
            rename { fixedApkName }
        }
        tasks.matching { it.name == "assemble$capitalizedVariantName" }.configureEach {
            finalizedBy(copyTask)
        }
    }
}
