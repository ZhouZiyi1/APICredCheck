pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

include(":app")

// Required so that gradle can resolve these dependencies even when
// building only a single project.
include(":internal")
project(":internal").projectDir = file("../internal")
include(":internal:lintchecks")
project(":internal:lintchecks").projectDir = file("../internal/lintchecks")
include(":internal:lint")
project(":internal:lint").projectDir = file("../internal/lint")
include(":internal:chooserx")
project(":internal:chooserx").projectDir = file("../internal/chooserx")
