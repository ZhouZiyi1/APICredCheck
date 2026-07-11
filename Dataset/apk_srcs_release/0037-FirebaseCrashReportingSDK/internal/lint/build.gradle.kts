plugins {
    id("java-library")
    id("kotlin")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    compileOnly("com.android.tools.lint:lint-api:32.2.1")
    testImplementation("com.android.tools.lint:lint:32.2.1")
    testImplementation("com.android.tools.lint:lint-tests:32.2.1")
    testImplementation("junit:junit:4.13.2")
}

tasks.withType<Jar> {
    manifest {
        attributes("Lint-Registry-v2" to "com.firebase.lint.QuickstartIssueRegistry")
    }
}
