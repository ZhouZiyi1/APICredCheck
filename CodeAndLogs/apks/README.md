# APK Inputs

This directory is the default APK input directory used by the runnable
APICredCheck scripts in `CodeAndLogs/`.

It should contain paired legitimate and attacker APK files for each evaluated
SDK. File names should follow this convention:

- `<SDK_ID>-<SDK_NAME>-demo.apk`
- `<SDK_ID>-<SDK_NAME>-attacker.apk`

For example:

- `0001-GoogleFirebaseSDK-demo.apk`
- `0001-GoogleFirebaseSDK-attacker.apk`

The `demo` APK is the legitimate app, and the `attacker` APK is the paired
attacker app with a different Android client identity and an invalid credential.

This release directory includes only one APK pair as an example input. The full
released APK example set is provided under `../../Dataset/apks/`.

Released APKs in both locations are sanitized examples and do not contain real,
currently effective API credentials. In particular, the released legitimate APKs
are not expected to successfully invoke SDK APIs that require valid
provider-issued credentials. To reproduce such calls, request your own
credentials from the SDK providers, insert them into the legitimate source
projects under `../../Dataset/apk_srcs_release/`, and rebuild the APKs.
