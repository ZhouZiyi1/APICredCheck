# 0023 GoogleMapsSDK App Hook Result

- Generated at: 2026-06-10T19:53:23
- Final status: success
- Final reason: map-visual-loaded
- Candidate methods from apk_analyze_rslts: 0
- Final target hook methods used: 0
- Generic runtime replacement hooks: 31
- Rejected methods: 0

## Runtime Replacement Values

- Package name: com.google.map.demo
- Cert SHA-1: E1E849B19182D16A212E66E11C9152BA8AEBA41A
- Cert SHA-256: 9B6D3A65DE5F2E5035AEB5070B6C0E04786F4F178022986B34E45BAAB878B60F
- Primary API key: AIzaSy*********************************
- Additional API keys: 0
- GMS identity clone: disabled

## Generated Hook Scripts

- Full script: app_hook_rslts\0023_app_hook_full.js
- Full script command: `adb shell am force-stop com.google.map.attacker; adb shell monkey -p com.google.map.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.google.map.attacker -l "app_hook_rslts\0023_app_hook_full.js"`
- Fill-in template: app_hook_rslts\0023_app_hook_template.js
- Fill-in template command: `adb shell am force-stop com.google.map.attacker; adb shell monkey -p com.google.map.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.google.map.attacker -l "app_hook_rslts\0023_app_hook_template.js"`

## SDK Validation Summary

- Validation type: Google API key restriction plus Android caller identity verification.
- Evidence: Maps/Location auth paths use package name, signing certificate digest, and GMS UID/package checks before returning service tokens or usable SDK results.
- Checked values inferred from source/runtime hooks: API key, Android package name, SHA-1/SHA-256 certificate fingerprints, PackageManager UID mappings, AppOps package checks, and GMS UidVerifier/PackageManagerWrapper checks.
- Required bypass strategy: replace package/key/certificate values and allow the demo package to pass auxiliary GMS UID/package validation for the attacker UID.

## Candidate Method Decisions

No candidate hook methods were loaded from apk_analyze_rslts.

## Adaptive Attempts

- baseline-passive-only: status=success, reason=map-visual-loaded, subset_size=0, stop_app_after=True

## Final Attempt Subset

Target-specific methods loaded by the final adaptive attempt.

The final successful attempt used no target-specific method hooks.

## Final Method List

These are the hooks loaded by the final successful script.

### Observer Hooks

1. `android.util.Log->i/d/w/e(String,String)`
   - Purpose: Observe APICREDTEST signals emitted by the attacker app, including SDK call success/failure/crash markers.
2. `java.security.MessageDigest->getInstance(...)`
   - Purpose: Observe digest algorithm selection before certificate digest replacement.
3. `java.net.URL->$init(...)`
   - Purpose: Observe sensitive URL construction before network requests are sent.

Summary: observer hooks do not change SDK inputs. They only record app signals, SDK responses, crashes, and verified success/failure evidence.

### Runtime Replacement Hooks

1. `android.content.ContextWrapper->getPackageName()`
   - Replaces: packageName
   - Purpose: Replace the attacker package name with the demo package name in SDK authentication paths.
2. `android.app.ContextImpl->getPackageName()`
   - Replaces: packageName
   - Purpose: Replace the attacker package name with the demo package name in SDK authentication paths.
3. `android.app.ApplicationPackageManager->getApplicationInfo(...)`
   - Replaces: packageName
   - Purpose: Patch ApplicationInfo.packageName for SDK authentication code that reads caller identity.
4. `android.app.ApplicationPackageManager->getPackageInfo(...)`
   - Replaces: packageName
   - Purpose: Patch PackageInfo.packageName for SDK authentication code that reads caller identity.
5. `android.app.ApplicationPackageManager->getPackagesForUid(int)`
   - Replaces: packageName
   - Purpose: Let GMS auxiliary authentication checks see the demo package alongside the attacker package for the caller UID.
6. `android.app.ApplicationPackageManager->getNameForUid(int)`
   - Replaces: packageName
   - Purpose: Replace attacker package identity with demo package identity in narrowly-scoped GMS auxiliary checks.
7. `android.app.AppOpsManager->checkPackage(int,String)`
   - Replaces: uidPackageCheck
   - Purpose: Allow GMS auxiliary UID/package validation when it checks the demo package for the attacker UID.
8. `com.google.android.gms.common.util.UidVerifier->uidHasPackageName(...)`
   - Replaces: uidPackageCheck
   - Purpose: Allow Google Play services UID/package validation for the demo package during Maps/Location authentication.
9. `com.google.android.gms.common.wrappers.PackageManagerWrapper->zza(...)`
   - Replaces: uidPackageCheck
   - Purpose: Allow Google Play services wrapper UID/package validation for the demo package during Maps/Location authentication.
10. `java.security.MessageDigest->digest(...)`
   - Replaces: certSha1/certSha256
   - Purpose: Replace SHA-1/SHA-256 digest bytes when SDK code derives Android certificate fingerprints, including GMS GoogleCertificates stacks for Maps/Location.
11. `android.os.Bundle->getString(...)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace sensitive bundle values if API key, package, or certificate fields pass through Bundle metadata.
12. `android.os.Bundle->putString(...)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace sensitive bundle values if API key, package, or certificate fields are written to Bundle metadata.
13. `android.content.res.Resources->getString/getText(...)`
   - Replaces: primaryApiKey/oneSignalAppId
   - Purpose: Replace sensitive resource strings such as google_api_key when app or SDK code reads values generated from google-services resources.
14. `android.app.SharedPreferencesImpl->getString/EditorImpl.putString(...)`
   - Replaces: oneSignalAppId
   - Purpose: Replace cached SDK credential values before app code passes them into SDK initialization.
15. `com.google.firebase.FirebaseOptions->getApiKey()`
   - Replaces: primaryApiKey
   - Purpose: Return the replacement API key when Firebase SDK code reads FirebaseApp options after google-services initialization.
16. `android.net.Uri$Builder->appendQueryParameter(String,String)`
   - Replaces: primaryApiKey
   - Purpose: Replace URL query credential fields, especially key=<apiKey>.
17. `java.net.URL->openConnection(...)`
   - Replaces: packageName/certSha1
   - Purpose: Patch Android authentication headers immediately after a URLConnection is created.
18. `java.net.URLConnection->connect()`
   - Replaces: packageName/certSha1
   - Purpose: Patch Android authentication headers immediately before URLConnection sends a request.
19. `java.net.URLConnection->getInputStream()`
   - Replaces: packageName/certSha1
   - Purpose: Patch Android authentication headers before lazy URLConnection request execution.
20. `java.net.URLConnection->getOutputStream()`
   - Replaces: packageName/certSha1
   - Purpose: Patch Android authentication headers before lazy URLConnection request execution with a request body.
21. `java.net.HttpURLConnection->connect()`
   - Replaces: packageName/certSha1
   - Purpose: Patch Android authentication headers immediately before HttpURLConnection sends a request.
22. `java.net.HttpURLConnection->setRequestProperty(String,String)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace request header values when API key, package, or certificate fields are set explicitly.
23. `java.net.URLConnection->setRequestProperty(String,String)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace request header values when API key, package, or certificate fields are set explicitly.
24. `java.net.URLConnection->addRequestProperty(String,String)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace added request header values when API key, package, or certificate fields are set explicitly.
25. `okhttp3.Request$Builder->header(String,String)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace OkHttp header values when OkHttp is present in the attacker app.
26. `okhttp3.Request$Builder->addHeader(String,String)`
   - Replaces: packageName/certSha1/certSha256/primaryApiKey
   - Purpose: Replace added OkHttp header values when OkHttp is present in the attacker app.
27. `com.onesignal.internal.*->initWithContext(Context,String) and config setAppId(String)`
   - Replaces: oneSignalAppId
   - Purpose: Replace OneSignal App ID at SDK initialization and model configuration entry points.
28. `org.json.JSONObject->put(String,Object)`
   - Replaces: oneSignalAppId
   - Purpose: Replace OneSignal App ID in REST request bodies before the app sends OneSignal API calls.

Summary: runtime replacement hooks are the value-substitution layer. They replace attacker-side credentials, package identity, certificate digests, or request fields with demo-side values so the SDK request can pass validation.


## SDK Invocation Result

- Instrumented/replaced SDK call result: success (final_status=success, reason=map-visual-loaded).
- SDK protection measures: Google Maps/Location validates API key restrictions together with Android package/certificate identity and GMS UID/package checks.
