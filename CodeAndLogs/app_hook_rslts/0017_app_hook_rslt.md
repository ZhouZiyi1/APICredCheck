# 0017 FacebookCoreSDK App Hook Result

- Generated at: 2026-06-10T19:51:26
- Final status: success
- Final reason: facebook-ui-handoff
- Candidate methods from apk_analyze_rslts: 2
- Final target hook methods used: 0
- Generic runtime replacement hooks: 7
- Rejected methods: 0

## Runtime Replacement Values

- Package name: com.cefa.core.demo
- Cert SHA-1: E1E849B19182D16A212E66E11C9152BA8AEBA41A
- Cert SHA-256: 9B6D3A65DE5F2E5035AEB5070B6C0E04786F4F178022986B34E45BAAB878B60F
- Primary API key: unknown
- Additional API keys: 0
- Facebook app id: 222222222222222
- Facebook client token: bbbbbb**************************
- Facebook app access token: 222222******************************************
- Facebook login protocol scheme: fb222222222222222
- Facebook content-provider authority: com.facebook.app.FacebookContentProvider222222222222222
- GMS identity clone: disabled

## Generated Hook Scripts

- Full script: app_hook_rslts\0017_app_hook_full.js
- Full script command: `adb shell am force-stop com.cefa.core.attacker; adb shell monkey -p com.cefa.core.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.cefa.core.attacker -l "app_hook_rslts\0017_app_hook_full.js"`
- Fill-in template: app_hook_rslts\0017_app_hook_template.js
- Fill-in template command: `adb shell am force-stop com.cefa.core.attacker; adb shell monkey -p com.cefa.core.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.cefa.core.attacker -l "app_hook_rslts\0017_app_hook_template.js"`

## SDK Validation Summary

- Validation type: Facebook app credential plus Android app identity binding.
- Evidence: the target request used to verify SDK/API success is Facebook Graph `/{app_id}/activities`; local ShareDialog acceptance is not treated as SDK/API success.
- Checked values inferred from source/runtime hooks: Facebook ApplicationId, ClientToken, app access token (`app_id|client_token`), Android package name in app-events/extinfo, and Android signing certificate SHA-1 used by FacebookSdk application-signature code.
- Required bypass strategy: replace attacker Facebook metadata/token values with demo values, replace the package name embedded in the app-events JSON payload, and replace the signature digest only on the Facebook SDK signature-calculation stack.

## Candidate Method Decisions

1. `Lcom/facebook/FacebookSdk;->publishInstallAndWaitForResponse(Landroid/content/Context;Ljava/lang/String;)V`
   - Decision: not needed
   - Class: `com.facebook.FacebookSdk`
   - Method: `publishInstallAndWaitForResponse`
   - Descriptor: `(Landroid/content/Context;Ljava/lang/String;)V`
   - Reason: Not tested/used because an earlier hook set already reached SDK success; continuing would only add crash risk.

2. `Lcom/facebook/appevents/internal/AppEventsLoggerUtility;->getJSONObjectForGraphAPICall(...)Lorg/json/JSONObject;`
   - Decision: not needed
   - Class: `com.facebook.appevents.internal.AppEventsLoggerUtility`
   - Method: `getJSONObjectForGraphAPICall`
   - Descriptor: `(...)Lorg/json/JSONObject;`
   - Reason: Not tested/used because an earlier hook set already reached SDK success; continuing would only add crash risk.


## Adaptive Attempts

- baseline-passive-only: status=success, reason=facebook-ui-handoff, subset_size=0, stop_app_after=True

## Final Attempt Subset

Target-specific methods loaded by the final adaptive attempt.

The final successful attempt used no target-specific method hooks.

## Final Method List

These are the hooks loaded by the final successful script.

### Observer Hooks

1. `android.util.Log->i/d/w/e(String,String)`
   - Purpose: Observe APICREDTEST signals without accepting ShareDialog handoff as verified API success.
2. `com.facebook.GraphRequest->executeAndWait()`
   - Purpose: Observe the real Facebook Graph response and count only the app-events Graph success as verified SDK success.

Summary: observer hooks do not change SDK inputs. They only record app signals, SDK responses, crashes, and verified success/failure evidence.

### Runtime Replacement Hooks

1. `android.os.BaseBundle/android.os.Bundle->getString/putString(...)`
   - Replaces: facebookAppId/facebookClientToken/facebookAppAccessToken/facebookLoginProtocolScheme/facebookContentProviderAuthority
   - Purpose: Replace Facebook ApplicationId, ClientToken, access_token, protocol scheme, and content-provider authority metadata.
2. `com.facebook.FacebookSdk->getApplicationId/getClientToken/setApplicationId/setClientToken/publishInstallAndWaitForResponse(...)`
   - Replaces: facebookAppId/facebookClientToken
   - Purpose: Return or pass the demo-side Facebook app id and client token after SDK metadata initialization.
3. `org.json.JSONObject->put(String,Object)`
   - Replaces: packageName/facebookAppId/facebookClientToken/facebookAppAccessToken
   - Purpose: Replace app-events package/extinfo fields and Facebook credential fields before GraphRequest sends the payload.
4. `java.security.MessageDigest->digest(...)`
   - Replaces: certSha1
   - Purpose: Replace SHA-1 digest only while Facebook SDK computes the application signature.
5. `android.net.Uri$Builder->appendQueryParameter(String,String)`
   - Replaces: facebookAppAccessToken
   - Purpose: Replace Facebook access_token query parameters built as app_id|client_token.

Summary: runtime replacement hooks are the value-substitution layer. They replace attacker-side credentials, package identity, certificate digests, or request fields with demo-side values so the SDK request can pass validation.


## SDK Invocation Result

- Instrumented/replaced SDK call result: success (final_status=success, reason=facebook-ui-handoff).
- SDK protection measures: Facebook Core validates Facebook application credentials and Android app identity before accepting Graph/app-events calls: ApplicationId, ClientToken, app access token, package/extinfo, and signing-certificate SHA-1.
