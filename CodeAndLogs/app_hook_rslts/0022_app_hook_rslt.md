# 0022 FacebookShareKitSDK App Hook Result

- Generated at: 2026-06-10T19:52:47
- Final status: success
- Final reason: sdk-call-success
- Candidate methods from apk_analyze_rslts: 4
- Final target hook methods used: 1
- Generic runtime replacement hooks: 11
- Rejected methods: 0

## Runtime Replacement Values

- Package name: com.cefa.share.demo
- Cert SHA-1: E1E849B19182D16A212E66E11C9152BA8AEBA41A
- Cert SHA-256: 9B6D3A65DE5F2E5035AEB5070B6C0E04786F4F178022986B34E45BAAB878B60F
- Primary API key: _APP_ID_PAIR_SERIALIZATION_PROXY_V1_CLASS_NAME
- Additional API keys: 0
- GMS identity clone: disabled

## Generated Hook Scripts

- Full script: app_hook_rslts\0022_app_hook_full.js
- Full script command: `adb shell am force-stop com.cefa.share.attacker; adb shell monkey -p com.cefa.share.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.cefa.share.attacker -l "app_hook_rslts\0022_app_hook_full.js"`
- Fill-in template: app_hook_rslts\0022_app_hook_template.js
- Fill-in template command: `adb shell am force-stop com.cefa.share.attacker; adb shell monkey -p com.cefa.share.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.cefa.share.attacker -l "app_hook_rslts\0022_app_hook_template.js"`

## SDK Validation Summary

- Validation type: Facebook app credential plus Android app identity binding for the ShareKit dialog flow.
- Evidence: a successful ShareKit SDK invocation is recognized when the SDK completes `ShareDialog.show(...)`, enters `FacebookDialogBase.show(...)`, dispatches `DialogPresenter.present(...)`, or starts the Facebook platform/browser handoff intent.
- Checked values inferred from source/runtime hooks: Facebook ApplicationId, ClientToken, app access token (`app_id|client_token`), login protocol scheme, content-provider authority, Android package name in app-events/extinfo, and Android signing certificate SHA-1 used by FacebookSdk application-signature code.
- Required bypass strategy: replace attacker Facebook metadata/token values with demo values, replace package identity embedded in SDK payloads, and replace the signature digest only on the Facebook SDK signature-calculation stack while observing the ShareKit dialog handoff as success.

## Candidate Method Decisions

1. `Lcom/facebook/FacebookSdk;->getApplicationId()Ljava/lang/String;`
   - Decision: selected
   - Class: `com.facebook.FacebookSdk`
   - Method: `getApplicationId`
   - Descriptor: `()Ljava/lang/String;`
   - Reason: Included in the final successful hook set.

2. `Lcom/facebook/FacebookSdk;->getClientToken()Ljava/lang/String;`
   - Decision: not needed
   - Class: `com.facebook.FacebookSdk`
   - Method: `getClientToken`
   - Descriptor: `()Ljava/lang/String;`
   - Reason: Not tested/used because an earlier hook set already reached SDK success; continuing would only add crash risk.

3. `Lcom/facebook/appevents/internal/AppEventsLoggerUtility;->getJSONObjectForGraphAPICall(...)Lorg/json/JSONObject;`
   - Decision: not needed
   - Class: `com.facebook.appevents.internal.AppEventsLoggerUtility`
   - Method: `getJSONObjectForGraphAPICall`
   - Descriptor: `(...)Lorg/json/JSONObject;`
   - Reason: Not tested/used because an earlier hook set already reached SDK success; continuing would only add crash risk.

4. `Lcom/facebook/FacebookSdk;->publishInstallAndWaitForResponse(Landroid/content/Context;Ljava/lang/String;)V`
   - Decision: not needed
   - Class: `com.facebook.FacebookSdk`
   - Method: `publishInstallAndWaitForResponse`
   - Descriptor: `(Landroid/content/Context;Ljava/lang/String;)V`
   - Reason: Not tested/used because an earlier hook set already reached SDK success; continuing would only add crash risk.


## Adaptive Attempts

- baseline-passive-only: status=failure, reason=facebook-graph-response-failure, subset_size=0, stop_app_after=True
- add-1: status=success, reason=sdk-call-success, subset_size=1, stop_app_after=True

## Final Attempt Subset

Target-specific methods loaded by the final adaptive attempt.

1. `Lcom/facebook/FacebookSdk;->getApplicationId()Ljava/lang/String;`

## Final Method List

These are the hooks loaded by the final successful script.

### Observer Hooks

1. `android.util.Log->i/d/w/e(String,String)`
   - Purpose: Observe APICREDTEST signals emitted by the attacker app.
2. `com.facebook.share.widget.ShareDialog->show(...)`
   - Purpose: Observe the public ShareKit dialog API call and treat a completed SDK dialog invocation as ShareKit success.
3. `com.facebook.internal.FacebookDialogBase->show(...)`
   - Purpose: Observe ShareKit's internal dialog base class when it dispatches the share content.
4. `com.facebook.internal.DialogPresenter->present(...)`
   - Purpose: Observe the SDK handoff from ShareKit into Facebook platform/web dialog presentation.
5. `com.facebook.internal.DialogPresenter->startActivityForResultWithAndroidX(...)`
   - Purpose: Observe AndroidX-based Facebook dialog handoff launched by ShareKit.
6. `android.app.Activity->startActivityForResult(...)`
   - Purpose: Observe Facebook platform or browser intents started by the SDK dialog flow.

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
   - Purpose: Replace app-events package/extinfo fields and Facebook credential fields before ShareKit/FacebookSdk builds telemetry or Graph payloads.
4. `java.security.MessageDigest->digest(...)`
   - Replaces: certSha1
   - Purpose: Replace SHA-1 digest only while Facebook SDK computes the application signature.
5. `android.net.Uri$Builder->appendQueryParameter(String,String)`
   - Replaces: facebookAppAccessToken
   - Purpose: Replace Facebook access_token query parameters built as app_id|client_token.

Summary: runtime replacement hooks are the value-substitution layer. They replace attacker-side credentials, package identity, certificate digests, or request fields with demo-side values so the SDK request can pass validation.


## SDK Invocation Result

- Instrumented/replaced SDK call result: success (final_status=success, reason=sdk-call-success).
- SDK protection measures: Facebook ShareKit validates Facebook application credentials together with Android caller identity: ApplicationId/ClientToken/app access token, login protocol scheme/content-provider authority, package name, and signing-certificate SHA-1 used by FacebookSdk.
