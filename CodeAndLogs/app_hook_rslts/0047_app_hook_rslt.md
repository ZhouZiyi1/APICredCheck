# 0047 GoogleMobileAdsSDK App Hook Result

- Generated at: 2026-06-10T19:55:25
- Final status: success
- Final reason: sdk-call-success
- Candidate methods from apk_analyze_rslts: 1
- Final target hook methods used: 0
- Generic runtime replacement hooks: 5
- Rejected methods: 0

## Runtime Replacement Values

- Package name: com.google.mobileads.demo
- Cert SHA-1: E1E849B19182D16A212E66E11C9152BA8AEBA41A
- Cert SHA-256: 9B6D3A65DE5F2E5035AEB5070B6C0E04786F4F178022986B34E45BAAB878B60F
- Primary API key: unknown
- Additional API keys: 0
- AdMob app id: ca-app********************************
- AdMob ad unit id: ca-app********************************
- Demo manifest APPLICATION_ID: ca-app********************************
- GMS identity clone: disabled

## Generated Hook Scripts

- Full script: app_hook_rslts\0047_app_hook_full.js
- Full script command: `adb shell am force-stop com.google.mobileads.attacker; adb shell monkey -p com.google.mobileads.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.google.mobileads.attacker -l "app_hook_rslts\0047_app_hook_full.js"`
- Fill-in template: app_hook_rslts\0047_app_hook_template.js
- Fill-in template command: `adb shell am force-stop com.google.mobileads.attacker; adb shell monkey -p com.google.mobileads.attacker -c android.intent.category.LAUNCHER 1; frida -U -n com.google.mobileads.attacker -l "app_hook_rslts\0047_app_hook_template.js"`

## SDK Validation Summary

- Validation type: AdMob publisher/app configuration lookup.
- Evidence: failures such as `Publisher data not found` come from Google Mobile Ads when the app id or ad unit id does not match a known publisher configuration.
- Checked values inferred from source/runtime hooks: `com.google.android.gms.ads.APPLICATION_ID`, ad unit id, and MobileAds/ad-view initialization values.
- Required bypass strategy: keep package/certificate hooks narrow and replace only AdMob app-id/ad-unit-id values with demo-side values.

## Candidate Method Decisions

1. `Lcom/google/android/gms/ads/BaseAdView;->setAdUnitId(Ljava/lang/String;)V`
   - Decision: not needed
   - Class: `com.google.android.gms.ads.BaseAdView`
   - Method: `setAdUnitId`
   - Descriptor: `(Ljava/lang/String;)V`
   - Reason: Not tested/used because an earlier hook set already reached SDK success; continuing would only add crash risk.


## Adaptive Attempts

- baseline-passive-only: status=success, reason=sdk-call-success, subset_size=0, stop_app_after=True

## Final Attempt Subset

Target-specific methods loaded by the final adaptive attempt.

The final successful attempt used no target-specific method hooks.

## Final Method List

These are the hooks loaded by the final successful script.

### Observer Hooks

1. `android.util.Log->i/d/w/e(String,String)`
   - Purpose: Observe APICREDTEST signals emitted by the attacker app.

Summary: observer hooks do not change SDK inputs. They only record app signals, SDK responses, crashes, and verified success/failure evidence.

### Runtime Replacement Hooks

1. `android.os.BaseBundle->getString/putString(...)`
   - Replaces: admobAppId
   - Purpose: Patch only com.google.android.gms.ads.APPLICATION_ID values read from metadata bundles.
2. `com.google.android.gms.ads.internal.util.zzm->zzaz/zzd(...)`
   - Replaces: admobAppId
   - Purpose: Return the demo-side AdMob application id when the SDK validates manifest metadata.
3. `com.google.android.gms.ads.*->setAdUnitId(String)`
   - Replaces: admobAdUnitId
   - Purpose: Use the demo-side AdMob ad-unit id at SDK public/internal ad-view entry points.
4. `com.google.android.gms.ads.MobileAds->initialize(...)`
   - Replaces: admobAppId
   - Purpose: Fill only missing or invalid String app-id initialization overloads; listener/settings overloads are left untouched.

Summary: runtime replacement hooks are the value-substitution layer. They replace attacker-side credentials, package identity, certificate digests, or request fields with demo-side values so the SDK request can pass validation.


## SDK Invocation Result

- Instrumented/replaced SDK call result: success (final_status=success, reason=sdk-call-success).
- SDK protection measures: AdMob validates publisher configuration, mainly the manifest application id and ad-unit id bound to a known publisher setup.
