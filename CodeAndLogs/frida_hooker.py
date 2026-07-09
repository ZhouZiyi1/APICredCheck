import json
import queue
import re
import subprocess
import tempfile
import threading
import time
from io import BytesIO
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

import frida


@dataclass
class HookRunResult:
    status: str
    reason: Optional[str] = None
    crash: Optional[object] = None
    last_signal: Optional[str] = None
    attempts: int = 1


PASSIVE_MONITOR_JS = r"""
var __replacementRoot = (typeof globalThis !== "undefined") ? globalThis : this;
var RUNTIME_REPLACEMENTS = __replacementRoot.RUNTIME_REPLACEMENTS || {};
var PACKAGE_STACK_MISS_LOG_COUNT = 0;
var PACKAGE_STACK_MISS_LOG_LIMIT = 20;
var PACKAGE_REPLACEMENT_SKIP_LOG_COUNT = 0;
var PACKAGE_REPLACEMENT_SKIP_LOG_LIMIT = 30;
var PARCEL_PACKAGE_LOG_COUNT = 0;
var PARCEL_PACKAGE_LOG_LIMIT = 60;
var DIGEST_DIAGNOSTIC_LOG_COUNT = 0;
var DIGEST_DIAGNOSTIC_LOG_LIMIT = 100;
var MAPS_GMS_TOKEN_AUTH_WINDOW_UNTIL = 0;

function maskValue(value) {
    if (value === null || value === undefined) return String(value);
    return String(value);
}

function looksSensitive(name, value) {
    var n = String(name || "").toLowerCase();
    var v = String(value || "");
    return n.indexOf("key") >= 0 ||
           n.indexOf("token") >= 0 ||
           n.indexOf("cert") >= 0 ||
           n.indexOf("package") >= 0 ||
           n.indexOf("sha") >= 0 ||
           n.indexOf("applicationid") >= 0 ||
           n.indexOf("clienttoken") >= 0 ||
           v.indexOf("AIza") >= 0;
}

function logEvent(kind, fields) {
    fields.kind = kind;
    fields.ts = Date.now();
    fields.process = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.instrumentedProcess) || "target");
    send(fields);
}

function replacementEnabled() {
    return !!(RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.enabled);
}

function replacementValue(kind) {
    if (!replacementEnabled()) return null;
    if (kind === "package") return RUNTIME_REPLACEMENTS.packageName || null;
    if (kind === "cert_sha1") return RUNTIME_REPLACEMENTS.certSha1 || null;
    if (kind === "cert_sha256") return RUNTIME_REPLACEMENTS.certSha256 || null;
    if (kind === "api_key") return RUNTIME_REPLACEMENTS.primaryApiKey || null;
    if (kind === "admob_app_id") return RUNTIME_REPLACEMENTS.admobAppId || null;
    if (kind === "admob_ad_unit_id") return RUNTIME_REPLACEMENTS.admobAdUnitId || null;
    if (kind === "facebook_app_id") return RUNTIME_REPLACEMENTS.facebookAppId || null;
    if (kind === "facebook_client_token") return RUNTIME_REPLACEMENTS.facebookClientToken || null;
    if (kind === "facebook_app_access_token") return RUNTIME_REPLACEMENTS.facebookAppAccessToken || null;
    if (kind === "facebook_login_protocol_scheme") return RUNTIME_REPLACEMENTS.facebookLoginProtocolScheme || null;
    if (kind === "facebook_content_provider_authority") return RUNTIME_REPLACEMENTS.facebookContentProviderAuthority || null;
    if (kind === "onesignal_app_id") return RUNTIME_REPLACEMENTS.oneSignalAppId || null;
    return null;
}

function packageReplacementMode() {
    return String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.packageReplacementMode) || "places_auth_stack");
}

function isBroadPackageReplacementMode() {
    return packageReplacementMode() === "google_maps_location_broad";
}

function isAdMobReplacementMode() {
    var sdkName = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.sdkName) || "").toLowerCase();
    var normalizedSdkName = sdkName.replace(/[^a-z0-9]+/g, "");
    return packageReplacementMode() === "admob_safe" ||
           sdkName.indexOf("admob") >= 0 ||
           sdkName.indexOf("mobile ads") >= 0 ||
           normalizedSdkName.indexOf("mobileads") >= 0 ||
           normalizedSdkName.indexOf("googlemobileads") >= 0;
}

function isFacebookReplacementMode() {
    var sdkName = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.sdkName) || "").toLowerCase();
    return packageReplacementMode() === "facebook_core" ||
           packageReplacementMode() === "facebook_share_kit" ||
           sdkName.indexOf("facebook") >= 0;
}

function isFacebookShareKitReplacementMode() {
    var sdkName = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.sdkName) || "").toLowerCase();
    return packageReplacementMode() === "facebook_share_kit" ||
           (sdkName.indexOf("facebook") >= 0 && sdkName.indexOf("share") >= 0);
}

function isOneSignalReplacementMode() {
    var sdkName = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.sdkName) || "").toLowerCase();
    var normalizedSdkName = sdkName.replace(/[^a-z0-9]+/g, "");
    return packageReplacementMode() === "onesignal_core" ||
           sdkName.indexOf("onesignal") >= 0 ||
           normalizedSdkName.indexOf("onesignal") >= 0;
}

function isRuntimePackageValue(value) {
    var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
    return !!(runtimePkg && String(value || "") === String(runtimePkg));
}

function isGmsAuxiliaryReplacementProcess() {
    return !!(
        RUNTIME_REPLACEMENTS &&
        RUNTIME_REPLACEMENTS.replaceLocalBundlePackageName &&
        packageReplacementMode() === "google_maps_location_broad"
    );
}

function isRuntimeReplacementProcess() {
    var proc = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.instrumentedProcess) || "");
    var runtimePkg = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.runtimePackageName) || "");
    return !!(proc && runtimePkg && proc === runtimePkg);
}

function isInstrumentedGmsProcess() {
    var proc = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.instrumentedProcess) || "");
    return proc === "com.google.android.gms";
}

function shouldReplaceMapsDynamiteParcelPackageName() {
    return !!(RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.replaceMapsDynamiteParcelPackageName);
}

function shouldReplaceGoogleCertificatesQueryPackageName() {
    return !!(RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.replaceGoogleCertificatesQueryPackageName);
}

function digestReplacementDisabled() {
    return !!(RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.disableDigestReplacement);
}

function urlConnectionHeaderPatchDisabled() {
    return !!(RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.disableUrlConnectionHeaderPatch);
}

function shouldSpoofUidPackage(packageName) {
    var demoPkg = replacementValue("package");
    return !!(isGmsAuxiliaryReplacementProcess() && demoPkg && String(packageName || "") === String(demoPkg));
}

function isExplicitPackageCredentialKey(key) {
    var k = String(key || "").toLowerCase();
    return k === "x-android-package" ||
           k.indexOf("x-android-package") >= 0 ||
           k.indexOf("android_package") >= 0 ||
           k.indexOf("android-package") >= 0 ||
           k.indexOf("android package") >= 0;
}

function looksLikeDigest(value, hexLength) {
    var s = String(value || "").replace(/:/g, "");
    var pattern = hexLength === 64 ? /^[0-9a-fA-F]{64}$/ : /^[0-9a-fA-F]{40}$/;
    return pattern.test(s);
}

function looksLikeApiKey(value) {
    var s = String(value || "");
    return /^AIza[0-9A-Za-z_\-]{20,}$/.test(s);
}

function looksLikeAdMobAppId(value) {
    var s = String(value || "");
    return /^ca-app-pub-\d{16}~\d{10}$/.test(s) || /^\/\d+~.+$/.test(s);
}

function looksLikeAdMobAdUnitId(value) {
    var s = String(value || "");
    return /^ca-app-pub-\d{16}\/\d{10}$/.test(s);
}

function looksLikeFacebookAppId(value) {
    return /^\d{12,18}$/.test(String(value || ""));
}

function looksLikeFacebookClientToken(value) {
    return /^[0-9a-fA-F]{32}$/.test(String(value || ""));
}

function looksLikeFacebookAppAccessToken(value) {
    return /^\d{12,18}\|[0-9a-fA-F]{32}$/.test(String(value || ""));
}

function looksLikeFacebookLoginProtocolScheme(value) {
    return /^fb\d{12,18}$/.test(String(value || ""));
}

function looksLikeFacebookContentProviderAuthority(value) {
    return /^com\.facebook\.app\.FacebookContentProvider\d{12,18}$/.test(String(value || ""));
}

function looksLikeOneSignalAppId(value) {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(String(value || ""));
}

function looksLikePackageName(value) {
    var s = String(value || "");
    return /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(s);
}

function hexToSignedByteArray(hex) {
    var clean = String(hex || "").replace(/:/g, "");
    var out = [];
    for (var i = 0; i + 1 < clean.length; i += 2) {
        var value = parseInt(clean.substring(i, i + 2), 16);
        if (value > 127) value -= 256;
        out.push(value);
    }
    return Java.array("byte", out);
}

function normalizeDigestHex(value) {
    return String(value || "").replace(/:/g, "").toUpperCase();
}

function byteArrayToHex(bytes) {
    if (!bytes) return "";
    var out = [];
    for (var i = 0; i < bytes.length; i++) {
        var value = Number(bytes[i]);
        if (value < 0) value += 256;
        var hex = value.toString(16);
        if (hex.length < 2) hex = "0" + hex;
        out.push(hex);
    }
    return out.join("").toUpperCase();
}

function chooseReplacement(kind, originalValue) {
    if (!replacementEnabled()) return null;
    if (kind === "package") {
        var pkg = replacementValue("package");
        return pkg && String(originalValue) !== String(pkg) ? pkg : null;
    }
    if (kind === "cert_sha1") {
        var sha1 = replacementValue("cert_sha1");
        return sha1 && String(originalValue).replace(/:/g, "").toUpperCase() !== String(sha1).replace(/:/g, "").toUpperCase() ? sha1 : null;
    }
    if (kind === "cert_sha256") {
        var sha256 = replacementValue("cert_sha256");
        return sha256 && String(originalValue).replace(/:/g, "").toUpperCase() !== String(sha256).replace(/:/g, "").toUpperCase() ? sha256 : null;
    }
    if (kind === "api_key") {
        var apiKey = replacementValue("api_key");
        return apiKey && String(originalValue) !== String(apiKey) ? apiKey : null;
    }
    if (kind === "admob_app_id") {
        var appId = replacementValue("admob_app_id");
        return appId && String(originalValue) !== String(appId) ? appId : null;
    }
    if (kind === "admob_ad_unit_id") {
        var adUnitId = replacementValue("admob_ad_unit_id");
        return adUnitId && String(originalValue) !== String(adUnitId) ? adUnitId : null;
    }
    if (kind === "facebook_app_id") {
        var facebookAppId = replacementValue("facebook_app_id");
        return facebookAppId && String(originalValue) !== String(facebookAppId) ? facebookAppId : null;
    }
    if (kind === "facebook_client_token") {
        var facebookClientToken = replacementValue("facebook_client_token");
        return facebookClientToken && String(originalValue) !== String(facebookClientToken) ? facebookClientToken : null;
    }
    if (kind === "facebook_app_access_token") {
        var facebookAccessToken = replacementValue("facebook_app_access_token");
        return facebookAccessToken && String(originalValue) !== String(facebookAccessToken) ? facebookAccessToken : null;
    }
    if (kind === "facebook_login_protocol_scheme") {
        var facebookScheme = replacementValue("facebook_login_protocol_scheme");
        return facebookScheme && String(originalValue) !== String(facebookScheme) ? facebookScheme : null;
    }
    if (kind === "facebook_content_provider_authority") {
        var facebookAuthority = replacementValue("facebook_content_provider_authority");
        return facebookAuthority && String(originalValue) !== String(facebookAuthority) ? facebookAuthority : null;
    }
    if (kind === "onesignal_app_id") {
        var oneSignalAppId = replacementValue("onesignal_app_id");
        return oneSignalAppId && String(originalValue) !== String(oneSignalAppId) ? oneSignalAppId : null;
    }
    return null;
}

function replacementKindForKeyValue(key, value) {
    var k = String(key || "").toLowerCase();
    var v = String(value || "");
    if (isOneSignalReplacementMode()) {
        if (isOneSignalAppIdKey(k)) return "onesignal_app_id";
    }
    if (isFacebookReplacementMode()) {
        if (k === "com.facebook.sdk.applicationid" || k === "applicationid" || k === "app_id" || k === "app_id_string" || k === "application_id") return "facebook_app_id";
        if (k === "com.facebook.sdk.clienttoken" || k === "client_token" || k === "clienttoken") return "facebook_client_token";
        if (k === "access_token" || looksLikeFacebookAppAccessToken(v)) return "facebook_app_access_token";
        if (k === "fb_login_protocol_scheme" || looksLikeFacebookLoginProtocolScheme(v)) return "facebook_login_protocol_scheme";
        if (k === "fb_authority" || k.indexOf("facebookcontentprovider") >= 0 || looksLikeFacebookContentProviderAuthority(v)) return "facebook_content_provider_authority";
    }
    if (isAdMobReplacementMode()) {
        if (k === "com.google.android.gms.ads.application_id" || k.indexOf("application_id") >= 0) return "admob_app_id";
        if (k.indexOf("ad_unit") >= 0 || k.indexOf("adunit") >= 0 || k.indexOf("ad unit") >= 0) return "admob_ad_unit_id";
        if (looksLikeAdMobAppId(v)) return "admob_app_id";
        if (looksLikeAdMobAdUnitId(v)) return "admob_ad_unit_id";
    }
    if (isExplicitPackageCredentialKey(k) || isRuntimePackageValue(v) || (k.indexOf("package") >= 0 && looksLikePackageName(v))) return "package";
    if (k.indexOf("sha256") >= 0) return "cert_sha256";
    if (k === "x-android-cert" || k.indexOf("cert") >= 0 || k.indexOf("sha1") >= 0) return "cert_sha1";
    if (k === "x-goog-api-key" || k.indexOf("api_key") >= 0 || k.indexOf("apikey") >= 0 || k.indexOf("api-key") >= 0 || k.indexOf("api key") >= 0 || looksLikeApiKey(v)) return "api_key";
    return null;
}

function isOneSignalAppIdKey(key) {
    var k = String(key || "").toLowerCase();
    if (k === "onesignal_app_id" ||
        k === "os_app_id_shared_pref" ||
        k === "app_id" ||
        k === "appid" ||
        k === "app id" ||
        k === "application_id") {
        return true;
    }
    if ((k.indexOf("onesignal") >= 0 || k.indexOf("os_") >= 0) &&
        (k.indexOf("app_id") >= 0 || k.indexOf("appid") >= 0 || k.indexOf("app id") >= 0)) {
        return true;
    }
    return false;
}

function isMapsLocationAuthOrTokenStack() {
    try {
        return stackContainsAny([
            "com.google.android.gms.maps.",
            "com.google.android.gms.internal.maps.",
            "com.google.maps.api.android.",
            "com.google.android.gms.location.",
            "com.google.android.gms.internal.location.",
            "ApiToken",
            "apiToken",
            "API token",
            "GetApiToken",
            "getApiToken",
            "Authentication",
            "authorization",
            "Authorization"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isMapsLocationAuthOrTokenStack", error: String(err) });
    }
    return false;
}

function isMapsDynamiteParcelStack() {
    try {
        return stackContainsAny([
            "com.google.android.gms.policy_maps_core_dynamite",
            "com.google.android.gms.dynamite.DynamiteModule",
            "com.google.android.gms.dynamite_dynamiteloader",
            "com.google.android.gms.maps.internal.",
            "com.google.maps.api.android.lib6.",
            "CreatorImpl",
            "policy_maps_core_dynamite"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isMapsDynamiteParcelStack", error: String(err) });
    }
    return false;
}

function isLocalBinderOrDynamiteLoaderStack() {
    try {
        return stackContainsAny([
            "DynamiteModule",
            "DynamiteLoader",
            "DynamiteLoaderImpl",
            "queryForDynamiteModule",
            "ContentProviderProxy",
            "ContentResolver.query",
            "IActivityManager$Stub$Proxy.getContentProvider",
            "IPackageManager$Stub$Proxy",
            "notifyDexLoad",
            "bindIsolatedService",
            "ActivityThread.acquireProvider"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isLocalBinderOrDynamiteLoaderStack", error: String(err) });
    }
    return false;
}

function isGoogleCertificatesQueryParcelStack() {
    if (!isBroadPackageReplacementMode()) return false;
    try {
        return stackContainsAny([
            "GoogleCertificatesQuery",
            "com.google.android.gms.common.zzq.writeToParcel",
            "com.google.android.gms.common.zzj.writeToParcel",
            "com.google.android.gms.common.internal.IGoogleCertificatesApi",
            "com.google.android.gms.common.internal.zzr",
            "com.google.android.gms.common.internal.zzq",
            "com.google.android.gms.common.GoogleCertificatesImpl",
            "com.google.android.gms.dynamite_googlecertificates",
            "m140.clw.writeToParcel",
            "m140.azd.c"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isGoogleCertificatesQueryParcelStack", error: String(err) });
    }
    return false;
}

function isGoogleCertificatesAuthStack() {
    if (!isBroadPackageReplacementMode()) return false;
    try {
        return stackContainsAny([
            "GoogleCertificates",
            "GoogleCertificatesRslt",
            "GoogleCertificatesQuery",
            "PhFlagUpdateRegistry",
            "IGoogleCertificatesApi",
            "com.google.android.gms.common.zzq",
            "com.google.android.gms.common.zzj",
            "com.google.android.gms.common.internal.zzr",
            "com.google.android.gms.common.internal.zzq",
            "com.google.android.gms.common.GoogleCertificatesImpl",
            "com.google.android.gms.dynamite_googlecertificates",
            "policy_maps_core_dynamite"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isGoogleCertificatesAuthStack", error: String(err) });
    }
    return false;
}

function isMapsLocationPackageBundleKey(key, value) {
    var k = String(key || "").toLowerCase();
    var v = String(value || "");
    if (k.indexOf("games.") >= 0 ||
        k.indexOf(".games.") >= 0 ||
        k.indexOf("gamepackagename") >= 0 ||
        k.indexOf("game_package") >= 0 ||
        k.indexOf("game package") >= 0) {
        return false;
    }
    if (isExplicitPackageCredentialKey(k)) return true;
    if (isRuntimePackageValue(v)) return true;
    if ((k.indexOf("maps") >= 0 || k.indexOf("map") >= 0 || k.indexOf("geo") >= 0 || k.indexOf("location") >= 0) &&
        k.indexOf("package") >= 0) {
        return true;
    }
    if ((k === "package_name" || k.indexOf("clientpackage") >= 0 || k.indexOf("client_package") >= 0 ||
         k.indexOf("callingpackage") >= 0 || k.indexOf("calling_package") >= 0 || k.indexOf("realclientpackage") >= 0 ||
         k.indexOf("real_client_package") >= 0) && isMapsLocationAuthOrTokenStack()) {
        return true;
    }
    return false;
}

function noteMapsGmsTokenBundleAccess(key, value, source) {
    if (!isBroadPackageReplacementMode() || !isInstrumentedGmsProcess()) return;
    var k = String(key || "").toLowerCase();
    var v = String(value || "");
    var demoPkg = String(replacementValue("package") || "");
    var apiKey = String(replacementValue("api_key") || "");
    var looksLikeTokenField =
        k === "api_key" ||
        k === "package_name" ||
        k === "package" ||
        k.indexOf("api_key") >= 0 ||
        k.indexOf("apikey") >= 0 ||
        k.indexOf("package_name") >= 0 ||
        (apiKey && v === apiKey) ||
        (demoPkg && v === demoPkg);
    if (!looksLikeTokenField) return;
    MAPS_GMS_TOKEN_AUTH_WINDOW_UNTIL = Date.now() + 3000;
    logEvent("maps_gms_token_auth_window", {
        source: source,
        key: String(key || ""),
        value: maskValue(value)
    });
}

function shouldSkipRuntimeReplacement(replacementKind, key, value, source) {
    if (replacementKind !== "package") return null;
    if (isAdMobReplacementMode()) return "admob_keep_runtime_package_identity";
    if (!isBroadPackageReplacementMode()) return null;
    var src = String(source || "");
    var k = String(key || "").toLowerCase();

    if (isGmsAuxiliaryReplacementProcess() &&
        (src.indexOf("Bundle.") === 0 || src.indexOf("BaseBundle.") === 0) &&
        !isMapsLocationPackageBundleKey(k, value)) {
        return "gms_aux_non_maps_location_package_field";
    }

    // GMS Maps/Location sends local Binder identity fields through Bundle before
    // it reaches any remote API request. Rewriting these fields causes the GMS
    // service to reject the call because demo package does not belong to the
    // attacker's UID. Keep local identity intact; only remote auth headers/keys
    // should be rewritten.
    if (!RUNTIME_REPLACEMENTS.replaceLocalBundlePackageName &&
        src.indexOf("Bundle.") === 0 && (k === "package_name" || k === "package" || k.indexOf("package") >= 0)) {
        return "gms_local_bundle_package_identity";
    }
    if (isGmsLocalIdentityStack()) {
        return "gms_local_identity_stack";
    }
    return null;
}

function maybeReplaceKeyValue(kind, key, value, source) {
    var replacementKind = kind || replacementKindForKeyValue(key, value);
    if (!replacementKind) return value;
    var skipReason = shouldSkipRuntimeReplacement(replacementKind, key, value, source);
    if (skipReason) {
        if (PACKAGE_REPLACEMENT_SKIP_LOG_COUNT < PACKAGE_REPLACEMENT_SKIP_LOG_LIMIT) {
            PACKAGE_REPLACEMENT_SKIP_LOG_COUNT += 1;
            logEvent("runtime_value_replacement_skipped", {
                source: source,
                replacementKind: replacementKind,
                key: String(key || ""),
                value: maskValue(value),
                reason: skipReason
            });
        }
        return value;
    }
    var replacement = chooseReplacement(replacementKind, value);
    if (replacement === null || replacement === undefined) return value;
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: replacementKind,
        key: String(key || ""),
        from: maskValue(value),
        to: maskValue(replacement)
    });
    return replacement;
}

function stackContainsAny(needles) {
    var Thread = Java.use("java.lang.Thread");
    var stack = Thread.currentThread().getStackTrace();
    for (var i = 0; i < stack.length; i++) {
        var frame = String(stack[i]);
        for (var j = 0; j < needles.length; j++) {
            if (frame.indexOf(needles[j]) >= 0) return true;
        }
    }
    return false;
}

function currentStackSummary(limit) {
    try {
        var Thread = Java.use("java.lang.Thread");
        var stack = Thread.currentThread().getStackTrace();
        var out = [];
        var max = Math.min(stack.length, limit || 16);
        for (var i = 0; i < max; i++) {
            out.push(String(stack[i]));
        }
        return out.join(" | ");
    } catch (err) {
        return "<stack unavailable: " + String(err) + ">";
    }
}

function isPlacesAuthStack() {
    try {
        return stackContainsAny([
            "com.google.android.libraries.places.internal.zzjc",
            "com.google.android.libraries.places.internal.zznh",
            "com.google.android.libraries.places.internal.zzmr",
            "com.google.android.libraries.places.internal.zzmz"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isPlacesAuthStack", error: String(err) });
    }
    return false;
}

function isGoogleSdkAuthStack() {
    try {
        return stackContainsAny([
            "com.google.android.gms.ads.",
            "com.google.android.gms.internal.ads.",
            "com.google.ads.",
            "MobileAds",
            "com.google.android.libraries.places.internal.",
            "com.google.android.gms.maps.",
            "com.google.android.gms.location.",
            "com.google.android.gms.internal.location.",
            "com.google.android.gms.common.api.GoogleApi",
            "com.google.android.gms.common.api.GoogleApiClient",
            "com.google.android.gms.common.api.internal.GoogleApiManager",
            "com.google.android.gms.common.internal.ClientSettings",
            "com.google.android.gms.common.internal.BaseGmsClient",
            "com.google.android.gms.common.internal.GmsClientSupervisor",
            "com.google.android.gms.common.internal.zzt",
            "com.google.android.gms.common.wrappers.PackageManagerWrapper"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isGoogleSdkAuthStack", error: String(err) });
    }
    return false;
}

function isGmsLocalIdentityStack() {
    try {
        return stackContainsAny([
            "com.google.android.gms.common.internal.BaseGmsClient",
            "com.google.android.gms.common.internal.GetServiceRequest",
            "com.google.android.gms.common.internal.GmsClientSupervisor",
            "com.google.android.gms.common.internal.IGmsServiceBroker",
            "com.google.android.gms.common.internal.zzt",
            "com.google.android.gms.common.api.GoogleApi",
            "com.google.android.gms.common.api.GoogleApiClient",
            "com.google.android.gms.common.api.internal.GoogleApiManager",
            "com.google.android.gms.signin.internal.SignInClientImpl"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isGmsLocalIdentityStack", error: String(err) });
    }
    return false;
}

function maybeReplacePackageForGoogleSdkAuth(value, source) {
    if (isAdMobReplacementMode()) {
        return value;
    }
    if (isBroadPackageReplacementMode()) {
        if (isGmsLocalIdentityStack()) {
            logEvent("package_replacement_skipped", {
                source: source,
                reason: "gms_local_identity_stack",
                value: String(value || "")
            });
            return value;
        }
        if (isRuntimePackageValue(value) && isGoogleCertificatesAuthStack()) {
            return maybeReplaceKeyValue("package", "GoogleCertificates.Context.getPackageName", value, source);
        }
        return value;
    }
    var shouldReplace = packageReplacementMode() === "places_auth_stack"
        ? isPlacesAuthStack()
        : isGoogleSdkAuthStack();
    if (!shouldReplace) {
        try {
            var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
            if (runtimePkg && String(value) === String(runtimePkg) && PACKAGE_STACK_MISS_LOG_COUNT < PACKAGE_STACK_MISS_LOG_LIMIT) {
                PACKAGE_STACK_MISS_LOG_COUNT += 1;
                logEvent("package_auth_stack_miss", {
                    source: source,
                    value: String(value),
                    stack: currentStackSummary(18)
                });
            }
        } catch (err) {
            logEvent("replacement_error", { source: "package_auth_stack_miss", error: String(err) });
        }
        return value;
    }
    return maybeReplaceKeyValue("package", "getPackageName", value, source);
}

function shouldReplaceParcelPackageString(value) {
    if (!isBroadPackageReplacementMode()) return false;
    var allowedProcess = isGmsAuxiliaryReplacementProcess() ||
        ((shouldReplaceMapsDynamiteParcelPackageName() || shouldReplaceGoogleCertificatesQueryPackageName()) && isRuntimeReplacementProcess());
    if (!allowedProcess) return false;
    if (!isRuntimePackageValue(value)) return false;
    if (shouldReplaceGoogleCertificatesQueryPackageName() && isGoogleCertificatesQueryParcelStack()) return true;
    if (!shouldReplaceMapsDynamiteParcelPackageName()) return false;
    if (isGmsLocalIdentityStack()) return false;
    if (isLocalBinderOrDynamiteLoaderStack()) return false;
    return isMapsLocationAuthOrTokenStack() || isMapsDynamiteParcelStack();
}

function maybeReplaceParcelPackageString(value, source) {
    var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
    var demoPkg = replacementValue("package");
    if (!runtimePkg || !demoPkg || String(value || "") !== String(runtimePkg)) return value;
    if (PARCEL_PACKAGE_LOG_COUNT < PARCEL_PACKAGE_LOG_LIMIT) {
        PARCEL_PACKAGE_LOG_COUNT += 1;
        logEvent("parcel_package_string", {
            source: source,
            value: String(value || ""),
            replaceAllowed: shouldReplaceParcelPackageString(value) ? "true" : "false",
            stack: currentStackSummary(18)
        });
    }
    if (!shouldReplaceParcelPackageString(value)) return value;
    return maybeReplaceKeyValue("package", "Parcel.packageName", value, source);
}

function maybeReplaceParcelReadPackageString(value, source) {
    var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
    var demoPkg = replacementValue("package");
    if (!runtimePkg || !demoPkg || String(value || "") !== String(runtimePkg)) return value;
    if (!shouldReplaceGoogleCertificatesQueryPackageName() || !isGoogleCertificatesQueryParcelStack()) return value;
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: "package",
        key: "GoogleCertificates.Parcel.readPackageName",
        from: String(runtimePkg),
        to: String(demoPkg)
    });
    return String(demoPkg);
}

function shouldPatchRuntimePackageObject(requestedPackageName, actualPackageName) {
    if (isAdMobReplacementMode()) {
        return false;
    }
    if (isBroadPackageReplacementMode()) {
        return false;
    }
    if (packageReplacementMode() === "places_auth_stack") {
        return isPlacesAuthStack();
    }
    return isGoogleSdkAuthStack();
}

function rewritePackageManagerLookupArgs(args, source) {
    if (!isBroadPackageReplacementMode() || !args || args.length === 0) return args;
    var demoPkg = replacementValue("package");
    var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
    if (!demoPkg || !runtimePkg) return args;
    if (isGoogleCertificatesQueryParcelStack()) {
        if (String(args[0] || "") === String(runtimePkg)) {
            args[0] = String(demoPkg);
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "package",
                key: "GoogleCertificates.PackageManager.lookupPackageName",
                from: String(runtimePkg),
                to: String(demoPkg)
            });
        }
        return args;
    }
    if (isGmsLocalIdentityStack()) return args;
    if (String(args[0] || "") !== String(demoPkg)) return args;
    args[0] = String(runtimePkg);
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: "package",
        key: "PackageManager.lookupPackageName",
        from: String(demoPkg),
        to: String(runtimePkg)
    });
    return args;
}

function makePlacesMetadataKey(name) {
    var Zzbmg = Java.use("com.google.android.libraries.places.internal.zzbmg");
    var Zzbmc = Java.use("com.google.android.libraries.places.internal.zzbmc");
    var Zzbmb = Java.use("com.google.android.libraries.places.internal.zzbmb");
    var JavaString = Java.use("java.lang.String");
    var field = Zzbmg.class.getDeclaredField("zza");
    field.setAccessible(true);
    var marshaller = field.get(null);
    var method = Zzbmc.class.getDeclaredMethod(
        "zzc",
        Java.array("java.lang.Class", [JavaString.class, Zzbmb.class])
    );
    method.setAccessible(true);
    return method.invoke(
        null,
        Java.array("java.lang.Object", [JavaString.$new(String(name)), marshaller])
    );
}

function upsertPlacesMetadataValue(metadata, keyName, value, source) {
    if (!metadata || value === null || value === undefined || String(value) === "") return false;
    var key = makePlacesMetadataKey(keyName);
    metadata.zzd
        .overload("com.google.android.libraries.places.internal.zzbmc")
        .call(metadata, key);
    metadata.zzc
        .overload("com.google.android.libraries.places.internal.zzbmc", "java.lang.Object")
        .call(metadata, key, String(value));
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: replacementKindForKeyValue(keyName, value) || "metadata",
        key: String(keyName),
        from: "<metadata>",
        to: maskValue(value)
    });
    return true;
}

function patchPlacesAuthMetadata(metadata, source) {
    if (!replacementEnabled() || !metadata) return metadata;
    try {
        var changed = false;
        changed = upsertPlacesMetadataValue(metadata, "X-Android-Package", replacementValue("package"), source) || changed;
        changed = upsertPlacesMetadataValue(metadata, "X-Android-Cert", replacementValue("cert_sha1"), source) || changed;
        changed = upsertPlacesMetadataValue(metadata, "X-Places-Android-Sdk", "5.1.1", source) || changed;
        if (changed) {
            logEvent("places_metadata_patched", {
                source: source,
                metadata: maskValue(metadata)
            });
        }
    } catch (err) {
        logEvent("replacement_error", { source: source, error: String(err) });
    }
    return metadata;
}

function patchURLConnectionAuthHeaders(connection, source) {
    if (!replacementEnabled() || !connection) return connection;
    if (urlConnectionHeaderPatchDisabled()) return connection;
    if (isAdMobReplacementMode()) return connection;
    try {
        var pkg = replacementValue("package");
        var cert = replacementValue("cert_sha1");
        if (pkg) {
            connection.setRequestProperty("X-Android-Package", String(pkg));
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "package",
                key: "X-Android-Package",
                from: "<urlconnection-header>",
                to: maskValue(pkg)
            });
        }
        if (cert) {
            connection.setRequestProperty("X-Android-Cert", String(cert).replace(/:/g, "").toUpperCase());
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "cert_sha1",
                key: "X-Android-Cert",
                from: "<urlconnection-header>",
                to: maskValue(cert)
            });
        }
    } catch (err) {
        logEvent("replacement_error", { source: source, error: String(err) });
    }
    return connection;
}

function injectCronetAuthHeaders(builder, source) {
    if (!replacementEnabled() || !builder) return builder;
    if (isAdMobReplacementMode()) return builder;
    try {
        var pkg = replacementValue("package");
        var cert = replacementValue("cert_sha1");
        var apiKey = replacementValue("api_key");
        if (pkg && builder.addHeader) {
            builder.addHeader("X-Android-Package", String(pkg));
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "package",
                key: "X-Android-Package",
                from: "<cronet-header>",
                to: maskValue(pkg)
            });
        }
        if (cert && builder.addHeader) {
            builder.addHeader("X-Android-Cert", String(cert).replace(/:/g, "").toUpperCase());
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "cert_sha1",
                key: "X-Android-Cert",
                from: "<cronet-header>",
                to: maskValue(cert)
            });
        }
        if (apiKey && builder.addHeader) {
            builder.addHeader("X-Goog-Api-Key", String(apiKey));
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "api_key",
                key: "X-Goog-Api-Key",
                from: "<cronet-header>",
                to: maskValue(apiKey)
            });
        }
    } catch (err) {
        logEvent("replacement_error", { source: source, error: String(err) });
    }
    return builder;
}

function maybeReplaceAdMobAppId(value, source) {
    if (!isAdMobReplacementMode()) return value;
    var appId = replacementValue("admob_app_id");
    if (!appId) return value;
    if (String(value || "") === String(appId)) return value;
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: "admob_app_id",
        key: "com.google.android.gms.ads.APPLICATION_ID",
        from: maskValue(value),
        to: maskValue(appId)
    });
    return String(appId);
}

function maybeReplaceAdMobAdUnitId(value, source) {
    if (!isAdMobReplacementMode()) return value;
    var adUnitId = replacementValue("admob_ad_unit_id");
    if (!adUnitId) return value;
    if (String(value || "") === String(adUnitId)) return value;
    if (String(value || "") && source.indexOf("setAdUnitId") < 0) return value;
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: "admob_ad_unit_id",
        key: "adUnitId",
        from: maskValue(value),
        to: maskValue(adUnitId)
    });
    return String(adUnitId);
}

function maybeReplaceFacebookValue(kind, key, value, source) {
    if (!isFacebookReplacementMode()) return value;
    var replacement = replacementValue(kind);
    if (!replacement || String(value || "") === String(replacement)) return value;
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: kind,
        key: String(key || ""),
        from: maskValue(value),
        to: maskValue(replacement)
    });
    return String(replacement);
}

function maybeReplaceFacebookKeyValue(key, value, source) {
    if (!isFacebookReplacementMode()) return value;
    var kind = replacementKindForKeyValue(key, value);
    if (!kind || String(kind).indexOf("facebook_") !== 0) return value;
    return maybeReplaceFacebookValue(kind, key, value, source);
}

function maybeReplaceOneSignalAppId(value, source) {
    if (!isOneSignalReplacementMode()) return value;
    var appId = replacementValue("onesignal_app_id");
    if (!appId) return value;
    if (String(value || "") === String(appId)) return value;
    if (value !== null && value !== undefined && String(value || "") !== "" && !looksLikeOneSignalAppId(value)) return value;
    logEvent("runtime_value_replaced", {
        source: source,
        replacementKind: "onesignal_app_id",
        key: "onesignal_app_id",
        from: maskValue(value),
        to: maskValue(appId)
    });
    return String(appId);
}

function describeIntentForShareKit(intent) {
    if (!intent) return "";
    try {
        var parts = [];
        parts.push(String(intent));
        try {
            var action = intent.getAction ? intent.getAction() : null;
            if (action) parts.push("action=" + String(action));
        } catch (actionErr) {}
        try {
            var data = intent.getData ? intent.getData() : null;
            if (data) parts.push("data=" + String(data));
        } catch (dataErr) {}
        try {
            var component = intent.getComponent ? intent.getComponent() : null;
            if (component) parts.push("component=" + String(component));
        } catch (componentErr) {}
        try {
            var pkg = intent.getPackage ? intent.getPackage() : null;
            if (pkg) parts.push("package=" + String(pkg));
        } catch (pkgErr) {}
        return parts.join(" ");
    } catch (err) {
        return String(intent);
    }
}

function looksLikeFacebookShareIntent(intentText) {
    var text = String(intentText || "").toLowerCase();
    return text.indexOf("facebook") >= 0 ||
           text.indexOf("fbconnect") >= 0 ||
           text.indexOf("fb-messenger") >= 0 ||
           text.indexOf("platformactivity") >= 0 ||
           (text.indexOf("share") >= 0 && text.indexOf("dialog") >= 0);
}

function emitFacebookShareSuccess(source, detail) {
    if (!isFacebookShareKitReplacementMode()) return;
    logEvent("facebook_share_handoff", {
        source: source,
        detail: String(detail || "")
    });
    logEvent("app_test_signal", {
        level: "I",
        tag: "APICREDTEST",
        message: "FACEBOOK_SHARE_UI_HANDOFF: source=" + source + " detail=" + String(detail || ""),
        status: "success"
    });
}

function installFacebookRuntimeHooks() {
    if (!isFacebookReplacementMode()) return;
    [
        "android.os.Bundle",
        "android.os.BaseBundle"
    ].forEach(function (className) {
        safeHook(className, "getString", function (overload) {
            return function () {
                var key = arguments.length > 0 ? String(arguments[0]) : "";
                var result = overload.apply(this, arguments);
                return maybeReplaceFacebookKeyValue(key, result, "Facebook." + className + ".getString");
            };
        });
        safeHook(className, "putString", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                var key = args.length > 0 ? String(args[0]) : "";
                if (args.length > 1) {
                    args[1] = maybeReplaceFacebookKeyValue(key, args[1], "Facebook." + className + ".putString");
                }
                return overload.apply(this, args);
            };
        });
    });
    safeHook("com.facebook.FacebookSdk", "getApplicationId", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            return maybeReplaceFacebookValue("facebook_app_id", "com.facebook.sdk.ApplicationId", result, "FacebookSdk.getApplicationId");
        };
    });
    safeHook("com.facebook.FacebookSdk", "setApplicationId", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            if (args.length > 0) {
                args[0] = maybeReplaceFacebookValue("facebook_app_id", "com.facebook.sdk.ApplicationId", args[0], "FacebookSdk.setApplicationId");
            }
            return overload.apply(this, args);
        };
    });
    safeHook("com.facebook.FacebookSdk", "getClientToken", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            return maybeReplaceFacebookValue("facebook_client_token", "com.facebook.sdk.ClientToken", result, "FacebookSdk.getClientToken");
        };
    });
    safeHook("com.facebook.FacebookSdk", "setClientToken", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            if (args.length > 0) {
                args[0] = maybeReplaceFacebookValue("facebook_client_token", "com.facebook.sdk.ClientToken", args[0], "FacebookSdk.setClientToken");
            }
            return overload.apply(this, args);
        };
    });
    safeHook("com.facebook.FacebookSdk", "publishInstallAndWaitForResponse", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            if (args.length > 1) {
                args[1] = maybeReplaceFacebookValue("facebook_app_id", "applicationId", args[1], "FacebookSdk.publishInstallAndWaitForResponse");
            }
            return overload.apply(this, args);
        };
    });
    safeHook("com.facebook.share.widget.ShareDialog", "show", function (overload) {
        return function () {
            var content = arguments.length > 0 ? String(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            emitFacebookShareSuccess("ShareDialog.show", content);
            return result;
        };
    });
    safeHook("com.facebook.internal.FacebookDialogBase", "show", function (overload) {
        return function () {
            var content = arguments.length > 0 ? String(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            emitFacebookShareSuccess("FacebookDialogBase.show", content);
            return result;
        };
    });
    safeHook("com.facebook.internal.DialogPresenter", "present", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            emitFacebookShareSuccess("DialogPresenter.present", arguments.length > 0 ? String(arguments[0]) : "");
            return result;
        };
    });
    safeHook("com.facebook.internal.DialogPresenter", "startActivityForResultWithAndroidX", function (overload) {
        return function () {
            var detail = "";
            for (var i = 0; i < arguments.length; i++) {
                var text = describeIntentForShareKit(arguments[i]);
                if (looksLikeFacebookShareIntent(text)) detail = text;
            }
            var result = overload.apply(this, arguments);
            emitFacebookShareSuccess("DialogPresenter.startActivityForResultWithAndroidX", detail);
            return result;
        };
    });
    safeHook("android.app.Activity", "startActivityForResult", function (overload) {
        return function () {
            var detail = arguments.length > 0 ? describeIntentForShareKit(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            if (looksLikeFacebookShareIntent(detail)) {
                emitFacebookShareSuccess("Activity.startActivityForResult", detail);
            }
            return result;
        };
    });
    safeHook("android.net.Uri$Builder", "appendQueryParameter", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            if (args.length > 1) {
                args[1] = maybeReplaceFacebookKeyValue(key, args[1], "Facebook.Uri.Builder.appendQueryParameter");
            }
            return overload.apply(this, args);
        };
    });
    safeHook("org.json.JSONObject", "put", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            if (args.length > 1) {
                if (key === "application_package_name") {
                    args[1] = maybeReplaceFacebookValue("package", key, args[1], "Facebook.JSONObject.put");
                } else if (key === "extinfo") {
                    var runtimePkg = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.runtimePackageName) || "");
                    var demoPkg = String(replacementValue("package") || "");
                    var text = String(args[1] || "");
                    if (runtimePkg && demoPkg && text.indexOf(runtimePkg) >= 0) {
                        var replaced = text.split(runtimePkg).join(demoPkg);
                        logEvent("runtime_value_replaced", {
                            source: "Facebook.JSONObject.put",
                            replacementKind: "package",
                            key: key,
                            from: maskValue(text),
                            to: maskValue(replaced)
                        });
                        args[1] = replaced;
                    }
                } else {
                    args[1] = maybeReplaceFacebookKeyValue(key, args[1], "Facebook.JSONObject.put");
                }
            }
            return overload.apply(this, args);
        };
    });
    safeHook("com.facebook.GraphRequest", "executeAndWait", function (overload) {
        return function () {
            var graphPath = "";
            try {
                if (this.getGraphPath) {
                    graphPath = String(this.getGraphPath());
                }
                if (this.graphPath) {
                    var fieldPath = String(this.graphPath.value || this.graphPath);
                    if (fieldPath && fieldPath !== "[object Object]") graphPath = fieldPath;
                }
            } catch (pathErr) {
                graphPath = "";
            }
            var result = overload.apply(this, arguments);
            try {
                var error = result && result.getError ? result.getError() : null;
                var isTargetGraphPath = graphPath.indexOf("activities") >= 0 ||
                    graphPath.indexOf("/activities") >= 0 ||
                    graphPath.indexOf("instruments") >= 0;
                logEvent("facebook_graph_response", {
                    graphPath: graphPath,
                    hasError: error ? "true" : "false",
                    response: String(result)
                });
                if (!isTargetGraphPath) {
                    return result;
                }
                if (error) {
                    logEvent("app_test_signal", {
                        level: "E",
                        tag: "APICREDTEST",
                        message: "FACEBOOK_GRAPH_RESPONSE_FAILURE: path=" + graphPath + " error=" + String(error),
                        status: "failure"
                    });
                } else {
                    logEvent("app_test_signal", {
                        level: "I",
                        tag: "APICREDTEST",
                        message: "FACEBOOK_GRAPH_RESPONSE_SUCCESS: path=" + graphPath + " response=" + String(result),
                        status: "success"
                    });
                }
            } catch (err) {
                logEvent("replacement_error", { source: "Facebook.GraphRequest.executeAndWait", error: String(err) });
            }
            return result;
        };
    });
    safeHook("java.security.MessageDigest", "getInstance", function (overload) {
        return function () {
            var alg = arguments.length > 0 ? String(arguments[0]) : "";
            logEvent("message_digest_algorithm", { algorithm: alg });
            return overload.apply(this, arguments);
        };
    });
    safeHook("java.security.MessageDigest", "digest", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var returnType = overload.returnType ? String(overload.returnType.name) : "";
            var algorithm = "";
            var replacementAllowed = false;
            try {
                algorithm = String(this.getAlgorithm());
                replacementAllowed = replacementEnabled() && returnType === "[B" && shouldReplaceDigestCall(arguments);
                logEvent("message_digest_digest", { algorithm: algorithm, byteLength: result ? result.length : 0, replacementAllowed: String(replacementAllowed) });
            } catch (diagErr) {
                logEvent("message_digest_digest", { byteLength: result ? result.length : 0 });
            }
            if (replacementAllowed && /^SHA-?1$/i.test(algorithm) && replacementValue("cert_sha1")) {
                logEvent("runtime_value_replaced", {
                    source: "Facebook.MessageDigest.digest",
                    replacementKind: "cert_sha1",
                    key: algorithm,
                    from: byteArrayToHex(result),
                    to: maskValue(replacementValue("cert_sha1"))
                });
                return hexToSignedByteArray(replacementValue("cert_sha1"));
            }
            return result;
        };
    });
}

function installAdMobRuntimeHooks() {
    if (!isAdMobReplacementMode()) return;
    safeHook("android.os.BaseBundle", "getString", function (overload) {
        return function () {
            var key = arguments.length > 0 ? String(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            if (key === "com.google.android.gms.ads.APPLICATION_ID") {
                return maybeReplaceAdMobAppId(result, "AdMob.BaseBundle.getString");
            }
            return result;
        };
    });
    safeHook("android.os.BaseBundle", "putString", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            if (args.length > 1 && key === "com.google.android.gms.ads.APPLICATION_ID") {
                args[1] = maybeReplaceAdMobAppId(args[1], "AdMob.BaseBundle.putString");
            }
            return overload.apply(this, args);
        };
    });
    safeHook("com.google.android.gms.ads.internal.util.zzm", "zzaz", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var returnType = overload.returnType ? String(overload.returnType.name) : "";
            if (returnType === "java.lang.String") {
                return maybeReplaceAdMobAppId(result, "AdMob.zzm.zzaz");
            }
            return result;
        };
    });
    safeHook("com.google.android.gms.ads.internal.util.zzm", "zzd", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var returnType = overload.returnType ? String(overload.returnType.name) : "";
            if (returnType === "java.lang.String") {
                return maybeReplaceAdMobAppId(result, "AdMob.zzm.zzd");
            }
            return result;
        };
    });
    [
        "com.google.android.gms.ads.BaseAdView",
        "com.google.android.gms.ads.AdView",
        "com.google.android.gms.ads.InterstitialAd",
        "com.google.android.gms.ads.doubleclick.PublisherAdView",
        "com.google.android.gms.ads.doubleclick.PublisherInterstitialAd",
        "com.google.android.gms.ads.internal.util.zzag",
        "com.google.android.gms.internal.ads.zzze",
        "com.google.android.gms.internal.ads.zzzg"
    ].forEach(function (className) {
        safeHook(className, "setAdUnitId", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.length > 0) {
                    args[0] = maybeReplaceAdMobAdUnitId(args[0], className + ".setAdUnitId");
                }
                return overload.apply(this, args);
            };
        });
    });
    safeHook("com.google.android.gms.ads.MobileAds", "initialize", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var secondType = overload.argumentTypes && overload.argumentTypes.length > 1
                ? String(overload.argumentTypes[1].name || "")
                : "";
            if (args.length > 1 && secondType === "java.lang.String") {
                args[1] = maybeReplaceAdMobAppId(args[1], "MobileAds.initialize");
            }
            return overload.apply(this, args);
        };
    });
}

function installOneSignalRuntimeHooks() {
    if (!isOneSignalReplacementMode()) return;

    safeHook("android.app.SharedPreferencesImpl", "getString", function (overload) {
        return function () {
            var key = arguments.length > 0 ? String(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            return maybeReplaceKeyValue(null, key, result, "OneSignal.SharedPreferences.getString");
        };
    });

    safeHook("android.app.SharedPreferencesImpl$EditorImpl", "putString", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, args[1], "OneSignal.SharedPreferences.Editor.putString");
            }
            return overload.apply(this, args);
        };
    });

    [
        "com.onesignal.internal.a",
        "k3.a"
    ].forEach(function (className) {
        safeHook(className, "initWithContext", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.length > 1) {
                    args[1] = maybeReplaceOneSignalAppId(args[1], className + ".initWithContext");
                }
                return overload.apply(this, args);
            };
        });
    });

    [
        "com.onesignal.core.internal.config.a",
        "com.onesignal.core.internal.config.c"
    ].forEach(function (className) {
        safeHook(className, "setAppId", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.length > 0) {
                    args[0] = maybeReplaceOneSignalAppId(args[0], className + ".setAppId");
                }
                return overload.apply(this, args);
            };
        });
    });

    safeHook("org.json.JSONObject", "put", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, args[1], "OneSignal.JSONObject.put");
            }
            return overload.apply(this, args);
        };
    });
}

function patchPackageInfo(packageInfo, source, requestedPackageName) {
    if (!replacementEnabled() || !packageInfo) return packageInfo;
    var pkg = replacementValue("package");
    if (!pkg) return packageInfo;
    var before = packageInfo.packageName ? String(packageInfo.packageName.value) : "";
    if (!shouldPatchRuntimePackageObject(requestedPackageName, before)) return packageInfo;
    var requested = String(requestedPackageName || "");
    if (requested && requested !== before && !isBroadPackageReplacementMode()) {
        return packageInfo;
    }
    try {
        packageInfo.packageName.value = pkg;
        if (packageInfo.applicationInfo) {
            packageInfo.applicationInfo.value.packageName.value = pkg;
        }
        if (before !== pkg) {
            logEvent("runtime_value_replaced", {
                source: source,
                replacementKind: "package",
                key: "PackageInfo.packageName",
                from: before,
                to: pkg
            });
        }
    } catch (err) {
        logEvent("replacement_error", { source: source, error: String(err) });
    }
    return packageInfo;
}

function getApplicationInfoMetadata(applicationInfo) {
    if (!applicationInfo) return null;
    try {
        if (applicationInfo.metaData && applicationInfo.metaData.value) {
            return applicationInfo.metaData.value;
        }
    } catch (err1) {
    }
    try {
        return applicationInfo.metaData || null;
    } catch (err2) {
        return null;
    }
}

function patchApplicationInfoMetadata(applicationInfo, source) {
    if (!replacementEnabled() || !applicationInfo) return applicationInfo;
    var apiKey = replacementValue("api_key");
    var admobAppId = replacementValue("admob_app_id");
    if (!apiKey && !admobAppId) return applicationInfo;
    try {
        var metadata = getApplicationInfoMetadata(applicationInfo);
        if (!metadata) return applicationInfo;
        var BundleClass = Java.use("android.os.Bundle");
        var bundle = Java.cast(metadata, BundleClass);
        if (!isAdMobReplacementMode()) {
            [
                "com.google.android.geo.API_KEY",
                "com.google.android.maps.v2.API_KEY",
                "com.google.android.geo.API_KEY_ANDROID",
                "com.google.android.maps.v2.API_KEY_ANDROID"
            ].forEach(function (keyName) {
                try {
                    var before = bundle.getString.overload("java.lang.String").call(bundle, keyName);
                    if (before !== null && before !== undefined && String(before) !== String(apiKey)) {
                        bundle.putString.overload("java.lang.String", "java.lang.String").call(bundle, keyName, String(apiKey));
                        logEvent("runtime_value_replaced", {
                            source: source,
                            replacementKind: "api_key",
                            key: keyName,
                            from: maskValue(before),
                            to: maskValue(apiKey)
                        });
                    }
                } catch (innerErr) {
                    logEvent("replacement_error", { source: source + "." + keyName, error: String(innerErr) });
                }
            });
        }
        if (isAdMobReplacementMode() && admobAppId) {
            try {
                var appIdKey = "com.google.android.gms.ads.APPLICATION_ID";
                var beforeAppId = bundle.getString.overload("java.lang.String").call(bundle, appIdKey);
                if (String(beforeAppId || "") !== String(admobAppId)) {
                    bundle.putString.overload("java.lang.String", "java.lang.String").call(bundle, appIdKey, String(admobAppId));
                    logEvent("runtime_value_replaced", {
                        source: source,
                        replacementKind: "admob_app_id",
                        key: appIdKey,
                        from: maskValue(beforeAppId),
                        to: maskValue(admobAppId)
                    });
                }
            } catch (admobErr) {
                logEvent("replacement_error", { source: source + ".admob_application_id", error: String(admobErr) });
            }
        }
    } catch (err) {
        logEvent("replacement_error", { source: source, error: String(err) });
    }
    return applicationInfo;
}

function shouldReplaceDigestCall(args) {
    if (isAdMobReplacementMode()) {
        return false;
    }
    if (isFacebookReplacementMode()) {
        return isFacebookSignatureDigestStack();
    }
    if (isBroadPackageReplacementMode() && isInstrumentedGmsProcess()) {
        return isGoogleCertificatesAuthStack();
    }
    if (!args || args.length === 0) {
        return isMapsCertificateDigestStack();
    }
    try {
        return (args[0] && args[0].length >= 64) || isMapsCertificateDigestStack();
    } catch (err) {
        return false;
    }
}

function shouldReplaceMapsGmsTokenDigest(algorithm, result) {
    if (!isBroadPackageReplacementMode() || !isInstrumentedGmsProcess()) return false;
    if (!replacementValue("cert_sha1")) return false;
    if (Date.now() > MAPS_GMS_TOKEN_AUTH_WINDOW_UNTIL) return false;
    if (!/^SHA-?1$/i.test(String(algorithm || ""))) return false;
    try {
        return !!(result && result.length === 20);
    } catch (err) {
        return false;
    }
}

function logDigestDecision(algorithm, result, replacementAllowed) {
    if (!isBroadPackageReplacementMode()) return;
    var googleCertStack = isGoogleCertificatesAuthStack();
    var mapsCertStack = isMapsCertificateDigestStack();
    if (!isInstrumentedGmsProcess() && !googleCertStack && !mapsCertStack) return;
    if (DIGEST_DIAGNOSTIC_LOG_COUNT >= DIGEST_DIAGNOSTIC_LOG_LIMIT) return;
    DIGEST_DIAGNOSTIC_LOG_COUNT += 1;
    var digestHex = byteArrayToHex(result);
    var certSha1 = normalizeDigestHex(replacementValue("cert_sha1"));
    var certSha256 = normalizeDigestHex(replacementValue("cert_sha256"));
    logEvent("message_digest_digest", {
        algorithm: String(algorithm || ""),
        byteLength: result ? result.length : 0,
        digestHex: digestHex,
        matchesDemoSha1: certSha1 && digestHex === certSha1 ? "true" : "false",
        matchesDemoSha256: certSha256 && digestHex === certSha256 ? "true" : "false",
        googleCertificatesStack: googleCertStack ? "true" : "false",
        mapsCertificateStack: mapsCertStack ? "true" : "false",
        replacementAllowed: replacementAllowed ? "true" : "false",
        stack: currentStackSummary(22)
    });
}

function isMapsCertificateDigestStack() {
    if (!isBroadPackageReplacementMode()) return false;
    try {
        return stackContainsAny([
            "GoogleCertificates",
            "GoogleCertificatesRslt",
            "PhFlagUpdateRegistry",
            "com.google.android.gms.common.",
            "com.google.maps.api.android.lib6.",
            "com.google.android.gms.maps.internal.",
            "policy_maps_core_dynamite"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isMapsCertificateDigestStack", error: String(err) });
    }
    return false;
}

function isFacebookSignatureDigestStack() {
    if (!isFacebookReplacementMode()) return false;
    try {
        return stackContainsAny([
            "com.facebook.FacebookSdk.getApplicationSignature",
            "FacebookSdk.getApplicationSignature",
            "com.facebook.appevents.internal.HashUtils",
            "AppEventsLoggerUtility.getJSONObjectForGraphAPICall",
            "FacebookSdk.publishInstallAndWaitForResponse"
        ]);
    } catch (err) {
        logEvent("replacement_error", { source: "isFacebookSignatureDigestStack", error: String(err) });
    }
    return false;
}

function safeHook(className, methodName, callback) {
    try {
        var clazz = Java.use(className);
        var method = clazz[methodName];
        if (!method || !method.overloads) {
            logEvent("hook_missing", { className: className, methodName: methodName });
            return;
        }
        method.overloads.forEach(function (overload) {
            overload.implementation = callback(overload);
        });
        logEvent("hook_loaded", { className: className, methodName: methodName });
    } catch (err) {
        logEvent("hook_error", { className: className, methodName: methodName, error: String(err) });
    }
}

function installCronetHooks() {
    [
        "org.chromium.net.UrlRequest$Builder",
        "org.chromium.net.ExperimentalUrlRequest$Builder",
        "org.chromium.net.impl.UrlRequestBuilderImpl",
        "org.chromium.net.impl.JavaUrlRequest$Factory$UrlRequestBuilderImpl",
        "org.chromium.net.BidirectionalStream$Builder",
        "org.chromium.net.ExperimentalBidirectionalStream$Builder",
        "org.chromium.net.impl.BidirectionalStreamBuilderImpl"
    ].forEach(function (className) {
        safeHook(className, "addHeader", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                var key = args.length > 0 ? String(args[0]) : "";
                var value = args.length > 1 ? String(args[1]) : "";
                if (looksSensitive(key, value)) {
                    logEvent("cronet_add_header", { className: className, key: key, value: maskValue(value) });
                }
                if (args.length > 1) {
                    args[1] = maybeReplaceKeyValue(null, key, value, className + ".addHeader");
                }
                return overload.apply(this, args);
            };
        });
        safeHook(className, "build", function (overload) {
            return function () {
                injectCronetAuthHeaders(this, className + ".build");
                return overload.apply(this, arguments);
            };
        });
    });
}

function appendPackageToUidResult(result, source) {
    if (!isGmsAuxiliaryReplacementProcess()) return result;
    var demoPkg = replacementValue("package");
    var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
    if (!demoPkg || !runtimePkg || !result) return result;
    try {
        var values = [];
        var hasRuntime = false;
        var hasDemo = false;
        for (var i = 0; i < result.length; i++) {
            var text = String(result[i]);
            values.push(text);
            if (text === String(runtimePkg)) hasRuntime = true;
            if (text === String(demoPkg)) hasDemo = true;
        }
        if (!hasRuntime || hasDemo) return result;
        values.push(String(demoPkg));
        logEvent("runtime_value_replaced", {
            source: source,
            replacementKind: "package",
            key: "PackageManager.getPackagesForUid",
            from: values.slice(0, values.length - 1).join(","),
            to: values.join(",")
        });
        return Java.array("java.lang.String", values);
    } catch (err) {
        logEvent("replacement_error", { source: source, error: String(err) });
        return result;
    }
}

function isTestSignalLog(tag, message) {
    var t = String(tag || "");
    var m = String(message || "");
    return t === "APICREDTEST" || m.indexOf("APICREDTEST_") >= 0;
}

function isGoogleMapsAuthFailureLog(tag, message) {
    var t = String(tag || "");
    var m = String(message || "");
    var text = (t + " " + m).toLowerCase();
    return (
        text.indexOf("google android maps sdk") >= 0 && text.indexOf("authorization failure") >= 0
    ) || (
        text.indexOf("google maps android api") >= 0 && text.indexOf("error requesting api token") >= 0
    ) || (
        text.indexOf("google maps sdk") >= 0 && text.indexOf("disabled for this application") >= 0
    ) || (
        text.indexOf("the google maps sdk has been disabled for this application") >= 0
    ) || (
        text.indexOf("api key") >= 0 && text.indexOf("not authorized") >= 0
    );
}

function verifiedSuccessRequirement() {
    var sdkName = String((RUNTIME_REPLACEMENTS && RUNTIME_REPLACEMENTS.sdkName) || "").toLowerCase();
    var normalizedSdkName = sdkName.replace(/[^a-z0-9]+/g, "");
    var mode = packageReplacementMode();
    if (
        sdkName.indexOf("admob") >= 0 ||
        sdkName.indexOf("mobile ads") >= 0 ||
        normalizedSdkName.indexOf("mobileads") >= 0 ||
        normalizedSdkName.indexOf("googlemobileads") >= 0 ||
        mode === "admob_safe"
    ) return "admob";
    if (sdkName.indexOf("facebook") >= 0 || mode === "facebook_core") return "facebook";
    if (sdkName.indexOf("performance") >= 0 || sdkName.indexOf("perf") >= 0) return "firebase_performance";
    if (sdkName.indexOf("places") >= 0 || mode === "places_auth_stack") return "places";
    if (sdkName.indexOf("location") >= 0 || sdkName.indexOf("map") >= 0 || mode === "google_maps_location_broad") return "maps_location";
    return "generic";
}

function isVerifiedSdkSuccessSignal(text) {
    var value = String(text || "");
    if (value.indexOf("APICREDTEST_SDK_CALL_SUCCESS") < 0) return false;
    var requirement = verifiedSuccessRequirement();
    if (requirement === "places") {
        if (value.indexOf("placeLikelihoods=0") >= 0 || value.indexOf("placeCount=0") >= 0) return false;
        return value.indexOf("placeLikelihoods=") >= 0 ||
               value.indexOf("placeCount=") >= 0 ||
               value.indexOf("FindCurrentPlaceResponse") >= 0 ||
               value.indexOf("PlaceLikelihood") >= 0 ||
               value.indexOf("firstPlace=") >= 0;
    }
    if (requirement === "maps_location") {
        return value.indexOf("mapLoaded=true") >= 0 ||
               value.indexOf("Location{") >= 0 ||
               value.indexOf("lat=") >= 0 ||
               value.indexOf("APICREDTEST_MAP_LOADED") >= 0 ||
               value.indexOf("map tiles loaded") >= 0 ||
               value.indexOf("tilesLoaded=true") >= 0;
    }
    if (requirement === "admob") {
        var lowered = value.toLowerCase();
        return lowered.indexOf("ad loaded") >= 0 ||
               lowered.indexOf("banner ad loaded") >= 0 ||
               lowered.indexOf("banner loaded") >= 0 ||
               lowered.indexOf("onadloaded") >= 0 ||
               lowered.indexOf("response info") >= 0;
    }
    if (requirement === "facebook") {
        return value.indexOf("FACEBOOK_GRAPH_RESPONSE_SUCCESS") >= 0 ||
               value.indexOf("GraphResponse") >= 0 ||
               value.indexOf("publishInstall") >= 0 ||
               value.indexOf("activities") >= 0;
    }
    if (requirement === "firebase_performance") {
        var perfLowered = value.toLowerCase();
        return perfLowered.indexOf("trace=") >= 0 ||
               perfLowered.indexOf("trace completed") >= 0 ||
               perfLowered.indexOf("firebase performance trace") >= 0;
    }
    return true;
}

function logTestSignal(level, tag, message) {
    var text = String(message || "");
    var status = "unknown";
    if (text.indexOf("APICREDTEST_SDK_CALL_SUCCESS") >= 0) {
        status = isVerifiedSdkSuccessSignal(text) ? "success" : "unverified_success";
    }
    else if (text.indexOf("APICREDTEST_SDK_CALL_FAILURE") >= 0) status = "failure";
    else if (text.indexOf("APICREDTEST_SDK_CALL_START") >= 0) status = "start";
    else if (text.indexOf("APICREDTEST_SDK_CALL_COMPLETE") >= 0) status = "complete";
    else if (text.indexOf("APICREDTEST_UNCAUGHT_EXCEPTION") >= 0) status = "uncaught_exception";
    logEvent("app_test_signal", {
        level: String(level || ""),
        tag: String(tag || ""),
        message: text,
        status: status
    });
}

Java.perform(function () {
    ["i", "d", "w", "e"].forEach(function (methodName) {
        safeHook("android.util.Log", methodName, function (overload) {
            return function () {
                if (arguments.length >= 2 && isTestSignalLog(arguments[0], arguments[1])) {
                    logTestSignal(methodName.toUpperCase(), arguments[0], arguments[1]);
                } else if (arguments.length >= 2 && isGoogleMapsAuthFailureLog(arguments[0], arguments[1])) {
                    logEvent("app_test_signal", {
                        level: methodName.toUpperCase(),
                        tag: String(arguments[0] || ""),
                        message: "GOOGLE_MAPS_AUTH_FAILURE: " + String(arguments[1] || ""),
                        status: "failure",
                        stack: currentStackSummary(24)
                    });
                }
                return overload.apply(this, arguments);
            };
        });
    });

    if (isAdMobReplacementMode()) {
        installAdMobRuntimeHooks();
        [1000, 3000, 7000, 12000].forEach(function (delayMs) {
            setTimeout(function () {
                Java.perform(function () {
                    installAdMobRuntimeHooks();
                });
            }, delayMs);
        });
        return;
    }

    if (isFacebookReplacementMode()) {
        installFacebookRuntimeHooks();
        [1000, 3000, 7000, 12000].forEach(function (delayMs) {
            setTimeout(function () {
                Java.perform(function () {
                    installFacebookRuntimeHooks();
                });
            }, delayMs);
        });
        return;
    }

    if (isOneSignalReplacementMode()) {
        installOneSignalRuntimeHooks();
        [1000, 3000, 7000, 12000].forEach(function (delayMs) {
            setTimeout(function () {
                Java.perform(function () {
                    installOneSignalRuntimeHooks();
                });
            }, delayMs);
        });
    }

    safeHook("android.content.ContextWrapper", "getPackageName", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            logEvent("package_name_return", { value: String(result) });
            var replacement = maybeReplacePackageForGoogleSdkAuth(result, "ContextWrapper.getPackageName");
            return replacement;
        };
    });

    safeHook("android.app.ContextImpl", "getPackageName", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            logEvent("package_name_return", { value: String(result) });
            return maybeReplacePackageForGoogleSdkAuth(result, "ContextImpl.getPackageName");
        };
    });

    safeHook("android.app.ApplicationPackageManager", "getApplicationInfo", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var pkg = args.length > 0 ? String(args[0]) : "";
            var flags = arguments.length > 1 ? String(arguments[1]) : "";
            logEvent("package_manager_get_application_info", { packageName: pkg, flags: flags });
            args = rewritePackageManagerLookupArgs(args, "ApplicationPackageManager.getApplicationInfo.lookup");
            var result = overload.apply(this, args);
            try {
                var before = result.packageName ? String(result.packageName.value) : "";
                var replacement = shouldPatchRuntimePackageObject(pkg, before)
                    ? maybeReplaceKeyValue("package", "ApplicationInfo.packageName", before, "ApplicationPackageManager.getApplicationInfo")
                    : before;
                if (result.packageName && String(replacement) !== String(result.packageName.value)) {
                    result.packageName.value = replacement;
                }
                patchApplicationInfoMetadata(result, "ApplicationPackageManager.getApplicationInfo.metaData");
            } catch (err) {
                logEvent("replacement_error", { source: "ApplicationPackageManager.getApplicationInfo", error: String(err) });
            }
            return result;
        };
    });

    safeHook("android.app.ApplicationPackageManager", "getPackageInfo", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var pkg = args.length > 0 ? String(args[0]) : "";
            var flags = arguments.length > 1 ? String(arguments[1]) : "";
            logEvent("package_manager_get_package_info", { packageName: pkg, flags: flags });
            args = rewritePackageManagerLookupArgs(args, "ApplicationPackageManager.getPackageInfo.lookup");
            var result = overload.apply(this, args);
            try {
                if (result && result.applicationInfo) {
                    patchApplicationInfoMetadata(result.applicationInfo.value || result.applicationInfo, "ApplicationPackageManager.getPackageInfo.applicationInfo.metaData");
                }
            } catch (err) {
                logEvent("replacement_error", { source: "ApplicationPackageManager.getPackageInfo.applicationInfo.metaData", error: String(err) });
            }
            return patchPackageInfo(result, "ApplicationPackageManager.getPackageInfo", pkg);
        };
    });

    if (isBroadPackageReplacementMode()) {
        safeHook("android.app.ApplicationPackageManager", "getPackagesForUid", function (overload) {
            return function () {
                var uid = arguments.length > 0 ? String(arguments[0]) : "";
                var result = overload.apply(this, arguments);
                var packageText = "<null>";
                try {
                    if (result) {
                        var values = [];
                        for (var i = 0; i < result.length; i++) values.push(String(result[i]));
                        packageText = values.join(",");
                    }
                } catch (err) {
                    packageText = "<unprintable: " + String(err) + ">";
                }
                logEvent("package_manager_get_packages_for_uid", {
                    uid: uid,
                    packages: packageText
                });
                return appendPackageToUidResult(result, "ApplicationPackageManager.getPackagesForUid");
            };
        });

        safeHook("android.app.ApplicationPackageManager", "getNameForUid", function (overload) {
            return function () {
                var uid = arguments.length > 0 ? String(arguments[0]) : "";
                var result = overload.apply(this, arguments);
                var runtimePkg = RUNTIME_REPLACEMENTS.runtimePackageName || null;
                var demoPkg = replacementValue("package");
                if (isGmsAuxiliaryReplacementProcess() && runtimePkg && demoPkg && String(result || "") === String(runtimePkg)) {
                    logEvent("runtime_value_replaced", {
                        source: "ApplicationPackageManager.getNameForUid",
                        replacementKind: "package",
                        key: uid,
                        from: String(result),
                        to: String(demoPkg)
                    });
                    return String(demoPkg);
                }
                return result;
            };
        });

        safeHook("android.app.AppOpsManager", "checkPackage", function (overload) {
            return function () {
                var uid = arguments.length > 0 ? String(arguments[0]) : "";
                var pkg = arguments.length > 1 ? String(arguments[1]) : "";
                if (shouldSpoofUidPackage(pkg)) {
                    logEvent("runtime_value_replaced", {
                        source: "AppOpsManager.checkPackage",
                        replacementKind: "uid_package_check",
                        key: uid,
                        from: pkg,
                        to: "allowed"
                    });
                    return;
                }
                return overload.apply(this, arguments);
            };
        });

        safeHook("com.google.android.gms.common.util.UidVerifier", "uidHasPackageName", function (overload) {
            return function () {
                var pkg = arguments.length > 2 ? String(arguments[2]) : "";
                if (shouldSpoofUidPackage(pkg)) {
                    logEvent("runtime_value_replaced", {
                        source: "UidVerifier.uidHasPackageName",
                        replacementKind: "uid_package_check",
                        key: arguments.length > 1 ? String(arguments[1]) : "",
                        from: pkg,
                        to: "true"
                    });
                    return true;
                }
                return overload.apply(this, arguments);
            };
        });

        safeHook("com.google.android.gms.common.wrappers.PackageManagerWrapper", "zza", function (overload) {
            return function () {
                var returnType = overload.returnType ? String(overload.returnType.name) : "";
                var pkg = arguments.length > 1 ? String(arguments[1]) : "";
                if (returnType === "boolean" && shouldSpoofUidPackage(pkg)) {
                    logEvent("runtime_value_replaced", {
                        source: "PackageManagerWrapper.zza",
                        replacementKind: "uid_package_check",
                        key: arguments.length > 0 ? String(arguments[0]) : "",
                        from: pkg,
                        to: "true"
                    });
                    return true;
                }
                return overload.apply(this, arguments);
            };
        });
    }

    safeHook("java.security.MessageDigest", "getInstance", function (overload) {
        return function () {
            var alg = arguments.length > 0 ? String(arguments[0]) : "";
            logEvent("message_digest_algorithm", { algorithm: alg });
            return overload.apply(this, arguments);
        };
    });

    safeHook("java.security.MessageDigest", "digest", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var returnType = overload.returnType ? String(overload.returnType.name) : "";
            var algorithm = "";
            var replacementAllowed = false;
            try {
                algorithm = String(this.getAlgorithm());
                replacementAllowed = replacementEnabled() && !digestReplacementDisabled() && returnType === "[B" && shouldReplaceDigestCall(arguments);
                replacementAllowed = replacementAllowed || (replacementEnabled() && !digestReplacementDisabled() && returnType === "[B" && shouldReplaceMapsGmsTokenDigest(algorithm, result));
                if (!isBroadPackageReplacementMode() || !isInstrumentedGmsProcess()) {
                    logEvent("message_digest_digest", { algorithm: algorithm, byteLength: result ? result.length : 0 });
                }
                logDigestDecision(algorithm, result, replacementAllowed);
            } catch (diagErr) {
                logEvent("message_digest_digest", { byteLength: result ? result.length : 0 });
            }
            if (replacementAllowed) {
                try {
                    if (/^SHA-?1$/i.test(algorithm) && replacementValue("cert_sha1")) {
                        logEvent("runtime_value_replaced", {
                            source: "MessageDigest.digest",
                            replacementKind: "cert_sha1",
                            key: algorithm,
                            from: byteArrayToHex(result),
                            to: maskValue(replacementValue("cert_sha1"))
                        });
                        return hexToSignedByteArray(replacementValue("cert_sha1"));
                    }
                    if (/^SHA-?256$/i.test(algorithm) && replacementValue("cert_sha256")) {
                        logEvent("runtime_value_replaced", {
                            source: "MessageDigest.digest",
                            replacementKind: "cert_sha256",
                            key: algorithm,
                            from: byteArrayToHex(result),
                            to: maskValue(replacementValue("cert_sha256"))
                        });
                        return hexToSignedByteArray(replacementValue("cert_sha256"));
                    }
                } catch (err) {
                    logEvent("replacement_error", { source: "MessageDigest.digest", error: String(err) });
                }
            }
            return result;
        };
    });

    safeHook("android.os.Bundle", "getString", function (overload) {
        return function () {
            var key = arguments.length > 0 ? String(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            if (looksSensitive(key, result)) {
                logEvent("bundle_get_string", { key: key, value: maskValue(result) });
            }
            noteMapsGmsTokenBundleAccess(key, result, "Bundle.getString");
            return maybeReplaceKeyValue(null, key, result, "Bundle.getString");
        };
    });

    safeHook("android.os.Bundle", "putString", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("bundle_put_string", { key: key, value: maskValue(value) });
            }
            noteMapsGmsTokenBundleAccess(key, value, "Bundle.putString");
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "Bundle.putString");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("android.os.BaseBundle", "getString", function (overload) {
        return function () {
            var key = arguments.length > 0 ? String(arguments[0]) : "";
            var result = overload.apply(this, arguments);
            if (looksSensitive(key, result)) {
                logEvent("base_bundle_get_string", { key: key, value: maskValue(result) });
            }
            noteMapsGmsTokenBundleAccess(key, result, "BaseBundle.getString");
            return maybeReplaceKeyValue(null, key, result, "BaseBundle.getString");
        };
    });

    safeHook("android.os.BaseBundle", "putString", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("base_bundle_put_string", { key: key, value: maskValue(value) });
            }
            noteMapsGmsTokenBundleAccess(key, value, "BaseBundle.putString");
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "BaseBundle.putString");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("android.content.res.Resources", "getString", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var key = "resources_string";
            if (arguments.length > 0) {
                try {
                    key = String(this.getResourceEntryName(arguments[0]));
                } catch (entryErr) {}
            }
            var replacement = maybeReplaceKeyValue(null, key, result, "Resources.getString");
            if (replacement !== result) {
                return Java.use("java.lang.String").$new(String(replacement));
            }
            return result;
        };
    });

    safeHook("android.content.res.Resources", "getText", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var key = "resources_text";
            if (arguments.length > 0) {
                try {
                    key = String(this.getResourceEntryName(arguments[0]));
                } catch (entryErr) {}
            }
            var replacement = maybeReplaceKeyValue(null, key, result, "Resources.getText");
            if (replacement !== result) {
                return Java.use("java.lang.String").$new(String(replacement));
            }
            return result;
        };
    });

    safeHook("com.google.firebase.FirebaseOptions", "getApiKey", function (overload) {
        return function () {
            var result = overload.apply(this, arguments);
            var replacement = chooseReplacement("api_key", result);
            if (replacement) {
                logEvent("runtime_value_replaced", {
                    source: "FirebaseOptions.getApiKey",
                    replacementKind: "api_key",
                    key: "apiKey",
                    from: maskValue(result),
                    to: maskValue(replacement)
                });
                return String(replacement);
            }
            return result;
        };
    });

    if (!isAdMobReplacementMode()) {
        safeHook("android.os.Parcel", "writeString", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.length > 0) {
                    args[0] = maybeReplaceParcelPackageString(args[0], "Parcel.writeString");
                }
                return overload.apply(this, args);
            };
        });

        safeHook("android.os.Parcel", "writeString8", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.length > 0) {
                    args[0] = maybeReplaceParcelPackageString(args[0], "Parcel.writeString8");
                }
                return overload.apply(this, args);
            };
        });

        safeHook("android.os.Parcel", "writeString16", function (overload) {
            return function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.length > 0) {
                    args[0] = maybeReplaceParcelPackageString(args[0], "Parcel.writeString16");
                }
                return overload.apply(this, args);
            };
        });

        safeHook("android.os.Parcel", "readString", function (overload) {
            return function () {
                var result = overload.apply(this, arguments);
                return maybeReplaceParcelReadPackageString(result, "Parcel.readString");
            };
        });

        safeHook("android.os.Parcel", "readString8", function (overload) {
            return function () {
                var result = overload.apply(this, arguments);
                return maybeReplaceParcelReadPackageString(result, "Parcel.readString8");
            };
        });

        safeHook("android.os.Parcel", "readString16", function (overload) {
            return function () {
                var result = overload.apply(this, arguments);
                return maybeReplaceParcelReadPackageString(result, "Parcel.readString16");
            };
        });
    }

    safeHook("android.net.Uri$Builder", "appendQueryParameter", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("uri_query_parameter", { key: key, value: maskValue(value) });
            }
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "Uri.Builder.appendQueryParameter");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("java.net.URL", "$init", function (overload) {
        return function () {
            if (arguments.length > 0) {
                var url = String(arguments[0]);
                if (looksSensitive("url", url)) {
                    logEvent("url_init", { url: maskValue(url) });
                }
            }
            return overload.apply(this, arguments);
        };
    });

    safeHook("java.net.URL", "openConnection", function (overload) {
        return function () {
            var connection = overload.apply(this, arguments);
            return patchURLConnectionAuthHeaders(connection, "URL.openConnection");
        };
    });

    safeHook("java.net.URLConnection", "connect", function (overload) {
        return function () {
            patchURLConnectionAuthHeaders(this, "URLConnection.connect");
            return overload.apply(this, arguments);
        };
    });

    safeHook("java.net.URLConnection", "getInputStream", function (overload) {
        return function () {
            patchURLConnectionAuthHeaders(this, "URLConnection.getInputStream");
            return overload.apply(this, arguments);
        };
    });

    safeHook("java.net.URLConnection", "getOutputStream", function (overload) {
        return function () {
            patchURLConnectionAuthHeaders(this, "URLConnection.getOutputStream");
            return overload.apply(this, arguments);
        };
    });

    safeHook("java.net.HttpURLConnection", "connect", function (overload) {
        return function () {
            patchURLConnectionAuthHeaders(this, "HttpURLConnection.connect");
            return overload.apply(this, arguments);
        };
    });

    safeHook("java.net.HttpURLConnection", "setRequestProperty", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("http_request_property", { key: key, value: maskValue(value) });
            }
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "HttpURLConnection.setRequestProperty");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("java.net.URLConnection", "setRequestProperty", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("url_connection_request_property", { key: key, value: maskValue(value) });
            }
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "URLConnection.setRequestProperty");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("java.net.URLConnection", "addRequestProperty", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("url_connection_add_request_property", { key: key, value: maskValue(value) });
            }
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "URLConnection.addRequestProperty");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("okhttp3.Request$Builder", "header", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("okhttp_header", { key: key, value: maskValue(value) });
            }
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "okhttp3.Request.Builder.header");
            }
            return overload.apply(this, args);
        };
    });

    safeHook("okhttp3.Request$Builder", "addHeader", function (overload) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            var key = args.length > 0 ? String(args[0]) : "";
            var value = args.length > 1 ? String(args[1]) : "";
            if (looksSensitive(key, value)) {
                logEvent("okhttp_add_header", { key: key, value: maskValue(value) });
            }
            if (args.length > 1) {
                args[1] = maybeReplaceKeyValue(null, key, value, "okhttp3.Request.Builder.addHeader");
            }
            return overload.apply(this, args);
        };
    });

    installAdMobRuntimeHooks();
    installCronetHooks();
    [1000, 3000, 7000, 12000].forEach(function (delayMs) {
        setTimeout(function () {
            Java.perform(function () {
                installAdMobRuntimeHooks();
                installCronetHooks();
            });
        }, delayMs);
    });
});
"""


class FridaHooker:
    """Passive Frida monitor for SDK credential/protection audits."""

    def __init__(
        self,
        package_name: str,
        launch_activity: Optional[str] = None,
        hook_method_signatures: Optional[List[str]] = None,
        runtime_replacements: Optional[Dict[str, object]] = None,
    ):
        self.package_name = package_name
        self.launch_activity = launch_activity
        self.hook_method_signatures = hook_method_signatures or []
        self.runtime_replacements = runtime_replacements or {}

    def write_script(self, output_path: str) -> str:
        Path(output_path).write_text(self.build_script(), encoding="utf-8")
        return output_path

    def build_script(self) -> str:
        replacements = dict(self.runtime_replacements or {})
        replacements.setdefault("instrumentedProcess", self.package_name)
        prefix = build_runtime_replacement_config_js(replacements)
        if not self.hook_method_signatures:
            return prefix + PASSIVE_MONITOR_JS

        return prefix + PASSIVE_MONITOR_JS + "\n" + build_method_observer_js(self.hook_method_signatures)

    def should_attach_gms_runtime_monitor(self) -> bool:
        return bool(
            self.runtime_replacements.get("enabled")
            and self.runtime_replacements.get("packageReplacementMode") == "google_maps_location_broad"
        )

    def build_gms_runtime_monitor_script(self) -> str:
        replacements = dict(self.runtime_replacements or {})
        replacements["instrumentedProcess"] = "com.google.android.gms"
        replacements["replaceLocalBundlePackageName"] = True
        replacements["disableUrlConnectionHeaderPatch"] = True
        prefix = build_runtime_replacement_config_js(replacements)
        return prefix + PASSIVE_MONITOR_JS

    def find_google_play_services_pid(self, device) -> Optional[int]:
        try:
            for process in device.enumerate_processes():
                if process.name == "com.google.android.gms":
                    return process.pid
        except Exception as exc:
            print(f"[!] Could not enumerate Frida processes for GMS: {exc}")
        proc = subprocess.run(
            ["adb", "shell", "pidof", "com.google.android.gms"],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        output = proc.stdout.strip()
        if output:
            first_pid = output.split()[0]
            if first_pid.isdigit():
                return int(first_pid)
        return None

    def attach_google_play_services_monitor(
        self,
        device,
        detached: Optional[threading.Event] = None,
        detach_info: Optional[Dict[str, object]] = None,
        stop_on_success: bool = True,
    ) -> List[object]:
        if not self.should_attach_gms_runtime_monitor():
            return []
        pid = self.find_google_play_services_pid(device)
        if not pid:
            print("[!] Google Play services process not found; continuing with attacker-process hooks only.")
            return []
        try:
            print(f"[*] Attaching auxiliary Frida monitor to com.google.android.gms pid {pid}.")
            session = device.attach(pid)
            script = session.create_script(self.build_gms_runtime_monitor_script())
            if detached is not None and detach_info is not None:
                script.on("message", self.on_message_with_result(detached, detach_info, stop_on_success=stop_on_success))
            else:
                script.on("message", self.on_message)
            script.load()
            return [session]
        except Exception as exc:
            print(f"[!] Could not attach auxiliary GMS monitor: {exc}")
            return []

    def detach_auxiliary_sessions(self, sessions: List[object]) -> None:
        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass

    def on_message(self, message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("kind") == "app_test_signal":
                status = payload.get("status") or "unknown"
                level = payload.get("level") or ""
                tag = payload.get("tag") or ""
                text = payload.get("message") or ""
                print(f"[app-signal] status={status} level={level} tag={tag} message={text}")
                if status == "success":
                    print("[+] SDK call success detected; keeping Frida session attached.")
                elif status == "failure":
                    reason = self.failure_reason_for_text(text)
                    if reason != "sdk-call-failure":
                        print(f"[app-signal] failure_reason={reason}")
                return
            print("[frida] " + json.dumps(payload, ensure_ascii=False))
        else:
            print(message)

    def on_message_with_result(
        self,
        detached: threading.Event,
        detach_info: Dict[str, object],
        stop_on_success: bool,
    ):
        def handler(message, data):
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, dict) and payload.get("kind") == "app_test_signal":
                    status = payload.get("status") or "unknown"
                    if status == "success":
                        detach_info["last_signal"] = status
                        detach_info["reason"] = "sdk-call-success"
                        if stop_on_success:
                            detached.set()
                    elif status == "failure":
                        if detach_info.get("reason") == "sdk-call-success" or detach_info.get("last_signal") == "success":
                            self.on_message(message, data)
                            return
                        detach_info["last_signal"] = status
                        detach_info["reason"] = self.failure_reason_for_text(str(payload.get("message") or ""))
                        detached.set()
                    else:
                        detach_info["last_signal"] = status
                self.on_message(message, data)
                return
            self.on_message(message, data)

        return handler

    def classify_test_signal_text(self, text: str) -> Optional[str]:
        if "APICREDTEST_SDK_CALL_SUCCESS" in text:
            return "success" if self.is_verified_success_signal(text) else "unverified_success"
        if "APICREDTEST_SDK_CALL_FAILURE" in text:
            return "failure"
        if "APICREDTEST_UNCAUGHT_EXCEPTION" in text:
            return "uncaught_exception"
        if "APICREDTEST_SDK_CALL_START" in text:
            return "start"
        if "APICREDTEST_SDK_CALL_COMPLETE" in text:
            return "complete"
        return None

    @staticmethod
    def failure_reason_for_text(text: str) -> str:
        lowered = (text or "").lower()
        if "publisher data not found" in lowered:
            return "admob-publisher-data-not-found"
        if "invalid_ad_unit_id" in lowered or "invalid ad unit" in lowered:
            return "admob-invalid-ad-unit-id"
        if "no fill" in lowered:
            return "admob-no-fill"
        if "facebook_graph_response_failure" in lowered:
            return "facebook-graph-response-failure"
        if "invalid app id" in lowered or "invalid application id" in lowered:
            return "facebook-invalid-app-id"
        if "client token" in lowered:
            return "facebook-client-token-error"
        return "sdk-call-failure"

    def is_facebook_share_kit_mode(self) -> bool:
        sdk_name = str(self.runtime_replacements.get("sdkName") or "").lower()
        mode = str(self.runtime_replacements.get("packageReplacementMode") or "")
        return mode == "facebook_share_kit" or ("facebook" in sdk_name and "share" in sdk_name)

    def is_google_maps_location_mode(self) -> bool:
        sdk_name = str(self.runtime_replacements.get("sdkName") or "").lower()
        mode = str(self.runtime_replacements.get("packageReplacementMode") or "")
        return "location" in sdk_name or "map" in sdk_name or mode == "google_maps_location_broad"

    def is_verified_success_signal(self, text: str) -> bool:
        sdk_name = str(self.runtime_replacements.get("sdkName") or "").lower()
        normalized_sdk_name = re.sub(r"[^a-z0-9]+", "", sdk_name)
        mode = str(self.runtime_replacements.get("packageReplacementMode") or "")
        if (
            "admob" in sdk_name
            or "mobile ads" in sdk_name
            or "mobileads" in normalized_sdk_name
            or "googlemobileads" in normalized_sdk_name
            or mode == "admob_safe"
        ):
            if (
                "user messaging platform" in sdk_name
                or "usermessagingplatform" in normalized_sdk_name
                or "googleusermessagingplatform" in normalized_sdk_name
            ):
                return "APICREDTEST_SDK_CALL_SUCCESS" in text
            lowered = text.lower()
            return any(
                marker in lowered
                for marker in (
                    "ad loaded",
                    "banner ad loaded",
                    "banner loaded",
                    "onadloaded",
                    "response info",
                )
            )
        if "places" in sdk_name or mode == "places_auth_stack":
            if "placeLikelihoods=0" in text or "placeCount=0" in text:
                return False
            return any(
                marker in text
                for marker in (
                    "placeLikelihoods=",
                    "placeCount=",
                    "FindCurrentPlaceResponse",
                    "PlaceLikelihood",
                    "firstPlace=",
                )
            )
        if "location" in sdk_name or "map" in sdk_name or mode == "google_maps_location_broad":
            return any(
                marker in text
                for marker in (
                    "mapLoaded=true",
                    "Location{",
                    "lat=",
                    "APICREDTEST_MAP_LOADED",
                    "map tiles loaded",
                    "tilesLoaded=true",
                )
            )
        if "performance" in sdk_name or "perf" in sdk_name:
            lowered = text.lower()
            return (
                "trace=" in lowered
                or "trace completed" in lowered
                or "firebase performance trace" in lowered
            )
        if self.is_facebook_share_kit_mode():
            lowered = text.lower()
            return (
                "FACEBOOK_SHARE_DIALOG_SHOWN" in text
                or "FACEBOOK_SHARE_UI_HANDOFF" in text
                or "share success" in lowered
                or "postid=" in lowered
            )
        if "facebook" in sdk_name or mode == "facebook_core":
            return (
                "FACEBOOK_GRAPH_RESPONSE_SUCCESS" in text
                or "GraphResponse" in text
                or "publishInstall" in text
                or "activities" in text
            )
        return True

    def detect_google_map_visual_loaded(self) -> bool:
        if not self.is_google_maps_location_mode():
            return False
        try:
            from PIL import Image
        except Exception as exc:
            print(f"[!] Map visual probe skipped; Pillow is unavailable: {exc}")
            return False

        try:
            proc = subprocess.run(
                ["adb", "exec-out", "screencap", "-p"],
                capture_output=True,
                check=False,
                timeout=8.0,
            )
        except Exception as exc:
            print(f"[!] Map visual probe failed to capture screen: {exc}")
            return False
        if proc.returncode != 0 or not proc.stdout:
            print("[!] Map visual probe failed: screencap returned no image.")
            return False

        try:
            image = Image.open(BytesIO(proc.stdout)).convert("RGB")
        except Exception as exc:
            print(f"[!] Map visual probe failed to decode screenshot: {exc}")
            return False

        width, height = image.size
        top = max(0, int(height * 0.13))
        bottom = min(height, int(height * 0.84))
        if bottom <= top:
            return False
        crop = image.crop((0, top, width, bottom))

        pixels = []
        step = max(4, min(width, height) // 140)
        for y in range(0, crop.height, step):
            for x in range(0, crop.width, step):
                r, g, b = crop.getpixel((x, y))
                pixels.append((r, g, b))
        if len(pixels) < 50:
            return False

        quantized = {(r // 16, g // 16, b // 16) for r, g, b in pixels}
        non_blank = 0
        colorful = 0
        for r, g, b in pixels:
            channel_range = max(r, g, b) - min(r, g, b)
            if channel_range > 24:
                colorful += 1
            if not (225 <= r <= 250 and 220 <= g <= 245 and 210 <= b <= 240):
                non_blank += 1

        unique_ratio = len(quantized) / max(1, len(pixels))
        non_blank_ratio = non_blank / max(1, len(pixels))
        colorful_ratio = colorful / max(1, len(pixels))
        loaded = (
            (unique_ratio >= 0.018 and non_blank_ratio >= 0.35 and colorful_ratio >= 0.08)
            or (non_blank_ratio >= 0.55 and colorful_ratio >= 0.18)
        )
        print(
            "[*] Map visual probe: "
            f"unique_ratio={unique_ratio:.3f}, non_blank_ratio={non_blank_ratio:.3f}, "
            f"colorful_ratio={colorful_ratio:.3f}, loaded={loaded}"
        )

        try:
            out_dir = Path("app_hook_logs")
            out_dir.mkdir(parents=True, exist_ok=True)
            image.save(out_dir / f"{self.package_name.replace('.', '_')}_map_visual_probe.png")
        except Exception:
            pass
        return loaded

    @staticmethod
    def printable_logcat_line(text: str) -> str:
        return text.replace("\ufffd", "?")

    def install_apk(self, apk_path: str) -> bool:
        try:
            proc = subprocess.run(
                ["adb", "install", "-r", apk_path],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            output = (proc.stdout + proc.stderr).strip()
            if output:
                print(output)
            if proc.returncode == 0:
                self.prepare_prelaunch_runtime_state()
                self.grant_common_runtime_permissions()
                return True
            if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in output or "signatures do not match" in output:
                print(
                    f"[!] Existing package {self.package_name} has an incompatible signature; "
                    "uninstalling it before reinstalling the test APK."
                )
                uninstall = subprocess.run(
                    ["adb", "uninstall", self.package_name],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
                uninstall_output = (uninstall.stdout + uninstall.stderr).strip()
                if uninstall_output:
                    print(uninstall_output)
                proc = subprocess.run(
                    ["adb", "install", "-r", apk_path],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
                output = (proc.stdout + proc.stderr).strip()
                if output:
                    print(output)
                if proc.returncode == 0:
                    self.prepare_prelaunch_runtime_state()
                    self.grant_common_runtime_permissions()
                    return True
                return False
            print(f"[-] adb install failed with exit code {proc.returncode}.")
            return False
        except Exception as exc:
            print(f"[-] adb install failed: {exc}")
            return False

    def prepare_prelaunch_runtime_state(self) -> None:
        if self.is_onesignal_replacement_mode():
            self.prepare_onesignal_app_id_cache()

    def is_onesignal_replacement_mode(self) -> bool:
        mode = str(self.runtime_replacements.get("packageReplacementMode") or "").lower()
        sdk_name = re.sub(r"[^a-z0-9]+", "", str(self.runtime_replacements.get("sdkName") or "").lower())
        return mode == "onesignal_core" or "onesignal" in sdk_name

    def prepare_onesignal_app_id_cache(self) -> None:
        app_id = str(self.runtime_replacements.get("oneSignalAppId") or "").strip().lower()
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            app_id,
        ):
            print("[!] OneSignal prelaunch cache seeding skipped: demo App ID is unavailable.")
            return

        print("[*] Preparing OneSignal prelaunch state with demo App ID cache.")
        clear_proc = subprocess.run(
            ["adb", "shell", "pm", "clear", self.package_name],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        clear_output = (clear_proc.stdout + clear_proc.stderr).strip()
        if clear_output:
            print(clear_output)
        if clear_proc.returncode != 0:
            print("[!] OneSignal prelaunch cache seeding skipped: pm clear failed.")
            return

        uid, data_dir = self.get_package_data_owner()
        if not uid or not data_dir:
            print("[!] OneSignal prelaunch cache seeding skipped: package data owner not found.")
            return

        context = self.get_remote_selinux_context(data_dir)
        prefs_dir = f"{data_dir}/shared_prefs"
        prefs_file = f"{prefs_dir}/{self.package_name}.xml"
        remote_tmp = f"/data/local/tmp/apicred_onesignal_{self.package_name.replace('.', '_')}.xml"
        xml = (
            "<map>\n"
            f"    <string name=\"OS_APP_ID_SHARED_PREF\">{xml_escape(app_id)}</string>\n"
            "</map>\n"
        )

        tmp_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8", newline="\n") as handle:
                handle.write(xml)
                tmp_path = Path(handle.name)
            push_proc = subprocess.run(
                ["adb", "push", str(tmp_path), remote_tmp],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            push_output = (push_proc.stdout + push_proc.stderr).strip()
            if push_output:
                print(push_output)
            if push_proc.returncode != 0:
                print("[!] OneSignal prelaunch cache seeding skipped: adb push failed.")
                return

            commands = [
                f"mkdir -p {prefs_dir}",
                f"cp {remote_tmp} {prefs_file}",
                f"chown {uid}.{uid} {prefs_dir}",
                f"chown {uid}.{uid} {prefs_file}",
                f"chmod 771 {prefs_dir}",
                f"chmod 660 {prefs_file}",
            ]
            if context:
                commands.extend(
                    [
                        f"chcon {context} {prefs_dir}",
                        f"chcon {context} {prefs_file}",
                    ]
                )
            commands.append(f"rm -f {remote_tmp}")

            for command in commands:
                proc = subprocess.run(
                    ["adb", "shell", "su", "-c", command],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
                output = (proc.stdout + proc.stderr).strip()
                if proc.returncode != 0:
                    print(f"[!] OneSignal prelaunch command failed: {command}")
                    if output:
                        print(output)
                    return
            print(f"[+] Seeded OneSignal App ID cache for {self.package_name}.")
        finally:
            if tmp_path:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def get_package_data_owner(self) -> Tuple[Optional[str], Optional[str]]:
        proc = subprocess.run(
            ["adb", "shell", "dumpsys", "package", self.package_name],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        text = proc.stdout + proc.stderr
        uid_match = re.search(r"\buserId=(\d+)", text)
        data_dir_match = re.search(r"\bdataDir=(\S+)", text)
        uid = uid_match.group(1) if uid_match else None
        data_dir = data_dir_match.group(1) if data_dir_match else f"/data/user/0/{self.package_name}"
        return uid, data_dir

    @staticmethod
    def get_remote_selinux_context(path: str) -> Optional[str]:
        proc = subprocess.run(
            ["adb", "shell", "su", "-c", f"ls -Zd {path}"],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        output = (proc.stdout + proc.stderr).strip()
        match = re.search(r"\bu:object_r:\S+", output)
        return match.group(0) if match else None

    def grant_common_runtime_permissions(self) -> None:
        permissions = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
        ]
        for permission in permissions:
            proc = subprocess.run(
                ["adb", "shell", "pm", "grant", self.package_name, permission],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            output = (proc.stdout + proc.stderr).strip()
            if proc.returncode == 0:
                print(f"[+] Granted {permission} to {self.package_name}.")
            elif output and "not requested" not in output.lower():
                print(f"[!] Could not grant {permission}: {output}")

    def is_package_installed(self) -> bool:
        proc = subprocess.run(
            ["adb", "shell", "pm", "path", self.package_name],
            capture_output=True,
            text=True,
            errors="replace",
        )
        installed = proc.returncode == 0 and "package:" in proc.stdout
        if installed:
            print(f"[+] Package is installed: {self.package_name}")
        else:
            print(f"[-] Package is not installed or not visible to adb: {self.package_name}")
        return installed

    def launch_with_adb(self) -> bool:
        commands = []
        if self.launch_activity:
            component = f"{self.package_name}/{self.launch_activity}"
            commands.append(["adb", "shell", "am", "start", "-W", "-n", component])
        commands.append(
            [
                "adb",
                "shell",
                "monkey",
                "-p",
                self.package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]
        )

        for command in commands:
            print(f"[*] Launching app with adb: {' '.join(command)}")
            proc = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
            output = (proc.stdout + proc.stderr).strip()
            if proc.returncode == 0 and "Error:" not in output and "Exception" not in output:
                launched_activity = self.extract_launched_activity(output)
                if launched_activity:
                    print(f"[+] adb launch succeeded: {launched_activity}")
                else:
                    print("[+] adb launch succeeded.")
                return True
            print(f"[!] adb launch command failed with exit code {proc.returncode}; trying fallback if available.")
            if output:
                print(output)

        self.print_launch_resolution()
        return False

    @staticmethod
    def extract_launched_activity(output: str) -> Optional[str]:
        for line in (output or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("Activity:"):
                return stripped.split(":", 1)[1].strip()
        return None

    def print_launch_resolution(self) -> None:
        commands = [
            ["adb", "shell", "cmd", "package", "resolve-activity", "--brief", self.package_name],
            [
                "adb",
                "shell",
                "cmd",
                "package",
                "resolve-activity",
                "--brief",
                "-c",
                "android.intent.category.LAUNCHER",
                self.package_name,
            ],
        ]
        print(f"[*] Launch resolution diagnostics for {self.package_name}:")
        for command in commands:
            proc = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
            text = (proc.stdout + proc.stderr).strip()
            print(f"$ {' '.join(command)}\n{text or '<no output>'}")

    def force_stop_app(self) -> None:
        proc = subprocess.run(
            ["adb", "shell", "am", "force-stop", self.package_name],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        output = (proc.stdout + proc.stderr).strip()
        if output:
            print(output)
        print(f"[*] Force-stopped {self.package_name}; waiting 2.0s for process cleanup.")
        time.sleep(2.0)

    def find_process_pid(self) -> Optional[int]:
        commands = [
            ["adb", "shell", "pidof", self.package_name],
            ["adb", "shell", "pidof", f"{self.package_name}:remote"],
        ]
        for command in commands:
            proc = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
            output = proc.stdout.strip()
            if output:
                first_pid = output.split()[0]
                if first_pid.isdigit():
                    return int(first_pid)
        return None

    def find_frida_process_pid(self, device) -> Optional[int]:
        try:
            for process in device.enumerate_processes():
                if process.name == self.package_name or process.name.startswith(self.package_name + ":"):
                    return process.pid
        except Exception as exc:
            print(f"[!] Could not enumerate Frida processes: {exc}")
        return None

    def wait_for_process_pid(self, device, timeout_seconds: float) -> Optional[int]:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            pid = self.find_process_pid() or self.find_frida_process_pid(device)
            if pid:
                return pid
            time.sleep(0.5)
        return None

    def call_with_timeout(self, label: str, timeout_seconds: float, func):
        result_queue: "queue.Queue[Tuple[str, object]]" = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                result_queue.put(("ok", func()))
            except Exception as exc:
                result_queue.put(("error", exc))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            status, value = result_queue.get(timeout=timeout_seconds)
        except queue.Empty as exc:
            raise TimeoutError(f"{label} timed out after {timeout_seconds:.1f}s") from exc
        if status == "error":
            raise value
        return value

    def attach_running_process(self, device, timeout_seconds: float):
        pid = self.wait_for_process_pid(device, timeout_seconds)
        if pid:
            print(f"[*] Attaching to pid {pid} for {self.package_name}.")
            try:
                return self.call_with_timeout(
                    f"Frida attach to pid {pid}",
                    timeout_seconds,
                    lambda: device.attach(pid),
                )
            except TimeoutError as exc:
                print(f"[!] {exc}; trying Frida attach by package name before server recovery.")

        print(f"[*] No pid found after {timeout_seconds:.1f}s; trying Frida attach by package name.")
        return self.call_with_timeout(
            f"Frida attach to {self.package_name}",
            timeout_seconds,
            lambda: device.attach(self.package_name),
        )

    def restart_frida_server_after_timeout(self) -> bool:
        print("[*] Restarting frida-server after attach timeout.")
        ps_proc = subprocess.run(
            ["adb", "shell", "ps", "-A"],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        server_names = []
        for line in (ps_proc.stdout + ps_proc.stderr).splitlines():
            if "frida-server" not in line:
                continue
            parts = line.split()
            if parts:
                server_names.append(parts[-1].split("/")[-1])
        if not server_names:
            server_names.append("frida-server")

        for name in server_names:
            pid_proc = subprocess.run(
                ["adb", "shell", "pidof", name],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            for pid in pid_proc.stdout.split():
                if not pid.isdigit():
                    continue
                subprocess.run(
                    ["adb", "shell", "su", "-c", f"kill -9 {pid}"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
                subprocess.run(
                    ["adb", "shell", "kill", "-9", pid],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
        subprocess.run(
            ["adb", "shell", "su", "-c", "pkill -f frida-server"],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        time.sleep(1.5)

        candidates = []
        for name in server_names:
            candidates.append(f"/data/local/tmp/{name}")
        candidates.extend(
            [
                "/data/local/tmp/frida-server-16.4.10-android-arm64",
                "/data/local/tmp/frida-server",
            ]
        )

        seen = set()
        for remote_path in candidates:
            if remote_path in seen:
                continue
            seen.add(remote_path)
            check = subprocess.run(
                ["adb", "shell", "ls", remote_path],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            if check.returncode != 0:
                continue
            command = ["adb", "shell", "su", "-c", f"nohup {remote_path} >/dev/null 2>&1 &"]
            proc = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
            if proc.returncode != 0:
                command = ["adb", "shell", f"nohup {remote_path} >/dev/null 2>&1 &"]
                proc = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
            if proc.returncode == 0:
                time.sleep(2.0)
                verify = subprocess.run(
                    ["adb", "shell", "pidof", remote_path.split("/")[-1]],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
                if verify.stdout.strip():
                    print(f"[+] frida-server restarted: {remote_path}")
                    return True
        print("[!] Could not restart frida-server automatically.")
        return False

    def print_process_diagnostics(self) -> None:
        print(f"[*] Process diagnostics for {self.package_name}:")
        commands = [
            ["adb", "shell", "pidof", self.package_name],
            ["adb", "shell", "ps", "-A"],
            ["adb", "shell", "dumpsys", "activity", "top"],
        ]
        for command in commands:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            text = (proc.stdout + proc.stderr).strip()
            if len(command) > 2 and command[2] == "pidof":
                print(f"$ {' '.join(command)}\n{text or '<no pid>'}")
            elif len(command) > 2 and command[2] == "ps":
                matches = [line for line in text.splitlines() if self.package_name in line]
                print(f"$ {' '.join(command)}\n" + ("\n".join(matches) if matches else "<no matching process>"))
            else:
                top_lines = text.splitlines()[:30]
                print(f"$ {' '.join(command)}\n" + ("\n".join(top_lines) if top_lines else "<no output>"))

    def detect_facebook_share_ui_handoff(self) -> bool:
        if "facebook" not in str(self.runtime_replacements.get("sdkName") or "").lower() and str(
            self.runtime_replacements.get("packageReplacementMode") or ""
        ) not in {"facebook_core", "facebook_share_kit"}:
            return False
        markers = (
            "com.facebook.katana",
            "com.facebook.lite",
            "com.facebook.orca",
            "com.facebook.fblite",
            "com.facebook.facebookactivity",
            "com.facebook.customtabactivity",
            "com.facebook.customtabmainactivity",
            "facebookactivity",
            "platformactivity",
            "proxyauth",
            "fbconnect",
            "com.android.chrome",
            "com.chrome",
            "com.android.browser",
            "org.mozilla.firefox",
        )

        checks = [
            (
                ["adb", "shell", "dumpsys", "activity", "top"],
                lambda text: "\n".join(text.splitlines()[:80]),
            ),
            (
                ["adb", "shell", "dumpsys", "activity", "activities"],
                lambda text: "\n".join(
                    line
                    for line in text.splitlines()
                    if any(
                        token in line.lower()
                        for token in (
                            "mresumedactivity",
                            "topresumedactivity",
                            "mfocusedapp",
                            "resumedactivity",
                        )
                    )
                ),
            ),
            (
                ["adb", "shell", "dumpsys", "window", "windows"],
                lambda text: "\n".join(
                    line
                    for line in text.splitlines()
                    if any(
                        token in line.lower()
                        for token in (
                            "mcurrentfocus",
                            "mfocusedapp",
                            "mfocusedwindow",
                        )
                    )
                ),
            ),
        ]
        for command, relevant_text in checks:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            text = relevant_text(proc.stdout + proc.stderr).lower()
            if self.package_name and self.package_name.lower() in text:
                continue
            if text and any(marker in text for marker in markers):
                print("[+] Facebook SDK UI handoff detected from Android activity/window state.")
                return True
        return False

    def spawn_with_timeout(self, device, spawn_target: str, timeout_seconds: float) -> Optional[int]:
        result_queue: "queue.Queue[Tuple[str, object]]" = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                result_queue.put(("ok", device.spawn(spawn_target)))
            except Exception as exc:
                result_queue.put(("error", exc))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            status, value = result_queue.get(timeout=timeout_seconds)
        except queue.Empty:
            print(
                f"[!] Frida spawn timed out after {timeout_seconds:.1f}s for {spawn_target}; "
                "falling back to adb launch + attach."
            )
            return None
        if status == "ok":
            pid = int(value)
            print(f"[+] Frida spawned {spawn_target} as pid {pid}.")
            return pid
        print(f"[!] spawn failed for {spawn_target}: {value}")
        return None

    def start_instrumented_session(self, device, spawn: bool, attach_timeout: float):
        session = None
        resume_pid = None
        monitor_pid = None

        if spawn:
            self.force_stop_app()
            time.sleep(0.5)
            spawn_target = self.package_name
            try:
                print(f"[*] Trying Frida spawn target: {spawn_target}")
                resume_pid = self.spawn_with_timeout(device, spawn_target, timeout_seconds=6.0)
                if resume_pid:
                    monitor_pid = resume_pid
                    session = self.call_with_timeout(
                        f"Frida attach to spawned pid {resume_pid}",
                        attach_timeout,
                        lambda: device.attach(resume_pid),
                    )
            except Exception as exc:
                resume_pid = None
                monitor_pid = None
                print(f"[!] spawn/attach failed for {spawn_target}: {exc}")
            if not session:
                print("[!] Frida spawn failed or timed out, falling back to adb launch + attach.")

        if not session:
            launched = self.launch_with_adb()
            if not launched:
                print("[!] adb launch did not report success; still trying to attach in case the process started.")
            session = self.attach_running_process(device, attach_timeout)
            monitor_pid = self.find_process_pid() or self.find_frida_process_pid(device)

        return session, resume_pid, monitor_pid

    def start_test_signal_monitor(
        self,
        pid: Optional[int],
        detached: threading.Event,
        detach_info: Dict[str, object],
        stop_on_success: bool = False,
    ) -> Optional[Tuple[subprocess.Popen, threading.Thread]]:
        if not pid:
            return None

        command = ["adb", "logcat", "--pid", str(pid)]
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except Exception as exc:
            print(f"[!] Could not start logcat signal monitor: {exc}")
            return None

        success_seen = False

        def watch_logcat() -> None:
            nonlocal success_seen
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    text = line.strip()
                    if not text:
                        continue
                    printable_text = self.printable_logcat_line(text)
                    signal_status = self.classify_test_signal_text(text)
                    if signal_status == "success":
                        print(f"[app-signal] {printable_text}")
                        if not success_seen:
                            success_seen = True
                            detach_info["last_signal"] = "success"
                            detach_info["reason"] = "sdk-call-success"
                            print("[+] SDK call success detected; keeping Frida session attached.")
                            if stop_on_success:
                                detached.set()
                                break
                    elif signal_status == "unverified_success":
                        print(f"[app-signal] status=unverified_success {printable_text}")
                        detach_info["last_signal"] = "unverified_success"
                        detach_info["unverified_success_seen"] = True
                        if self.detect_facebook_share_ui_handoff():
                            detach_info["last_signal"] = "success"
                            detach_info["reason"] = "facebook-ui-handoff"
                            detached.set()
                            break
                    elif signal_status == "failure":
                        print(f"[app-signal] {printable_text}")
                        if success_seen or detach_info.get("reason") == "sdk-call-success" or detach_info.get("last_signal") == "success":
                            continue
                        detach_info["reason"] = self.failure_reason_for_text(text)
                        detach_info["last_signal"] = "failure"
                        detached.set()
                        break
                    elif signal_status == "uncaught_exception":
                        print(f"[app-signal] {printable_text}")
            except Exception as exc:
                if proc.poll() is None:
                    print(f"[!] logcat signal monitor failed: {exc}")

        thread = threading.Thread(target=watch_logcat, daemon=True)
        thread.start()
        return proc, thread

    def stop_test_signal_monitor(self, monitor: Optional[Tuple[subprocess.Popen, threading.Thread]]) -> None:
        if not monitor:
            return
        proc, _ = monitor
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()

    def run(
        self,
        install_apk_path: Optional[str] = None,
        spawn: bool = True,
        attach_timeout: float = 10.0,
        max_restarts: int = 3,
        restart_delay: float = 2.0,
        monitor_interval: float = 1.0,
    ) -> None:
        if install_apk_path and not self.install_apk(install_apk_path):
            return
        if not self.is_package_installed():
            print("[!] Set AppHook_INSTALL_ATTACKER=true if you want app_hooker.py to install the attacker APK first.")
            return

        if self.runtime_replacements.get("enabled"):
            print("[*] Starting Frida monitor with runtime value replacement enabled.")
        else:
            print("[*] Starting passive Frida monitor. No app values will be modified.")
        device = frida.get_usb_device(timeout=10)

        restart_count = 0
        print(
            f"[*] Crash/restart monitor enabled: max_restarts={max_restarts}, "
            f"restart_delay={restart_delay:.1f}s."
        )
        while True:
            session = None
            pid = None
            detached = threading.Event()
            detach_info = {"reason": None, "crash": None}
            signal_monitor = None
            auxiliary_sessions: List[object] = []
            try:
                auxiliary_sessions = self.attach_google_play_services_monitor(
                    device,
                    detached=detached,
                    detach_info=detach_info,
                    stop_on_success=False,
                )
                session, resume_pid, monitor_pid = self.start_instrumented_session(device, spawn, attach_timeout)
            except Exception as exc:
                print(f"[-] Could not attach to {self.package_name}: {exc}")
                self.detach_auxiliary_sessions(auxiliary_sessions)
                self.print_process_diagnostics()
                return

            def on_detached(reason=None, crash=None, *args):
                detach_info["reason"] = reason
                detach_info["crash"] = crash
                print(f"[!] Frida session detached: reason={reason}, crash={crash}")
                detached.set()

            session.on("detached", on_detached)
            script = session.create_script(self.build_script())
            script.on("message", self.on_message_with_result(detached, detach_info, stop_on_success=False))
            self.call_with_timeout("Frida script load", 8.0, script.load)
            if resume_pid:
                device.resume(resume_pid)
            signal_monitor = self.start_test_signal_monitor(monitor_pid, detached, detach_info)
            print(f"[+] Monitoring {self.package_name}. Press Ctrl+C to stop; crashes will restart automatically.")

            missing_pid_checks = 0
            try:
                while not detached.wait(timeout=monitor_interval):
                    if detach_info.get("unverified_success_seen") and self.detect_facebook_share_ui_handoff():
                        detach_info["reason"] = "facebook-ui-handoff"
                        detach_info["last_signal"] = "success"
                        detached.set()
                        break
                    if self.find_process_pid() or self.find_frida_process_pid(device):
                        missing_pid_checks = 0
                        continue
                    missing_pid_checks += 1
                    if missing_pid_checks >= 2:
                        detach_info["reason"] = "process-not-found"
                        print(f"[!] No running pid found for {self.package_name}; treating as crash/exit.")
                        break
            except KeyboardInterrupt:
                print("[*] Stopping Frida monitor.")
                self.stop_test_signal_monitor(signal_monitor)
                try:
                    session.detach()
                except Exception:
                    pass
                self.detach_auxiliary_sessions(auxiliary_sessions)
                return

            restart_count += 1
            if restart_count > max_restarts:
                print(f"[-] Restart limit reached ({max_restarts}); leaving monitor stopped.")
                self.stop_test_signal_monitor(signal_monitor)
                try:
                    session.detach()
                except Exception:
                    pass
                self.detach_auxiliary_sessions(auxiliary_sessions)
                self.print_process_diagnostics()
                return

            print(
                f"[*] Restarting {self.package_name} after detach/exit "
                f"({restart_count}/{max_restarts}) in {restart_delay:.1f}s..."
            )
            self.stop_test_signal_monitor(signal_monitor)
            try:
                session.detach()
            except Exception:
                pass
            self.detach_auxiliary_sessions(auxiliary_sessions)
            time.sleep(restart_delay)

    def run_attempt(
        self,
        install_apk_path: Optional[str] = None,
        spawn: bool = True,
        attach_timeout: float = 10.0,
        attempt_timeout: float = 45.0,
        monitor_interval: float = 1.0,
        stop_app_after: bool = True,
        keep_app_on_success: bool = False,
    ) -> HookRunResult:
        if install_apk_path and not self.install_apk(install_apk_path):
            return HookRunResult(status="setup_failed", reason="install_failed")
        if not self.is_package_installed():
            print("[!] Set AppHook_INSTALL_ATTACKER=true if you want app_hooker.py to install the attacker APK first.")
            return HookRunResult(status="setup_failed", reason="package_not_installed")

        if self.runtime_replacements.get("enabled"):
            print("[*] Starting one-shot Frida attempt with runtime value replacement enabled.")
        else:
            print("[*] Starting one-shot passive Frida attempt. No app values will be modified.")

        device = frida.get_usb_device(timeout=10)
        session = None
        signal_monitor = None
        auxiliary_sessions: List[object] = []
        final_status = "unknown"
        detached = threading.Event()
        detach_info: Dict[str, object] = {"reason": None, "crash": None, "last_signal": None}

        try:
            try:
                auxiliary_sessions = self.attach_google_play_services_monitor(
                    device,
                    detached=detached,
                    detach_info=detach_info,
                    stop_on_success=True,
                )
                session, resume_pid, monitor_pid = self.start_instrumented_session(device, spawn, attach_timeout)
            except Exception as exc:
                print(f"[-] Could not attach to {self.package_name}: {exc}")
                self.detach_auxiliary_sessions(auxiliary_sessions)
                auxiliary_sessions = []
                if "timed out" in str(exc).lower() and self.restart_frida_server_after_timeout():
                    try:
                        self.force_stop_app()
                        device = frida.get_usb_device(timeout=10)
                        auxiliary_sessions = self.attach_google_play_services_monitor(
                            device,
                            detached=detached,
                            detach_info=detach_info,
                            stop_on_success=True,
                        )
                        session, resume_pid, monitor_pid = self.start_instrumented_session(device, spawn, attach_timeout)
                        print("[+] Frida attach recovered after frida-server restart.")
                    except Exception as retry_exc:
                        print(f"[-] Retry after frida-server restart failed: {retry_exc}")
                        self.detach_auxiliary_sessions(auxiliary_sessions)
                        self.print_process_diagnostics()
                        return HookRunResult(status="setup_failed", reason=str(retry_exc))
                else:
                    self.print_process_diagnostics()
                    return HookRunResult(status="setup_failed", reason=str(exc))

            def on_detached(reason=None, crash=None, *args):
                if not detach_info.get("reason"):
                    detach_info["reason"] = reason or "detached"
                detach_info["crash"] = crash
                print(f"[!] Frida session detached: reason={reason}, crash={crash}")
                detached.set()

            session.on("detached", on_detached)
            script = session.create_script(self.build_script())
            script.on("message", self.on_message_with_result(detached, detach_info, stop_on_success=True))
            self.call_with_timeout("Frida script load", 8.0, script.load)
            if resume_pid:
                device.resume(resume_pid)
            signal_monitor = self.start_test_signal_monitor(
                monitor_pid,
                detached,
                detach_info,
                stop_on_success=True,
            )
            print(
                f"[+] One-shot monitoring {self.package_name} for up to "
                f"{attempt_timeout:.1f}s with {len(self.hook_method_signatures)} hook signature(s)."
            )

            deadline = time.time() + attempt_timeout
            missing_pid_checks = 0
            map_visual_probe_at: Optional[float] = None
            while time.time() < deadline:
                if detached.wait(timeout=monitor_interval):
                    break
                if detach_info.get("unverified_success_seen") and self.detect_facebook_share_ui_handoff():
                    detach_info["reason"] = "facebook-ui-handoff"
                    detach_info["last_signal"] = "success"
                    detached.set()
                    break
                if (
                    detach_info.get("unverified_success_seen")
                    and self.is_google_maps_location_mode()
                    and detach_info.get("last_signal") != "failure"
                ):
                    now = time.time()
                    if map_visual_probe_at is None:
                        map_visual_probe_at = now + 6.0
                    elif now >= map_visual_probe_at:
                        if self.detect_google_map_visual_loaded():
                            detach_info["reason"] = "map-visual-loaded"
                            detach_info["last_signal"] = "success"
                            detached.set()
                            break
                        map_visual_probe_at = now + 4.0
                if self.find_process_pid() or self.find_frida_process_pid(device):
                    missing_pid_checks = 0
                    continue
                missing_pid_checks += 1
                if missing_pid_checks >= 2:
                    if detach_info.get("unverified_success_seen") and self.detect_facebook_share_ui_handoff():
                        detach_info["reason"] = "facebook-share-ui-handoff"
                        detach_info["last_signal"] = "success"
                        detached.set()
                        break
                    detach_info["reason"] = "process-not-found"
                    print(f"[!] No running pid found for {self.package_name}; treating as crash/exit.")
                    break

            reason = str(detach_info.get("reason") or "")
            last_signal = detach_info.get("last_signal")
            if (
                not reason
                and detach_info.get("unverified_success_seen")
                and self.detect_facebook_share_ui_handoff()
            ):
                reason = "facebook-ui-handoff"
                last_signal = "success"
            if reason == "sdk-call-success" or last_signal == "success":
                status = "success"
            elif reason == "sdk-call-failure" or last_signal == "failure" or reason.startswith("facebook-") or reason.startswith("admob-"):
                status = "failure"
            elif reason in {"process-not-found", "crash", "detached"} or detach_info.get("crash"):
                status = "crash"
            elif time.time() >= deadline:
                reason = "timeout"
                status = "timeout"
            else:
                status = "unknown"
            print(f"[*] One-shot attempt result: status={status}, reason={reason}, last_signal={last_signal}")
            final_status = status
            return HookRunResult(
                status=status,
                reason=reason or None,
                crash=detach_info.get("crash"),
                last_signal=str(last_signal) if last_signal else None,
            )
        finally:
            self.stop_test_signal_monitor(signal_monitor)
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
            self.detach_auxiliary_sessions(auxiliary_sessions)
            if stop_app_after:
                if keep_app_on_success and final_status == "success":
                    print("[*] Successful attempt completed; leaving app running.")
                else:
                    self.force_stop_app()


def build_method_observer_js(signatures: List[str]) -> str:
    payload = json.dumps(signatures, ensure_ascii=False)
    return f"""
var TARGET_METHOD_SIGNATURES = {payload};

function parseSmaliMethodSignature(signature) {{
    var match = String(signature).match(/^L([^;]+);->([^\\(]+)\\(/);
    if (!match) return null;
    var methodName = match[2];
    if (methodName === "<init>") methodName = "$init";
    if (methodName === "<clinit>") return null;
    return {{
        signature: String(signature),
        className: match[1].replace(/\\//g, "."),
        methodName: methodName,
        returnType: String(signature).substring(String(signature).indexOf(")") + 1)
    }};
}}

function maybeReplaceTargetReturn(parsed, value) {{
    if (!replacementEnabled() || value === null || value === undefined) return value;
    if (parsed.returnType !== "Ljava/lang/String;") return value;
    if (isAdMobReplacementMode() &&
        (parsed.signature.indexOf("ads/internal/util/zzm;->zzaz(") >= 0 ||
         parsed.signature.indexOf("ads/internal/util/zzm;->zzd(Landroid/os/Bundle;)") >= 0)) {{
        return maybeReplaceAdMobAppId(value, "target_method_return:" + parsed.signature);
    }}
    var text = String(value);
    var replacement = null;
    var replacementKind = null;
    if (looksLikeApiKey(text)) {{
        replacementKind = "api_key";
        replacement = chooseReplacement(replacementKind, text);
    }} else if (looksLikeDigest(text, 40)) {{
        replacementKind = "cert_sha1";
        replacement = chooseReplacement(replacementKind, text);
        }} else if (looksLikeDigest(text, 64)) {{
            replacementKind = "cert_sha256";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (isAdMobReplacementMode() && looksLikeAdMobAppId(text)) {{
            replacementKind = "admob_app_id";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (isAdMobReplacementMode() && looksLikeAdMobAdUnitId(text)) {{
            replacementKind = "admob_ad_unit_id";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (isFacebookReplacementMode() && looksLikeFacebookAppAccessToken(text)) {{
            replacementKind = "facebook_app_access_token";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (isFacebookReplacementMode() && looksLikeFacebookAppId(text)) {{
            replacementKind = "facebook_app_id";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (isFacebookReplacementMode() && looksLikeFacebookClientToken(text)) {{
            replacementKind = "facebook_client_token";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (looksLikePackageName(text)) {{
            replacementKind = "package";
            replacement = chooseReplacement(replacementKind, text);
    }}
    if (replacement === null || replacement === undefined) return value;
    logEvent("runtime_value_replaced", {{
        source: "target_method_return",
        signature: parsed.signature,
        replacementKind: replacementKind,
        from: maskValue(text),
        to: maskValue(replacement)
    }});
    return replacement;
}}

function stringifyArgs(args) {{
    var values = [];
    for (var i = 0; i < args.length; i++) {{
        try {{
            values.push(maskValue(args[i]));
        }} catch (err) {{
            values.push("<unprintable>");
        }}
    }}
    return values;
}}

function maybeReplaceTargetArguments(parsed, args) {{
    if (!replacementEnabled()) return args;
    var replacedArgs = Array.prototype.slice.call(args);
    for (var i = 0; i < replacedArgs.length; i++) {{
        var value = replacedArgs[i];
        if (value === null || value === undefined) continue;
        if (typeof value !== "string" && !(value instanceof String)) continue;
        var text = String(value);
        var replacement = null;
        var replacementKind = null;
        if (looksLikeApiKey(text)) {{
            replacementKind = "api_key";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (looksLikeDigest(text, 40)) {{
            replacementKind = "cert_sha1";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (looksLikeDigest(text, 64)) {{
            replacementKind = "cert_sha256";
            replacement = chooseReplacement(replacementKind, text);
        }} else if (isAdMobReplacementMode() &&
                   (looksLikeAdMobAdUnitId(text) || parsed.signature.indexOf("setAdUnitId(Ljava/lang/String;)V") >= 0)) {{
            replacementKind = "admob_ad_unit_id";
            replacement = replacementValue("admob_ad_unit_id");
        }} else if (isAdMobReplacementMode() && looksLikeAdMobAppId(text)) {{
            replacementKind = "admob_app_id";
            replacement = replacementValue("admob_app_id");
        }} else if (isFacebookReplacementMode() && looksLikeFacebookAppAccessToken(text)) {{
            replacementKind = "facebook_app_access_token";
            replacement = replacementValue("facebook_app_access_token");
        }} else if (isFacebookReplacementMode() &&
                   (looksLikeFacebookAppId(text) || parsed.signature.indexOf("publishInstallAndWaitForResponse(Landroid/content/Context;Ljava/lang/String;)V") >= 0)) {{
            replacementKind = "facebook_app_id";
            replacement = replacementValue("facebook_app_id");
        }} else if (isFacebookReplacementMode() && looksLikeFacebookClientToken(text)) {{
            replacementKind = "facebook_client_token";
            replacement = replacementValue("facebook_client_token");
        }} else if (looksLikePackageName(text) && parsed.signature.indexOf("zzjc;->zzc(") >= 0) {{
            replacementKind = "package";
            replacement = chooseReplacement(replacementKind, text);
        }}
        if (replacement === null || replacement === undefined) continue;
        logEvent("runtime_value_replaced", {{
            source: "target_method_arg",
            signature: parsed.signature,
            argIndex: i,
            replacementKind: replacementKind,
            from: maskValue(text),
            to: maskValue(replacement)
        }});
        replacedArgs[i] = replacement;
    }}
    return replacedArgs;
}}

function patchTargetPlacesMetadata(parsed, args, result, phase) {{
    if (!replacementEnabled()) return result;
    try {{
        var source = "target_method_" + phase + ":" + parsed.signature;
        if (parsed.signature.indexOf("zzjc;->zzc(Lcom/google/android/libraries/places/internal/zzbmg;)V") >= 0) {{
            if (args && args.length > 0) patchPlacesAuthMetadata(args[0], source);
        }}
        if (parsed.signature.indexOf("zzjc;->zza(Ljava/lang/String;Ljava/lang/String;)Lcom/google/android/libraries/places/internal/zzbmg;") >= 0 ||
            parsed.signature.indexOf("zzjc;->zzb(Ljava/lang/String;Ljava/lang/String;)Lcom/google/android/libraries/places/internal/zzbmg;") >= 0) {{
            patchPlacesAuthMetadata(result, source);
        }}
    }} catch (err) {{
        logEvent("replacement_error", {{ source: "patchTargetPlacesMetadata", signature: parsed.signature, error: String(err) }});
    }}
    return result;
}}

function patchTargetPlacesHeaderMap(parsed, result) {{
    if (!replacementEnabled() || !result) return result;
    if (parsed.signature.indexOf("zznh;->zza()Lcom/google/common/collect/ImmutableMap;") < 0) return result;
    try {{
        var pkg = replacementValue("package");
        var cert = replacementValue("cert_sha1");
        if (!pkg && !cert) return result;
        var ImmutableMap = Java.use("com.google.common.collect.ImmutableMap");
        var builder = ImmutableMap.builder();
        builder.putAll.overload("java.util.Map").call(builder, result);
        if (pkg) {{
            builder.put.overload("java.lang.Object", "java.lang.Object").call(builder, "X-Android-Package", String(pkg));
        }}
        if (cert) {{
            builder.put.overload("java.lang.Object", "java.lang.Object").call(builder, "X-Android-Cert", String(cert).replace(/:/g, "").toUpperCase());
        }}
        var patched = builder.buildKeepingLast();
        logEvent("places_header_map_patched", {{
            signature: parsed.signature,
            from: maskValue(result),
            to: maskValue(patched)
        }});
        return patched;
    }} catch (err) {{
        logEvent("replacement_error", {{ source: "patchTargetPlacesHeaderMap", signature: parsed.signature, error: String(err) }});
        return result;
    }}
}}

Java.perform(function () {{
    TARGET_METHOD_SIGNATURES.forEach(function (signature) {{
        var parsed = parseSmaliMethodSignature(signature);
        if (!parsed) {{
            logEvent("target_hook_parse_error", {{ signature: String(signature) }});
            return;
        }}
        safeHook(parsed.className, parsed.methodName, function (overload) {{
            return function () {{
                logEvent("target_method_enter", {{
                    signature: parsed.signature,
                    className: parsed.className,
                    methodName: parsed.methodName,
                    args: stringifyArgs(arguments)
                }});
                var callArgs = maybeReplaceTargetArguments(parsed, arguments);
                patchTargetPlacesMetadata(parsed, callArgs, null, "before");
                var result = overload.apply(this, callArgs);
                patchTargetPlacesMetadata(parsed, callArgs, result, "after");
                result = patchTargetPlacesHeaderMap(parsed, result);
                logEvent("target_method_return", {{
                    signature: parsed.signature,
                    className: parsed.className,
                    methodName: parsed.methodName,
                    returnValue: maskValue(result)
                }});
                return maybeReplaceTargetReturn(parsed, result);
            }};
        }});
    }});
}});
"""


def build_runtime_replacement_config_js(runtime_replacements: Dict[str, object]) -> str:
    payload = json.dumps(runtime_replacements or {}, ensure_ascii=False)
    return (
        "var __runtimeReplacementRoot = (typeof globalThis !== \"undefined\") ? globalThis : this;\n"
        f"__runtimeReplacementRoot.RUNTIME_REPLACEMENTS = {payload};\n"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python frida_hooker.py <package.name> [apk_path]")
        raise SystemExit(2)
    package = sys.argv[1]
    apk = sys.argv[2] if len(sys.argv) > 2 else None
    FridaHooker(package).run(install_apk_path=apk)
