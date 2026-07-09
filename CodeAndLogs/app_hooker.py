import argparse
import contextlib
import configparser
import json
import re
import shutil
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from apk_analyzer import ApkPair, discover_pairs, format_selected_ids, parse_sdk_ids
from apk_audit_core import APKAnalyzer, ApkStaticReport
from frida_hooker import FridaHooker
from frida_server import FridaServerConfig, start_frida_server


GOOGLE_API_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{20,}")
ADMOB_APP_ID_RE = re.compile(r"ca-app-pub-\d{16}~\d{10}")
ADMOB_AD_UNIT_ID_RE = re.compile(r"ca-app-pub-\d{16}/\d{10}")
FACEBOOK_APP_ID_RE = re.compile(r"\b\d{12,18}\b")
FACEBOOK_CLIENT_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
ONESIGNAL_APP_ID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
GOOGLE_SAMPLE_ADMOB_PUBLISHER = "ca-app-pub-3940256099942544"
GOOGLE_SAMPLE_ADMOB_APP_ID = GOOGLE_SAMPLE_ADMOB_PUBLISHER + "~3347511713"


RUNTIME_REPLACEMENT_HOOKS: List[Dict[str, str]] = [
    {
        "signature": "android.util.Log->i/d/w/e(String,String)",
        "role": "Observe APICREDTEST signals emitted by the attacker app, including SDK call success/failure/crash markers.",
        "replacement": "none",
    },
    {
        "signature": "android.content.ContextWrapper->getPackageName()",
        "role": "Replace the attacker package name with the demo package name in SDK authentication paths.",
        "replacement": "packageName",
    },
    {
        "signature": "android.app.ContextImpl->getPackageName()",
        "role": "Replace the attacker package name with the demo package name in SDK authentication paths.",
        "replacement": "packageName",
    },
    {
        "signature": "android.app.ApplicationPackageManager->getApplicationInfo(...)",
        "role": "Patch ApplicationInfo.packageName for SDK authentication code that reads caller identity.",
        "replacement": "packageName",
    },
    {
        "signature": "android.app.ApplicationPackageManager->getPackageInfo(...)",
        "role": "Patch PackageInfo.packageName for SDK authentication code that reads caller identity.",
        "replacement": "packageName",
    },
    {
        "signature": "android.app.ApplicationPackageManager->getPackagesForUid(int)",
        "role": "Let GMS auxiliary authentication checks see the demo package alongside the attacker package for the caller UID.",
        "replacement": "packageName",
        "modes": ["google_maps_location_broad"],
    },
    {
        "signature": "android.app.ApplicationPackageManager->getNameForUid(int)",
        "role": "Replace attacker package identity with demo package identity in narrowly-scoped GMS auxiliary checks.",
        "replacement": "packageName",
        "modes": ["google_maps_location_broad"],
    },
    {
        "signature": "android.app.AppOpsManager->checkPackage(int,String)",
        "role": "Allow GMS auxiliary UID/package validation when it checks the demo package for the attacker UID.",
        "replacement": "uidPackageCheck",
        "modes": ["google_maps_location_broad"],
    },
    {
        "signature": "com.google.android.gms.common.util.UidVerifier->uidHasPackageName(...)",
        "role": "Allow Google Play services UID/package validation for the demo package during Maps/Location authentication.",
        "replacement": "uidPackageCheck",
        "modes": ["google_maps_location_broad"],
    },
    {
        "signature": "com.google.android.gms.common.wrappers.PackageManagerWrapper->zza(...)",
        "role": "Allow Google Play services wrapper UID/package validation for the demo package during Maps/Location authentication.",
        "replacement": "uidPackageCheck",
        "modes": ["google_maps_location_broad"],
    },
    {
        "signature": "java.security.MessageDigest->getInstance(...)",
        "role": "Observe digest algorithm selection before certificate digest replacement.",
        "replacement": "none",
    },
    {
        "signature": "java.security.MessageDigest->digest(...)",
        "role": "Replace SHA-1/SHA-256 digest bytes when SDK code derives Android certificate fingerprints, including GMS GoogleCertificates stacks for Maps/Location.",
        "replacement": "certSha1/certSha256",
    },
    {
        "signature": "android.os.Bundle->getString(...)",
        "role": "Replace sensitive bundle values if API key, package, or certificate fields pass through Bundle metadata.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "android.os.Bundle->putString(...)",
        "role": "Replace sensitive bundle values if API key, package, or certificate fields are written to Bundle metadata.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "android.content.res.Resources->getString/getText(...)",
        "role": "Replace sensitive resource strings such as google_api_key when app or SDK code reads values generated from google-services resources.",
        "replacement": "primaryApiKey/oneSignalAppId",
    },
    {
        "signature": "android.app.SharedPreferencesImpl->getString/EditorImpl.putString(...)",
        "role": "Replace cached SDK credential values before app code passes them into SDK initialization.",
        "replacement": "oneSignalAppId",
    },
    {
        "signature": "com.google.firebase.FirebaseOptions->getApiKey()",
        "role": "Return the replacement API key when Firebase SDK code reads FirebaseApp options after google-services initialization.",
        "replacement": "primaryApiKey",
    },
    {
        "signature": "android.net.Uri$Builder->appendQueryParameter(String,String)",
        "role": "Replace URL query credential fields, especially key=<apiKey>.",
        "replacement": "primaryApiKey",
    },
    {
        "signature": "java.net.URL->$init(...)",
        "role": "Observe sensitive URL construction before network requests are sent.",
        "replacement": "none",
    },
    {
        "signature": "java.net.URL->openConnection(...)",
        "role": "Patch Android authentication headers immediately after a URLConnection is created.",
        "replacement": "packageName/certSha1",
    },
    {
        "signature": "java.net.URLConnection->connect()",
        "role": "Patch Android authentication headers immediately before URLConnection sends a request.",
        "replacement": "packageName/certSha1",
    },
    {
        "signature": "java.net.URLConnection->getInputStream()",
        "role": "Patch Android authentication headers before lazy URLConnection request execution.",
        "replacement": "packageName/certSha1",
    },
    {
        "signature": "java.net.URLConnection->getOutputStream()",
        "role": "Patch Android authentication headers before lazy URLConnection request execution with a request body.",
        "replacement": "packageName/certSha1",
    },
    {
        "signature": "java.net.HttpURLConnection->connect()",
        "role": "Patch Android authentication headers immediately before HttpURLConnection sends a request.",
        "replacement": "packageName/certSha1",
    },
    {
        "signature": "java.net.HttpURLConnection->setRequestProperty(String,String)",
        "role": "Replace request header values when API key, package, or certificate fields are set explicitly.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "java.net.URLConnection->setRequestProperty(String,String)",
        "role": "Replace request header values when API key, package, or certificate fields are set explicitly.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "java.net.URLConnection->addRequestProperty(String,String)",
        "role": "Replace added request header values when API key, package, or certificate fields are set explicitly.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "okhttp3.Request$Builder->header(String,String)",
        "role": "Replace OkHttp header values when OkHttp is present in the attacker app.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "okhttp3.Request$Builder->addHeader(String,String)",
        "role": "Replace added OkHttp header values when OkHttp is present in the attacker app.",
        "replacement": "packageName/certSha1/certSha256/primaryApiKey",
    },
    {
        "signature": "com.onesignal.internal.*->initWithContext(Context,String) and config setAppId(String)",
        "role": "Replace OneSignal App ID at SDK initialization and model configuration entry points.",
        "replacement": "oneSignalAppId",
    },
    {
        "signature": "org.json.JSONObject->put(String,Object)",
        "role": "Replace OneSignal App ID in REST request bodies before the app sends OneSignal API calls.",
        "replacement": "oneSignalAppId",
    },
]


@dataclass
class AppHookerConfig:
    sdk_ids: Optional[Set[str]]
    apk_dir: Path
    analyze_results_dir: Path
    hook_results_dir: Path
    work_dir: Path
    logs_dir: Path
    install_attacker: bool
    spawn_attacker: bool
    start_frida_server: bool
    frida_server_config: FridaServerConfig
    adaptive_hook_filter: bool
    adaptive_attempt_timeout: float
    adaptive_run_final: bool
    identity_clone_for_gms: bool


def read_hooker_config(config_path: str, discovered_pairs: Dict[str, ApkPair]) -> AppHookerConfig:
    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")
    width = max((len(sdk_id) for sdk_id in discovered_pairs), default=4)

    sdk_ids_text = get_config_value(
        parser,
        "APP_HOOKER",
        "AppHook_SDK_IDS",
        fallback_section="APK_ANALYZER",
        fallback_key="ApkAna_SDK_IDS",
        fallback="all",
    )
    try:
        sdk_ids = parse_sdk_ids(sdk_ids_text, width=width)
    except ValueError as exc:
        raise SystemExit(f"[APP_HOOKER] AppHook_SDK_IDS is invalid: {exc}") from exc

    return AppHookerConfig(
        sdk_ids=sdk_ids,
        apk_dir=Path(
            get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_APK_DIR",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_APK_DIR",
                fallback="apks",
            )
        ),
        analyze_results_dir=Path(
            get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_ANALYZE_RESULTS_DIR",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_ANALYZE_RESULTS_DIR",
                fallback="apk_analyze_rslts",
            )
        ),
        hook_results_dir=Path(
            get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_RESULTS_DIR",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_HOOK_RESULTS_DIR",
                fallback="app_hook_rslts",
            )
        ),
        work_dir=Path(
            get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_DECOMPILE_DIR",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_DECOMPILE_DIR",
                fallback="decompiled_apks",
            )
        ),
        logs_dir=Path(
            get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_LOGS_DIR",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_HOOK_LOGS_DIR",
                fallback="app_hook_logs",
            )
        ),
        install_attacker=get_config_bool(
            parser,
            "APP_HOOKER",
            "AppHook_INSTALL_ATTACKER",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_INSTALL_ATTACKER",
            fallback=False,
        ),
        spawn_attacker=get_config_bool(
            parser,
            "APP_HOOKER",
            "AppHook_SPAWN_ATTACKER",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_FRIDA_SPAWN",
            fallback=True,
        ),
        start_frida_server=get_config_bool(
            parser,
            "APP_HOOKER",
            "AppHook_START_FRIDA_SERVER",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_START_FRIDA_SERVER",
            fallback=True,
        ),
        frida_server_config=FridaServerConfig(
            local_path=get_optional_path(parser, "APP_HOOKER", "AppHook_FRIDA_SERVER_LOCAL_PATH"),
            remote_path=get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_FRIDA_SERVER_REMOTE_PATH",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_FRIDA_SERVER_REMOTE_PATH",
                fallback="/data/local/tmp/frida-server",
            ),
            use_su=get_config_bool(
                parser,
                "APP_HOOKER",
                "AppHook_FRIDA_SERVER_USE_SU",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_FRIDA_SERVER_USE_SU",
                fallback=True,
            ),
            auto_push=get_config_bool(
                parser,
                "APP_HOOKER",
                "AppHook_FRIDA_SERVER_AUTO_PUSH",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_FRIDA_SERVER_AUTO_PUSH",
                fallback=True,
            ),
            wait_seconds=float(
                get_config_value(
                    parser,
                    "APP_HOOKER",
                    "AppHook_FRIDA_SERVER_WAIT_SECONDS",
                    fallback_section="APK_ANALYZER",
                    fallback_key="ApkAna_FRIDA_SERVER_WAIT_SECONDS",
                    fallback="3.0",
                )
            ),
        ),
        adaptive_hook_filter=get_config_bool(
            parser,
            "APP_HOOKER",
            "AppHook_ADAPTIVE_HOOK_FILTER",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_ADAPTIVE_HOOK_FILTER",
            fallback=False,
        ),
        adaptive_attempt_timeout=float(
            get_config_value(
                parser,
                "APP_HOOKER",
                "AppHook_ADAPTIVE_ATTEMPT_TIMEOUT",
                fallback_section="APK_ANALYZER",
                fallback_key="ApkAna_ADAPTIVE_ATTEMPT_TIMEOUT",
                fallback="45.0",
            )
        ),
        adaptive_run_final=get_config_bool(
            parser,
            "APP_HOOKER",
            "AppHook_ADAPTIVE_RUN_FINAL",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_ADAPTIVE_RUN_FINAL",
            fallback=False,
        ),
        identity_clone_for_gms=get_config_bool(
            parser,
            "APP_HOOKER",
            "AppHook_IDENTITY_CLONE_FOR_GMS",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_IDENTITY_CLONE_FOR_GMS",
            fallback=False,
        ),
    )


def get_config_value(
    parser: configparser.ConfigParser,
    section: str,
    key: str,
    fallback_section: str,
    fallback_key: str,
    fallback: str,
) -> str:
    if parser.has_option(section, key):
        return parser.get(section, key)
    if parser.has_option(fallback_section, fallback_key):
        return parser.get(fallback_section, fallback_key)
    return fallback


def get_config_bool(
    parser: configparser.ConfigParser,
    section: str,
    key: str,
    fallback_section: str,
    fallback_key: str,
    fallback: bool,
) -> bool:
    if parser.has_option(section, key):
        return parser.getboolean(section, key)
    if parser.has_option(fallback_section, fallback_key):
        return parser.getboolean(fallback_section, fallback_key)
    return fallback


def get_optional_path(parser: configparser.ConfigParser, section: str, key: str) -> Optional[Path]:
    value = parser.get(section, key, fallback="").strip()
    return Path(value) if value else None


def select_pairs(pairs: Dict[str, ApkPair], sdk_ids: Optional[Set[str]]) -> Iterable[ApkPair]:
    if sdk_ids is None:
        return pairs.values()
    missing = sorted(sdk_ids.difference(pairs.keys()))
    if missing:
        print(f"[!] Config selected SDK ids not present in APK dir: {', '.join(missing)}")
    selected = [pair for sdk_id, pair in pairs.items() if sdk_id in sdk_ids]
    if not selected:
        raise SystemExit("No APKs matched [APP_HOOKER] AppHook_SDK_IDS.")
    return selected


class TeeStream:
    def __init__(self, console_stream, log_stream):
        self.console_stream = console_stream
        self.log_stream = log_stream

    def write(self, text: str) -> int:
        self.console_stream.write(text)
        self.log_stream.write(text)
        return len(text)

    def flush(self) -> None:
        self.console_stream.flush()
        self.log_stream.flush()


@contextlib.contextmanager
def tee_to_log(log_path: Path):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    with log_path.open("w", encoding="utf-8") as log_file:
        sys.stdout = TeeStream(old_stdout, log_file)
        sys.stderr = TeeStream(old_stderr, log_file)
        print(f"[*] Log file: {log_path}")
        print(f"[*] Started at: {datetime.now().isoformat(timespec='seconds')}")
        try:
            yield
        finally:
            print(f"[*] Finished at: {datetime.now().isoformat(timespec='seconds')}")
            sys.stdout.flush()
            sys.stderr.flush()
            sys.stdout = old_stdout
            sys.stderr = old_stderr


def get_runtime_target(apk_path: Path, work_dir: Path) -> ApkStaticReport:
    analyzer = APKAnalyzer(str(apk_path), str(work_dir / apk_path.stem))
    package_name, launch_activity = analyzer.get_badging()
    report = ApkStaticReport(
        apk_path=str(apk_path),
        package_name=package_name,
        launch_activity=launch_activity,
    )
    if not package_name:
        report.tool_warnings.append("Could not detect package name with aapt; instrumentation may fail.")
    return report


def prepare_identity_clone_apk(
    pair: ApkPair,
    cfg: AppHookerConfig,
    original_hook_report: ApkStaticReport,
    runtime_replacements: Dict[str, object],
) -> Optional[Path]:
    if not cfg.identity_clone_for_gms:
        return None
    if runtime_replacements.get("packageReplacementMode") != "google_maps_location_broad":
        return None
    demo_package = str(runtime_replacements.get("packageName") or "").strip()
    original_package = str(original_hook_report.package_name or "").strip()
    if not demo_package or not original_package or demo_package == original_package:
        return None
    if not pair.attacker:
        return None

    keystore = Path("apk_srcs") / "lawgeek.jks"
    if not keystore.is_file():
        print(f"[!] GMS identity clone skipped: demo signing keystore not found: {keystore}")
        return None

    clone_root = (cfg.work_dir / "_identity_clones" / pair.sdk_id).resolve()
    work_root = cfg.work_dir.resolve()
    try:
        clone_root.relative_to(work_root)
    except ValueError:
        print(f"[!] GMS identity clone skipped: unsafe clone directory: {clone_root}")
        return None
    if clone_root.exists():
        shutil.rmtree(clone_root)
    decoded_dir = clone_root / "decoded"
    unsigned_apk = clone_root / f"{pair.sdk_id}-identity-clone-unsigned.apk"
    aligned_apk = clone_root / f"{pair.sdk_id}-identity-clone-aligned.apk"
    signed_apk = cfg.hook_results_dir / f"{pair.sdk_id}_identity_clone_attacker.apk"
    clone_root.mkdir(parents=True, exist_ok=True)
    signed_apk.parent.mkdir(parents=True, exist_ok=True)

    print("[*] GMS identity clone enabled for this SDK.")
    print(f"    original attacker package: {original_package}")
    print(f"    cloned install package:    {demo_package}")
    print("    source APK is unchanged; only a temporary test APK is generated.")

    if not run_tool(["apktool", "d", "-f", str(pair.attacker), "-o", str(decoded_dir)], "apktool decode"):
        return None

    manifest_path = decoded_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        print(f"[!] GMS identity clone skipped: decoded manifest not found: {manifest_path}")
        return None
    ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    root.set("package", demo_package)
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

    if not run_tool(["apktool", "b", str(decoded_dir), "-o", str(unsigned_apk)], "apktool build"):
        return None
    if aligned_apk.exists():
        aligned_apk.unlink()
    if not run_tool(["zipalign", "-f", "-p", "4", str(unsigned_apk), str(aligned_apk)], "zipalign"):
        aligned_apk = unsigned_apk
    if signed_apk.exists():
        signed_apk.unlink()
    if not run_tool(
        [
            "apksigner",
            "sign",
            "--ks",
            str(keystore),
            "--ks-key-alias",
            "key0",
            "--ks-pass",
            "pass:lawgeek",
            "--key-pass",
            "pass:lawgeek",
            "--out",
            str(signed_apk),
            str(aligned_apk),
        ],
        "apksigner sign",
    ):
        return None
    run_tool(["apksigner", "verify", "--print-certs", str(signed_apk)], "apksigner verify", echo=False)
    print(f"[+] GMS identity clone APK ready: {signed_apk}")
    return signed_apk


def run_tool(args: List[str], label: str, echo: bool = True) -> bool:
    if args:
        resolved = resolve_executable(args[0])
        if not resolved:
            print(f"[-] {label} failed: executable not found: {args[0]}")
            return False
        args = [resolved] + args[1:]
    proc = subprocess.run(args, capture_output=True, text=True, errors="replace", check=False)
    output = (proc.stdout + proc.stderr).strip()
    if echo and output:
        print(output)
    if proc.returncode != 0:
        print(f"[-] {label} failed with exit code {proc.returncode}.")
        if not echo and output:
            print(output)
        return False
    return True


def resolve_executable(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    if sys.platform.startswith("win") and not Path(name).suffix:
        for suffix in (".bat", ".cmd", ".exe"):
            found = shutil.which(name + suffix)
            if found:
                return found
    return None


def read_hook_method_signatures(analyze_results_dir: Path, sdk_id: str) -> List[str]:
    path = analyze_results_dir / f"{sdk_id}_apk_analyze_rslt.txt"
    if not path.is_file():
        raise FileNotFoundError(f"Hook method signature file not found: {path}")

    signatures: List[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line not in signatures:
            signatures.append(line)
    return signatures


def write_hook_method_signatures(analyze_results_dir: Path, sdk_id: str, signatures: List[str]) -> Path:
    path = analyze_results_dir / f"{sdk_id}_apk_analyze_rslt.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = analyze_results_dir / f"{sdk_id}_apk_analyze_rslt.before_adaptive.txt"
        if not backup.exists():
            backup.write_text(path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
    if signatures:
        path.write_text("\n".join(signatures) + "\n", encoding="utf-8")
    else:
        path.write_text("# No hook method signatures identified.\n", encoding="utf-8")
    return path


def write_app_hook_result_signatures(
    hook_results_dir: Path,
    sdk_id: str,
    sdk_name: str,
    target_package_name: str,
    signatures: List[str],
    original_signatures: List[str],
    rejected_signatures: List[Dict[str, object]],
    attempts: List[Dict[str, object]],
    runtime_replacements: Dict[str, object],
    script_paths: Dict[str, Path],
    final_status: str,
    final_reason: Optional[str],
) -> Path:
    path = hook_results_dir / f"{sdk_id}_app_hook_rslt.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    selected = set(signatures)
    rejected = {str(item.get("signature")): item for item in rejected_signatures}
    final_attempt = attempts[-1] if attempts else {}
    lines = [
        f"# {sdk_id} {sdk_name} App Hook Result",
        "",
        f"- Generated at: {datetime.now().isoformat(timespec='seconds')}",
        f"- Final status: {final_status}",
        f"- Final reason: {final_reason or 'unknown'}",
        f"- Candidate methods from apk_analyze_rslts: {len(original_signatures)}",
        f"- Final target hook methods used: {len(signatures)}",
        f"- Generic runtime replacement hooks: {len(runtime_replacement_hooks_for(runtime_replacements)) if runtime_replacements.get('enabled') else 0}",
        f"- Rejected methods: {len(rejected_signatures)}",
        "",
        "## Runtime Replacement Values",
        "",
        f"- Package name: {runtime_replacements.get('packageName') or 'unknown'}",
        f"- Cert SHA-1: {runtime_replacements.get('certSha1') or 'unknown'}",
        f"- Cert SHA-256: {runtime_replacements.get('certSha256') or 'unknown'}",
        f"- Primary API key: {runtime_replacements.get('primaryApiKey') or 'unknown'}",
        f"- Additional API keys: {max(len(runtime_replacements.get('apiKeys') or []) - 1, 0)}",
    ]
    if runtime_replacements.get("oneSignalAppId"):
        lines.append(f"- OneSignal app id: {runtime_replacements.get('oneSignalAppId')}")
    if runtime_replacements.get("packageReplacementMode") == "admob_safe":
        lines.extend(
            [
                f"- AdMob app id: {runtime_replacements.get('admobAppId') or 'unknown'}",
                f"- AdMob ad unit id: {runtime_replacements.get('admobAdUnitId') or 'unknown'}",
                f"- Demo manifest APPLICATION_ID: {runtime_replacements.get('admobManifestApplicationId') or 'unknown'}",
            ]
        )
    if runtime_replacements.get("packageReplacementMode") == "facebook_core":
        lines.extend(
            [
                f"- Facebook app id: {runtime_replacements.get('facebookAppId') or 'unknown'}",
                f"- Facebook client token: {runtime_replacements.get('facebookClientToken') or 'unknown'}",
                f"- Facebook app access token: {runtime_replacements.get('facebookAppAccessToken') or 'unknown'}",
                f"- Facebook login protocol scheme: {runtime_replacements.get('facebookLoginProtocolScheme') or 'unknown'}",
                f"- Facebook content-provider authority: {runtime_replacements.get('facebookContentProviderAuthority') or 'unknown'}",
            ]
        )
    if runtime_replacements.get("identityCloneEnabled"):
        lines.extend(
            [
                "- GMS identity clone: enabled",
                f"- Original attacker package: {runtime_replacements.get('identityCloneSourcePackage') or 'unknown'}",
                f"- Temporary identity-clone APK: {runtime_replacements.get('identityCloneApk') or 'unknown'}",
            ]
        )
    else:
        lines.append("- GMS identity clone: disabled")
    lines.extend(
        [
            "",
            "## Generated Hook Scripts",
            "",
            f"- Full script: {script_paths.get('full')}",
            f"- Full script command: `{format_frida_script_command(target_package_name, script_paths.get('full'))}`",
            f"- Fill-in template: {script_paths.get('template')}",
            f"- Fill-in template command: `{format_frida_script_command(target_package_name, script_paths.get('template'))}`",
        ]
    )

    lines.extend(["", "## SDK Validation Summary", ""])
    lines.extend(sdk_validation_summary_lines(sdk_name, runtime_replacements))

    lines.extend(["", "## Candidate Method Decisions", ""])
    if original_signatures:
        for index, signature in enumerate(original_signatures, start=1):
            if any(signatures_match(signature, selected_signature) for selected_signature in selected):
                decision = "selected"
                if final_status == "success":
                    reason = "Included in the final successful hook set."
                else:
                    reason = "Included in the final adaptive hook set."
            elif signature in rejected:
                decision = "rejected"
                rejected_item = rejected[signature]
                reason = str(rejected_item.get("decision") or rejected_item.get("reason") or "Rejected by adaptive filtering.")
            elif final_status == "success":
                decision = "not needed"
                reason = (
                    "Not tested/used because an earlier hook set already reached SDK success; "
                    "continuing would only add crash risk."
                )
            else:
                decision = "not selected"
                reason = "Adaptive filtering did not select this method."
            lines.extend(format_method_decision(index, signature, decision, reason))
    else:
        lines.append("No candidate hook methods were loaded from apk_analyze_rslts.")

    lines.extend(["", "## Adaptive Attempts", ""])
    if attempts:
        for attempt in attempts:
            lines.append(
                f"- {attempt.get('label')}: status={attempt.get('status')}, "
                f"reason={attempt.get('reason')}, subset_size={attempt.get('subset_size')}, "
                f"stop_app_after={attempt.get('stop_app_after')}"
            )
    else:
        lines.append("No adaptive attempts were recorded.")

    if final_attempt:
        lines.extend(
            [
                "",
                "## Final Attempt Subset",
                "",
            ]
        )
        final_subset = final_attempt.get("subset") or []
        lines.append("Target-specific methods loaded by the final adaptive attempt.")
        lines.append("")
        if final_subset:
            for index, signature in enumerate(final_subset, start=1):
                lines.append(f"{index}. `{signature}`")
        else:
            if final_status == "success":
                lines.append("The final successful attempt used no target-specific method hooks.")
            else:
                lines.append("The final attempt used no target-specific method hooks.")

    lines.extend(["", "## Final Method List", ""])
    append_final_method_list(lines, signatures, runtime_replacements, final_status)
    append_sdk_invocation_result(lines, final_status, final_reason, runtime_replacements)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def sdk_protection_measure_summary(runtime_replacements: Dict[str, object]) -> str:
    mode = str(runtime_replacements.get("packageReplacementMode") or "")
    if mode == "facebook_share_kit":
        return (
            "Facebook ShareKit validates Facebook application credentials together with Android caller identity: "
            "ApplicationId/ClientToken/app access token, login protocol scheme/content-provider authority, package name, "
            "and signing-certificate SHA-1 used by FacebookSdk."
        )
    if mode == "facebook_core":
        return (
            "Facebook Core validates Facebook application credentials and Android app identity before accepting Graph/app-events calls: "
            "ApplicationId, ClientToken, app access token, package/extinfo, and signing-certificate SHA-1."
        )
    if mode == "admob_safe":
        return (
            "AdMob validates publisher configuration, mainly the manifest application id and ad-unit id bound to a known publisher setup."
        )
    if mode == "onesignal_core":
        return (
            "OneSignal validates the app id used during SDK initialization and reuses it in notification/user API payloads."
        )
    if mode == "google_maps_location_broad":
        return (
            "Google Maps/Location validates API key restrictions together with Android package/certificate identity and GMS UID/package checks."
        )
    if mode == "places_auth_stack":
        return (
            "Google Places validates API key restrictions together with Android package name, signing certificate, and request auth fields."
        )
    return (
        "The SDK appears to validate credential material together with Android application identity such as package name and certificate digest."
    )


def append_sdk_invocation_result(
    lines: List[str],
    final_status: str,
    final_reason: Optional[str],
    runtime_replacements: Dict[str, object],
) -> None:
    succeeded = final_status == "success"
    lines.extend(["", "## SDK Invocation Result", ""])
    lines.append(
        "- Instrumented/replaced SDK call result: "
        + ("success" if succeeded else "not verified as success")
        + f" (final_status={final_status}, reason={final_reason or 'unknown'})."
    )
    lines.append(f"- SDK protection measures: {sdk_protection_measure_summary(runtime_replacements)}")


def signatures_match(candidate: str, selected: str) -> bool:
    if candidate == selected:
        return True
    if "..." not in candidate:
        return False
    prefix, suffix = candidate.split("...", 1)
    return selected.startswith(prefix) and selected.endswith(suffix)


def append_final_method_list(
    lines: List[str],
    signatures: List[str],
    runtime_replacements: Dict[str, object],
    final_status: str,
) -> None:
    if final_status == "success":
        lines.append("These are the hooks loaded by the final successful script.")
    else:
        lines.append("These are the hooks loaded by the final script; the final run did not reach verified SDK success.")
    lines.append("")

    runtime_hooks = runtime_replacement_hooks_for(runtime_replacements) if runtime_replacements.get("enabled") else []
    enabling_hooks = [hook for hook in runtime_hooks if str(hook.get("replacement") or "none") != "none"]
    observer_hooks = [hook for hook in runtime_hooks if str(hook.get("replacement") or "none") == "none"]

    if observer_hooks:
        lines.append("### Observer Hooks")
        lines.append("")
        for index, hook in enumerate(observer_hooks, start=1):
            lines.append(f"{index}. `{hook['signature']}`")
            lines.append(f"   - Purpose: {hook['role']}")
        lines.append("")
        lines.append(
            "Summary: observer hooks do not change SDK inputs. They only record app signals, SDK responses, crashes, "
            "and verified success/failure evidence."
        )
        lines.append("")
    else:
        lines.append("### Observer Hooks")
        lines.append("")
        lines.append("No observer hooks were listed for this runtime mode.")
        lines.append("")
        lines.append("Summary: the final script has no separate observation-only hook entries for this SDK mode.")
        lines.append("")

    if enabling_hooks:
        lines.append("### Runtime Replacement Hooks")
        lines.append("")
        for index, hook in enumerate(enabling_hooks, start=1):
            lines.append(f"{index}. `{hook['signature']}`")
            lines.append(f"   - Replaces: {hook['replacement']}")
            lines.append(f"   - Purpose: {hook['role']}")
        lines.append("")
        lines.append(
            "Summary: runtime replacement hooks are the value-substitution layer. They replace attacker-side credentials, "
            "package identity, certificate digests, or request fields with demo-side values so the SDK request can pass validation."
        )
        lines.append("")
    elif runtime_replacements.get("enabled"):
        lines.append("### Runtime Replacement Hooks")
        lines.append("")
        lines.append("No runtime replacement hooks with value substitution were configured.")
        lines.append("")
        lines.append("Summary: runtime replacement was enabled, but this SDK mode did not define value-substitution hook entries.")
        lines.append("")
    else:
        lines.append("### Runtime Replacement Hooks")
        lines.append("")
        lines.append("Runtime replacement was disabled because demo package/certificate/API key values were unavailable.")
        lines.append("")
        lines.append("Summary: no attacker-to-demo credential or identity replacement could be configured for this run.")
        lines.append("")


def sdk_validation_summary_lines(sdk_name: str, runtime_replacements: Dict[str, object]) -> List[str]:
    mode = str(runtime_replacements.get("packageReplacementMode") or "")
    sdk_name_text = str(sdk_name or "")
    if mode == "facebook_share_kit":
        return [
            "- Validation type: Facebook app credential plus Android app identity binding for the ShareKit dialog flow.",
            "- Evidence: a successful ShareKit SDK invocation is recognized when the SDK completes `ShareDialog.show(...)`, enters `FacebookDialogBase.show(...)`, dispatches `DialogPresenter.present(...)`, or starts the Facebook platform/browser handoff intent.",
            "- Checked values inferred from source/runtime hooks: Facebook ApplicationId, ClientToken, app access token (`app_id|client_token`), login protocol scheme, content-provider authority, Android package name in app-events/extinfo, and Android signing certificate SHA-1 used by FacebookSdk application-signature code.",
            "- Required bypass strategy: replace attacker Facebook metadata/token values with demo values, replace package identity embedded in SDK payloads, and replace the signature digest only on the Facebook SDK signature-calculation stack while observing the ShareKit dialog handoff as success.",
        ]
    if mode == "facebook_core":
        return [
            "- Validation type: Facebook app credential plus Android app identity binding.",
            "- Evidence: the target request used to verify SDK/API success is Facebook Graph `/{app_id}/activities`; local ShareDialog acceptance is not treated as SDK/API success.",
            "- Checked values inferred from source/runtime hooks: Facebook ApplicationId, ClientToken, app access token (`app_id|client_token`), Android package name in app-events/extinfo, and Android signing certificate SHA-1 used by FacebookSdk application-signature code.",
            "- Required bypass strategy: replace attacker Facebook metadata/token values with demo values, replace the package name embedded in the app-events JSON payload, and replace the signature digest only on the Facebook SDK signature-calculation stack.",
        ]
    if mode == "admob_safe":
        return [
            "- Validation type: AdMob publisher/app configuration lookup.",
            "- Evidence: failures such as `Publisher data not found` come from Google Mobile Ads when the app id or ad unit id does not match a known publisher configuration.",
            "- Checked values inferred from source/runtime hooks: `com.google.android.gms.ads.APPLICATION_ID`, ad unit id, and MobileAds/ad-view initialization values.",
            "- Required bypass strategy: keep package/certificate hooks narrow and replace only AdMob app-id/ad-unit-id values with demo-side values.",
        ]
    if mode == "onesignal_core":
        return [
            "- Validation type: OneSignal App ID initialization and notification/user API payload binding.",
            "- Evidence: the attacker app reads `onesignal_app_id` or cached `OS_APP_ID_SHARED_PREF` before `OneSignal.initWithContext`, then reuses the value in REST JSON `app_id` fields.",
            "- Checked values inferred from source/runtime hooks: resource `onesignal_app_id`, SharedPreferences App ID cache, `initWithContext(Context,String)`, config `setAppId(String)`, and JSON `app_id` request bodies.",
            "- Required bypass strategy: replace the attacker-side OneSignal App ID with the paired demo-side App ID at every read/init/payload boundary.",
        ]
    if mode == "google_maps_location_broad":
        return [
            "- Validation type: Google API key restriction plus Android caller identity verification.",
            "- Evidence: Maps/Location auth paths use package name, signing certificate digest, and GMS UID/package checks before returning service tokens or usable SDK results.",
            "- Checked values inferred from source/runtime hooks: API key, Android package name, SHA-1/SHA-256 certificate fingerprints, PackageManager UID mappings, AppOps package checks, and GMS UidVerifier/PackageManagerWrapper checks.",
            "- Required bypass strategy: replace package/key/certificate values and allow the demo package to pass auxiliary GMS UID/package validation for the attacker UID.",
        ]
    if mode == "places_auth_stack":
        return [
            "- Validation type: Google Places API key restriction and Android app identity verification.",
            "- Evidence: Places calls are accepted only when the request carries an authorized key together with the expected Android package/certificate identity.",
            "- Checked values inferred from source/runtime hooks: API key, package name, certificate SHA-1/SHA-256, Bundle/URL query parameters, and Android auth headers.",
            "- Required bypass strategy: replace attacker key/package/certificate material with demo-side values across Bundle, URL, header, and digest paths.",
        ]
    if "facebook" in sdk_name_text.lower():
        return sdk_validation_summary_lines("Facebook", {**runtime_replacements, "packageReplacementMode": "facebook_core"})
    return [
        "- Validation type: generic SDK credential and Android app identity verification.",
        "- Checked values inferred from source/runtime hooks: API key or SDK token, Android package name, signing certificate SHA-1/SHA-256, Bundle metadata, URL query parameters, and request/auth headers.",
        "- Required bypass strategy: replace attacker-side credential and identity material with the paired demo-side values before the SDK constructs its authenticated request.",
    ]


def append_runtime_replacement_hook_lines(
    lines: List[str],
    runtime_replacements: Dict[str, object],
    start_index: int = 1,
) -> None:
    if not runtime_replacements.get("enabled"):
        lines.append("Runtime replacement was disabled because demo package/certificate/API key values were unavailable.")
        return
    lines.append(
        "These hooks are injected in the final attempt in addition to any target-specific "
        "LLM/analyzer hooks. A hook may be loaded but not hit if the app does not use that API path."
    )
    lines.append("")
    for index, hook in enumerate(runtime_replacement_hooks_for(runtime_replacements), start=start_index):
        lines.append(f"{index}. `{hook['signature']}`")
        lines.append(f"   - Role: {hook['role']}")
        lines.append(f"   - Replacement value(s): {hook['replacement']}")
        lines.append("")


def runtime_replacement_hooks_for(runtime_replacements: Dict[str, object]) -> List[Dict[str, str]]:
    mode = str(runtime_replacements.get("packageReplacementMode") or "")
    if mode == "admob_safe":
        return [
            {
                "signature": "android.util.Log->i/d/w/e(String,String)",
                "role": "Observe APICREDTEST signals emitted by the attacker app.",
                "replacement": "none",
            },
            {
                "signature": "android.os.BaseBundle->getString/putString(...)",
                "role": "Patch only com.google.android.gms.ads.APPLICATION_ID values read from metadata bundles.",
                "replacement": "admobAppId",
            },
            {
                "signature": "com.google.android.gms.ads.internal.util.zzm->zzaz/zzd(...)",
                "role": "Return the demo-side AdMob application id when the SDK validates manifest metadata.",
                "replacement": "admobAppId",
            },
            {
                "signature": "com.google.android.gms.ads.*->setAdUnitId(String)",
                "role": "Use the demo-side AdMob ad-unit id at SDK public/internal ad-view entry points.",
                "replacement": "admobAdUnitId",
            },
            {
                "signature": "com.google.android.gms.ads.MobileAds->initialize(...)",
                "role": "Fill only missing or invalid String app-id initialization overloads; listener/settings overloads are left untouched.",
                "replacement": "admobAppId",
            },
        ]
    if mode == "facebook_core":
        return [
            {
                "signature": "android.util.Log->i/d/w/e(String,String)",
                "role": "Observe APICREDTEST signals without accepting ShareDialog handoff as verified API success.",
                "replacement": "none",
            },
            {
                "signature": "android.os.BaseBundle/android.os.Bundle->getString/putString(...)",
                "role": "Replace Facebook ApplicationId, ClientToken, access_token, protocol scheme, and content-provider authority metadata.",
                "replacement": "facebookAppId/facebookClientToken/facebookAppAccessToken/facebookLoginProtocolScheme/facebookContentProviderAuthority",
            },
            {
                "signature": "com.facebook.FacebookSdk->getApplicationId/getClientToken/setApplicationId/setClientToken/publishInstallAndWaitForResponse(...)",
                "role": "Return or pass the demo-side Facebook app id and client token after SDK metadata initialization.",
                "replacement": "facebookAppId/facebookClientToken",
            },
            {
                "signature": "org.json.JSONObject->put(String,Object)",
                "role": "Replace app-events package/extinfo fields and Facebook credential fields before GraphRequest sends the payload.",
                "replacement": "packageName/facebookAppId/facebookClientToken/facebookAppAccessToken",
            },
            {
                "signature": "java.security.MessageDigest->digest(...)",
                "role": "Replace SHA-1 digest only while Facebook SDK computes the application signature.",
                "replacement": "certSha1",
            },
            {
                "signature": "android.net.Uri$Builder->appendQueryParameter(String,String)",
                "role": "Replace Facebook access_token query parameters built as app_id|client_token.",
                "replacement": "facebookAppAccessToken",
            },
            {
                "signature": "com.facebook.GraphRequest->executeAndWait()",
                "role": "Observe the real Facebook Graph response and count only the app-events Graph success as verified SDK success.",
                "replacement": "none",
            },
        ]
    if mode == "facebook_share_kit":
        return [
            {
                "signature": "android.util.Log->i/d/w/e(String,String)",
                "role": "Observe APICREDTEST signals emitted by the attacker app.",
                "replacement": "none",
            },
            {
                "signature": "com.facebook.share.widget.ShareDialog->show(...)",
                "role": "Observe the public ShareKit dialog API call and treat a completed SDK dialog invocation as ShareKit success.",
                "replacement": "none",
            },
            {
                "signature": "com.facebook.internal.FacebookDialogBase->show(...)",
                "role": "Observe ShareKit's internal dialog base class when it dispatches the share content.",
                "replacement": "none",
            },
            {
                "signature": "com.facebook.internal.DialogPresenter->present(...)",
                "role": "Observe the SDK handoff from ShareKit into Facebook platform/web dialog presentation.",
                "replacement": "none",
            },
            {
                "signature": "com.facebook.internal.DialogPresenter->startActivityForResultWithAndroidX(...)",
                "role": "Observe AndroidX-based Facebook dialog handoff launched by ShareKit.",
                "replacement": "none",
            },
            {
                "signature": "android.app.Activity->startActivityForResult(...)",
                "role": "Observe Facebook platform or browser intents started by the SDK dialog flow.",
                "replacement": "none",
            },
            {
                "signature": "android.os.BaseBundle/android.os.Bundle->getString/putString(...)",
                "role": "Replace Facebook ApplicationId, ClientToken, access_token, protocol scheme, and content-provider authority metadata.",
                "replacement": "facebookAppId/facebookClientToken/facebookAppAccessToken/facebookLoginProtocolScheme/facebookContentProviderAuthority",
            },
            {
                "signature": "com.facebook.FacebookSdk->getApplicationId/getClientToken/setApplicationId/setClientToken/publishInstallAndWaitForResponse(...)",
                "role": "Return or pass the demo-side Facebook app id and client token after SDK metadata initialization.",
                "replacement": "facebookAppId/facebookClientToken",
            },
            {
                "signature": "org.json.JSONObject->put(String,Object)",
                "role": "Replace app-events package/extinfo fields and Facebook credential fields before ShareKit/FacebookSdk builds telemetry or Graph payloads.",
                "replacement": "packageName/facebookAppId/facebookClientToken/facebookAppAccessToken",
            },
            {
                "signature": "java.security.MessageDigest->digest(...)",
                "role": "Replace SHA-1 digest only while Facebook SDK computes the application signature.",
                "replacement": "certSha1",
            },
            {
                "signature": "android.net.Uri$Builder->appendQueryParameter(String,String)",
                "role": "Replace Facebook access_token query parameters built as app_id|client_token.",
                "replacement": "facebookAppAccessToken",
            },
        ]
    hooks: List[Dict[str, str]] = []
    for hook in RUNTIME_REPLACEMENT_HOOKS:
        modes = hook.get("modes")
        if modes and mode not in modes:
            continue
        if mode == "admob_safe":
            signature = hook.get("signature", "")
            if signature.startswith("android.os.Parcel"):
                continue
        hooks.append(hook)
    return hooks


def format_method_decision(index: int, signature: str, decision: str, reason: str) -> List[str]:
    class_name, method_name, descriptor = parse_smali_signature_parts(signature)
    return [
        f"{index}. `{signature}`",
        f"   - Decision: {decision}",
        f"   - Class: `{class_name}`",
        f"   - Method: `{method_name}`",
        f"   - Descriptor: `{descriptor}`",
        f"   - Reason: {reason}",
        "",
    ]


def parse_smali_signature_parts(signature: str) -> tuple[str, str, str]:
    match = re.match(r"^L([^;]+);->([^\(]+)(\(.*)$", signature)
    if not match:
        return "unknown", "unknown", signature
    return match.group(1).replace("/", "."), match.group(2), match.group(3)


def format_frida_script_command(package_name: str, script_path: Optional[Path]) -> str:
    script = str(script_path or "__FILL_SCRIPT_PATH__")
    package = package_name or "__FILL_ATTACKER_PACKAGE_NAME__"
    return (
        f"adb shell am force-stop {package}; "
        f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1; "
        f'frida -U -n {package} -l "{script}"'
    )


def make_fill_in_runtime_replacements(runtime_replacements: Dict[str, object]) -> Dict[str, object]:
    template = dict(runtime_replacements or {})
    template["enabled"] = True
    template["sourceApk"] = "__FILL_DEMO_APK_PATH_OPTIONAL__"
    template["packageName"] = "__FILL_DEMO_PACKAGE_NAME__"
    template["certSha1"] = "__FILL_DEMO_CERT_SHA1__"
    template["certSha256"] = "__FILL_DEMO_CERT_SHA256__"
    template["primaryApiKey"] = "__FILL_DEMO_API_KEY__"
    template["apiKeys"] = ["__FILL_DEMO_API_KEY__"]
    if template.get("packageReplacementMode") == "admob_safe":
        template["admobAppId"] = "__FILL_ADMOB_APP_ID__"
        template["admobAdUnitId"] = "__FILL_ADMOB_AD_UNIT_ID__"
        template["admobManifestApplicationId"] = "__FILL_ADMOB_MANIFEST_APPLICATION_ID_OPTIONAL__"
    if template.get("packageReplacementMode") == "facebook_core":
        template["facebookAppId"] = "__FILL_FACEBOOK_APP_ID__"
        template["facebookClientToken"] = "__FILL_FACEBOOK_CLIENT_TOKEN__"
        template["facebookAppAccessToken"] = "__FILL_FACEBOOK_APP_ACCESS_TOKEN__"
        template["facebookLoginProtocolScheme"] = "__FILL_FACEBOOK_LOGIN_PROTOCOL_SCHEME__"
        template["facebookContentProviderAuthority"] = "__FILL_FACEBOOK_CONTENT_PROVIDER_AUTHORITY__"
    if template.get("packageReplacementMode") == "onesignal_core":
        template["oneSignalAppId"] = "__FILL_ONESIGNAL_APP_ID__"
    return template


def write_app_hook_scripts(
    hook_results_dir: Path,
    sdk_id: str,
    hook_report: ApkStaticReport,
    signatures: List[str],
    runtime_replacements: Dict[str, object],
) -> Dict[str, Path]:
    hook_results_dir.mkdir(parents=True, exist_ok=True)
    full_path = hook_results_dir / f"{sdk_id}_app_hook_full.js"
    template_path = hook_results_dir / f"{sdk_id}_app_hook_template.js"

    full_script = FridaHooker(
        hook_report.package_name,
        hook_report.launch_activity,
        hook_method_signatures=signatures,
        runtime_replacements=runtime_replacements,
    ).build_script()
    template_script = FridaHooker(
        hook_report.package_name,
        hook_report.launch_activity,
        hook_method_signatures=signatures,
        runtime_replacements=make_fill_in_runtime_replacements(runtime_replacements),
    ).build_script()

    full_header = (
        "// Full app hook script generated by app_hooker.py.\n"
        "// Runtime replacement values are filled from the paired demo APK.\n"
        f"// Run command: {format_frida_script_command(hook_report.package_name, full_path)}\n"
    )
    template_header = (
        "// Fill-in app hook script generated by app_hooker.py.\n"
        "// Replace __FILL_*__ placeholders at the top of this file before testing.\n"
        f"// Run command after filling placeholders: {format_frida_script_command(hook_report.package_name, template_path)}\n"
    )
    full_path.write_text(full_header + full_script, encoding="utf-8")
    template_path.write_text(template_header + template_script, encoding="utf-8")
    return {"full": full_path, "template": template_path}


def build_runtime_replacements(
    pair: ApkPair,
    cfg: AppHookerConfig,
    attacker_package_name: str,
) -> Dict[str, object]:
    if not pair.demo:
        print("[!] No paired demo APK found; runtime replacement is disabled.")
        return {"enabled": False}

    demo_output_dir = cfg.work_dir / pair.demo.stem
    analyzer = APKAnalyzer(str(pair.demo), str(demo_output_dir))
    demo_package, _ = analyzer.get_badging()
    if not demo_package:
        demo_package = analyzer.get_manifest_package_name()
    cert_sha1, cert_sha256 = analyzer.get_certificate_digests()
    api_keys = collect_demo_api_keys(pair.demo, demo_output_dir)
    attacker_validation_api_keys = collect_attacker_validation_api_keys(pair, cfg)
    if attacker_validation_api_keys:
        merged_keys: "OrderedDict[str, str]" = OrderedDict()
        for key in attacker_validation_api_keys:
            merged_keys.setdefault(key, "attacker-validation")
        for key in api_keys:
            merged_keys.setdefault(key, "demo")
        api_keys = list(merged_keys.keys())
    admob_values = collect_demo_admob_values(demo_output_dir)
    facebook_values = collect_demo_facebook_values(demo_output_dir)
    onesignal_values = collect_demo_onesignal_values(demo_output_dir)

    package_replacement_mode = package_replacement_mode_for_pair(pair)
    if package_replacement_mode == "facebook_core":
        api_keys = []
    replacements: Dict[str, object] = {
        "enabled": bool(
            demo_package
            or cert_sha1
            or cert_sha256
            or api_keys
            or admob_values
            or facebook_values
            or onesignal_values
        ),
        "sdkId": pair.sdk_id,
        "sdkName": pair.sdk_name,
        "packageReplacementMode": package_replacement_mode,
        "sourceApk": str(pair.demo),
        "runtimePackageName": attacker_package_name,
        "packageName": demo_package,
        "certSha1": normalize_digest(cert_sha1),
        "certSha256": normalize_digest(cert_sha256),
        "primaryApiKey": api_keys[0] if api_keys else None,
        "apiKeys": api_keys,
        "admobAppId": admob_values.get("app_id"),
        "admobAdUnitId": admob_values.get("ad_unit_id"),
        "admobManifestApplicationId": admob_values.get("manifest_application_id"),
        "facebookAppId": facebook_values.get("app_id"),
        "facebookClientToken": facebook_values.get("client_token"),
        "facebookAppAccessToken": facebook_values.get("app_access_token"),
        "facebookLoginProtocolScheme": facebook_values.get("login_protocol_scheme"),
        "facebookContentProviderAuthority": facebook_values.get("content_provider_authority"),
        "oneSignalAppId": onesignal_values.get("app_id"),
        "replaceMapsDynamiteParcelPackageName": False,
        "replaceGoogleCertificatesQueryPackageName": package_replacement_mode == "google_maps_location_broad",
    }

    if replacements["enabled"]:
        print("[+] Runtime replacement values loaded from demo APK:")
        print(f"    package: {demo_package or 'unknown'}")
        print(f"    cert SHA-1: {normalize_digest(cert_sha1) or 'unknown'}")
        print(f"    cert SHA-256: {normalize_digest(cert_sha256) or 'unknown'}")
        if api_keys:
            print(f"    primary API key: {api_keys[0]}")
            if len(api_keys) > 1:
                print(f"    additional API keys: {len(api_keys) - 1}")
            if attacker_validation_api_keys:
                print("    API key source override: attacker validation constant")
        else:
            print("    primary API key: unknown")
        if admob_values:
            print(f"    AdMob app id: {admob_values.get('app_id') or 'unknown'}")
            print(f"    AdMob ad unit id: {admob_values.get('ad_unit_id') or 'unknown'}")
        if facebook_values:
            print(f"    Facebook app id: {facebook_values.get('app_id') or 'unknown'}")
            print(f"    Facebook client token: {facebook_values.get('client_token') or 'unknown'}")
        if onesignal_values:
            print(f"    OneSignal app id: {onesignal_values.get('app_id') or 'unknown'}")
    else:
        print("[!] No demo package/certificate/API key values were found; runtime replacement is disabled.")
    return replacements


def is_admob_like_sdk_name(sdk_name: str) -> bool:
    lowered = (sdk_name or "").lower()
    normalized = re.sub(r"[^a-z0-9]+", "", lowered)
    return (
        "admob" in lowered
        or "mobile ads" in lowered
        or "user messaging platform" in lowered
        or "mobileads" in normalized
        or "googlemobileads" in normalized
        or "googleusermessagingplatform" in normalized
        or "usermessagingplatform" in normalized
    )


def package_replacement_mode_for_pair(pair: ApkPair) -> str:
    sdk_name = (pair.sdk_name or "").lower()
    if is_admob_like_sdk_name(sdk_name):
        return "admob_safe"
    if "facebook" in sdk_name and ("share" in sdk_name or "sharekit" in sdk_name or "share kit" in sdk_name):
        return "facebook_share_kit"
    if "facebook" in sdk_name:
        return "facebook_core"
    if "onesignal" in sdk_name:
        return "onesignal_core"
    if "location" in sdk_name or "map" in sdk_name:
        return "google_maps_location_broad"
    if "places" in sdk_name:
        return "places_auth_stack"
    return "google_sdk_stack"


def normalize_digest(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    return cleaned.upper() if cleaned else None


def collect_demo_api_keys(demo_apk: Path, decompiled_dir: Path) -> List[str]:
    found: "OrderedDict[str, str]" = OrderedDict()

    def add(value: Optional[str], source: str) -> None:
        if not value:
            return
        candidate = value.strip().strip("\"'")
        if candidate.startswith("@string/"):
            candidate = resolve_string_resource(decompiled_dir, candidate.split("/", 1)[1]) or candidate
        if not is_runtime_api_key(candidate):
            return
        found.setdefault(candidate, source)

    collect_manifest_api_keys(decompiled_dir, add)
    collect_build_config_api_keys(decompiled_dir, add)
    collect_decompiled_google_api_keys(decompiled_dir, add)

    analyzer = APKAnalyzer(str(demo_apk), str(decompiled_dir))
    for finding in analyzer.scan_apk_strings():
        add(finding.value, f"apk:{finding.source}")

    return list(found.keys())


def collect_attacker_validation_api_keys(pair: ApkPair, cfg: AppHookerConfig) -> List[str]:
    sdk_name = (pair.sdk_name or "").lower()
    if "firebase" not in sdk_name or "performance" not in sdk_name:
        return []
    if not pair.attacker:
        return []
    output_dir = cfg.work_dir / pair.attacker.stem
    analyzer = APKAnalyzer(str(pair.attacker), str(output_dir))
    keys: "OrderedDict[str, str]" = OrderedDict()
    for finding in analyzer.scan_apk_strings():
        if finding.kind != "google_api_key":
            continue
        if finding.source != "classes.dex":
            continue
        if not is_runtime_api_key(finding.value):
            continue
        keys.setdefault(finding.value, finding.source)
    return list(keys.keys())


def collect_demo_admob_values(decompiled_dir: Path) -> Dict[str, Optional[str]]:
    values: Dict[str, Optional[str]] = {}
    manifest_value = collect_manifest_admob_application_id(decompiled_dir)
    app_ids: "OrderedDict[str, str]" = OrderedDict()
    ad_units: "OrderedDict[str, str]" = OrderedDict()

    def scan_text(text: str, source: str) -> None:
        for match in ADMOB_APP_ID_RE.finditer(text):
            app_ids.setdefault(match.group(0), source)
        for match in ADMOB_AD_UNIT_ID_RE.finditer(text):
            ad_units.setdefault(match.group(0), source)

    if manifest_value:
        values["manifest_application_id"] = manifest_value
        scan_text(manifest_value, "manifest:com.google.android.gms.ads.APPLICATION_ID")

    if decompiled_dir.is_dir():
        for path in decompiled_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".xml", ".smali", ".json", ".properties"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scan_text(text, str(path.relative_to(decompiled_dir)))

    ad_unit_id = next(iter(ad_units.keys()), None)
    app_id = next(iter(app_ids.keys()), None)
    if not app_id and ad_unit_id:
        app_id = derive_admob_app_id_from_ad_unit(ad_unit_id)
    if app_id:
        values["app_id"] = app_id
    if ad_unit_id:
        values["ad_unit_id"] = ad_unit_id
    return values


def collect_demo_facebook_values(decompiled_dir: Path) -> Dict[str, Optional[str]]:
    values: Dict[str, Optional[str]] = {}
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    if manifest_path.is_file():
        try:
            root = ET.parse(manifest_path).getroot()
        except ET.ParseError:
            root = None
        if root is not None:
            for elem in root.iter():
                tag = str(elem.tag)
                if tag.endswith("meta-data"):
                    name = elem.attrib.get(ANDROID_NS + "name") or elem.attrib.get("android:name") or ""
                    value = elem.attrib.get(ANDROID_NS + "value") or elem.attrib.get("android:value") or ""
                    resolved = resolve_android_resource_value(decompiled_dir, value)
                    if name == "com.facebook.sdk.ApplicationId" and resolved:
                        values["app_id"] = normalize_facebook_app_id(resolved)
                    elif name == "com.facebook.sdk.ClientToken" and resolved:
                        values["client_token"] = normalize_facebook_client_token(resolved)
                elif tag.endswith("provider"):
                    name = elem.attrib.get(ANDROID_NS + "name") or elem.attrib.get("android:name") or ""
                    authority = elem.attrib.get(ANDROID_NS + "authorities") or elem.attrib.get("android:authorities") or ""
                    resolved_authority = resolve_android_resource_value(decompiled_dir, authority)
                    if name == "com.facebook.FacebookContentProvider" and resolved_authority:
                        values["content_provider_authority"] = resolved_authority.strip()
    for key, res_name in (
        ("app_id", "app_id"),
        ("client_token", "facebook_client_token"),
        ("login_protocol_scheme", "fb_login_protocol_scheme"),
        ("content_provider_authority", "fb_authority"),
    ):
        if values.get(key):
            continue
        resolved = resolve_string_resource(decompiled_dir, res_name)
        if not resolved:
            continue
        if key == "app_id":
            values[key] = normalize_facebook_app_id(resolved)
        elif key == "client_token":
            values[key] = normalize_facebook_client_token(resolved)
        else:
            values[key] = resolved.strip()

    app_id = values.get("app_id")
    client_token = values.get("client_token")
    if app_id and client_token:
        values["app_access_token"] = f"{app_id}|{client_token}"
    if app_id and not values.get("login_protocol_scheme"):
        values["login_protocol_scheme"] = f"fb{app_id}"
    if app_id and not values.get("content_provider_authority"):
        values["content_provider_authority"] = f"com.facebook.app.FacebookContentProvider{app_id}"
    return {key: value for key, value in values.items() if value}


def collect_demo_onesignal_values(decompiled_dir: Path) -> Dict[str, Optional[str]]:
    values: Dict[str, Optional[str]] = {}
    app_id = normalize_onesignal_app_id(resolve_string_resource(decompiled_dir, "onesignal_app_id") or "")
    if app_id:
        values["app_id"] = app_id
        return values

    if decompiled_dir.is_dir():
        for path in decompiled_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".xml", ".smali", ".json", ".properties"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lowered = text.lower()
            if "onesignal" not in lowered and "os_app_id" not in lowered:
                continue
            match = ONESIGNAL_APP_ID_RE.search(text)
            if match:
                values["app_id"] = match.group(0).lower()
                break
    return values


def normalize_onesignal_app_id(value: str) -> Optional[str]:
    match = ONESIGNAL_APP_ID_RE.search(value or "")
    return match.group(0).lower() if match else None


def normalize_facebook_app_id(value: str) -> Optional[str]:
    text = (value or "").strip()
    if text.startswith("fb") and FACEBOOK_APP_ID_RE.search(text[2:]):
        text = text[2:]
    match = FACEBOOK_APP_ID_RE.search(text)
    return match.group(0) if match else None


def normalize_facebook_client_token(value: str) -> Optional[str]:
    match = FACEBOOK_CLIENT_TOKEN_RE.search(value or "")
    return match.group(0).lower() if match else None


def resolve_android_resource_value(decompiled_dir: Path, value: str) -> Optional[str]:
    text = (value or "").strip()
    if not text:
        return None
    if text.startswith("@string/"):
        return resolve_string_resource(decompiled_dir, text.split("/", 1)[1]) or text
    return text


def collect_manifest_admob_application_id(decompiled_dir: Path) -> Optional[str]:
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        return None
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError:
        return None
    for elem in root.iter():
        if not str(elem.tag).endswith("meta-data"):
            continue
        name = elem.attrib.get(ANDROID_NS + "name") or elem.attrib.get("android:name") or ""
        value = elem.attrib.get(ANDROID_NS + "value") or elem.attrib.get("android:value") or ""
        if name == "com.google.android.gms.ads.APPLICATION_ID":
            if value.startswith("@string/"):
                return resolve_string_resource(decompiled_dir, value.split("/", 1)[1]) or value
            return value.strip() or None
    return None


def derive_admob_app_id_from_ad_unit(ad_unit_id: str) -> Optional[str]:
    if not ad_unit_id:
        return None
    if ad_unit_id.startswith(GOOGLE_SAMPLE_ADMOB_PUBLISHER + "/"):
        return GOOGLE_SAMPLE_ADMOB_APP_ID
    match = re.match(r"^(ca-app-pub-\d{16})/(\d{10})$", ad_unit_id)
    if not match:
        return None
    return f"{match.group(1)}~{match.group(2)}"


def collect_manifest_api_keys(decompiled_dir: Path, add) -> None:
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        return
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError:
        return
    for elem in root.iter():
        if not str(elem.tag).endswith("meta-data"):
            continue
        name = elem.attrib.get(ANDROID_NS + "name") or elem.attrib.get("android:name") or ""
        value = elem.attrib.get(ANDROID_NS + "value") or elem.attrib.get("android:value") or ""
        if is_api_key_name(name):
            add(value, "manifest:meta-data")


def collect_build_config_api_keys(decompiled_dir: Path, add) -> None:
    if not decompiled_dir.is_dir():
        return
    field_re = re.compile(r'\.field\b.*\b(API[_A-Z0-9]*KEY|[A-Z0-9_]*API_KEY)\b.*=\s*"([^"]+)"')
    for path in decompiled_dir.rglob("BuildConfig.smali"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(decompiled_dir)
        for match in field_re.finditer(text):
            add(match.group(2), f"decompiled:{rel}")


def collect_decompiled_google_api_keys(decompiled_dir: Path, add) -> None:
    if not decompiled_dir.is_dir():
        return
    for path in decompiled_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".xml", ".smali", ".json", ".properties"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(decompiled_dir)
        for match in GOOGLE_API_KEY_RE.finditer(text):
            add(match.group(0), f"decompiled:{rel}")


def resolve_string_resource(decompiled_dir: Path, name: str) -> Optional[str]:
    values_dir = decompiled_dir / "res" / "values"
    if not values_dir.is_dir():
        return None
    for path in values_dir.glob("*.xml"):
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            continue
        for elem in root.iter("string"):
            if elem.attrib.get("name") == name and elem.text:
                return elem.text.strip()
    return None


def is_api_key_name(name: str) -> bool:
    lowered = (name or "").lower()
    return "api_key" in lowered or "apikey" in lowered or "api-key" in lowered or "maps" in lowered or "places" in lowered


def is_runtime_api_key(value: str) -> bool:
    if not value or value.startswith("@"):
        return False
    if value.upper() in {"YOUR_API_KEY", "API_KEY", "NO_API_KEY"}:
        return False
    return bool(GOOGLE_API_KEY_RE.fullmatch(value)) or (len(value) >= 16 and re.search(r"[A-Za-z]", value) and re.search(r"\d", value))


def run_app_hooker() -> None:
    parser = argparse.ArgumentParser(
        description="Install/spawn attacker APKs and passively instrument methods listed by apk_analyzer.py."
    )
    parser.add_argument("--config", default="config.ini", help="Path to config.ini.")
    args = parser.parse_args()

    config_parser = configparser.ConfigParser()
    config_parser.read(args.config, encoding="utf-8")
    apk_dir = Path(
        get_config_value(
            config_parser,
            "APP_HOOKER",
            "AppHook_APK_DIR",
            fallback_section="APK_ANALYZER",
            fallback_key="ApkAna_APK_DIR",
            fallback="apks",
        )
    )
    pairs = discover_pairs(apk_dir)
    if not pairs:
        raise SystemExit(f"No named APKs found in {apk_dir}. Expected files like 0018-NameSDK-attacker.apk")

    cfg = read_hooker_config(args.config, pairs)
    print(
        "[*] App hooker config: "
        f"ids={format_selected_ids(cfg.sdk_ids)}, apk_dir={cfg.apk_dir}, "
        f"results_dir={cfg.analyze_results_dir}, hook_results_dir={cfg.hook_results_dir}, "
        f"logs_dir={cfg.logs_dir}, install_attacker={cfg.install_attacker}, "
        f"spawn_attacker={cfg.spawn_attacker}, start_frida_server={cfg.start_frida_server}, "
        f"adaptive_hook_filter={cfg.adaptive_hook_filter}"
    )

    for pair in select_pairs(pairs, cfg.sdk_ids):
        log_path = cfg.logs_dir / f"{pair.sdk_id}-app_hook.log"
        with tee_to_log(log_path):
            try:
                run_one_sdk_pair(pair, cfg)
            except Exception:
                print("[-] App hook failed with an unhandled exception:")
                print(traceback.format_exc())
                raise


def run_adaptive_hook_filter(
    pair: ApkPair,
    cfg: AppHookerConfig,
    hook_report: ApkStaticReport,
    runtime_replacements: Dict[str, object],
    signatures: List[str],
    install_apk_path: Path,
) -> List[str]:
    print("[*] Adaptive hook filtering enabled.")
    print(
        "[*] Strategy: baseline without target hooks, then add candidates one by one; "
        "a candidate that turns a success into failure/crash, or crashes by itself, is excluded."
    )
    attempts = []
    safe_signatures: List[str] = []
    rejected_signatures: List[Dict[str, object]] = []
    install_next = cfg.install_attacker
    success_result = None

    def attempt(label: str, subset: List[str], stop_app_after: bool = True):
        nonlocal install_next
        print(f"\n=== Adaptive attempt: {label} ===")
        print(f"[*] Hook subset size: {len(subset)}")
        for signature in subset:
            print(f"    {signature}")
        result = FridaHooker(
            hook_report.package_name,
            hook_report.launch_activity,
            hook_method_signatures=subset,
            runtime_replacements=runtime_replacements,
        ).run_attempt(
            install_apk_path=str(install_apk_path) if install_next else None,
            spawn=cfg.spawn_attacker,
            attach_timeout=12.0,
            attempt_timeout=cfg.adaptive_attempt_timeout,
            stop_app_after=stop_app_after,
            keep_app_on_success=True,
        )
        install_next = False
        attempts.append(
            {
                "label": label,
                "subset_size": len(subset),
                "subset": subset,
                "status": result.status,
                "reason": result.reason,
                "last_signal": result.last_signal,
                "stop_app_after": stop_app_after,
            }
        )
        return result

    baseline = attempt("baseline-passive-only", [], stop_app_after=True)
    known_success = baseline.status == "success"
    last_good_status = baseline.status

    if baseline.status == "success":
        success_result = baseline
        print("[+] Baseline run already reached SDK success; no target hook signatures are needed.")
    else:
        for index, signature in enumerate(signatures, start=1):
            candidate_subset = safe_signatures + [signature]
            result = attempt(f"add-{index}", candidate_subset, stop_app_after=True)
            reject_reason = None
            if result.status == "crash":
                reject_reason = "candidate caused app crash or process exit"
            elif result.status == "setup_failed":
                reject_reason = "candidate could not be tested because setup failed"
            elif known_success and result.status != "success":
                reject_reason = (
                    "candidate changed a previously successful SDK call into "
                    f"{result.status}"
                )

            if reject_reason:
                print(f"[!] Rejecting hook candidate: {signature}")
                print(f"    reason: {reject_reason}")
                rejected_signatures.append(
                    {
                        "signature": signature,
                        "status": result.status,
                        "reason": result.reason,
                        "decision": reject_reason,
                    }
                )
                continue

            safe_signatures.append(signature)
            if result.status == "success":
                known_success = True
                success_result = result
                print("[+] SDK call succeeded with the current hook set; stopping adaptive search.")
                break
            last_good_status = result.status

    final_result = success_result or attempt(
        "final-safe-set",
        safe_signatures,
        stop_app_after=True,
    )
    if final_result.status == "success":
        print("[+] Adaptive filtering found a successful hook set.")
    else:
        print(
            "[!] Adaptive filtering did not reach SDK success with the final hook set; "
            f"status={final_result.status}, reason={final_result.reason}."
        )
        if not rejected_signatures:
            print("[!] No hook candidates were rejected; writing the setup/failure result for observability.")

    trace = {
        "sdk_id": pair.sdk_id,
        "sdk_name": pair.sdk_name,
        "attempt_timeout_seconds": cfg.adaptive_attempt_timeout,
        "original_count": len(signatures),
        "safe_count": len(safe_signatures),
        "rejected_count": len(rejected_signatures),
        "safe_signatures": safe_signatures,
        "rejected_signatures": rejected_signatures,
        "attempts": attempts,
        "final_status": final_result.status,
        "final_reason": final_result.reason,
    }
    trace_path = cfg.logs_dir / f"{pair.sdk_id}_adaptive_hook_filter.json"
    trace_path.write_text(json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8")
    script_paths = write_app_hook_scripts(
        cfg.hook_results_dir,
        pair.sdk_id,
        hook_report,
        safe_signatures,
        runtime_replacements,
    )
    app_hook_result_path = write_app_hook_result_signatures(
        cfg.hook_results_dir,
        pair.sdk_id,
        pair.sdk_name,
        hook_report.package_name,
        safe_signatures,
        signatures,
        rejected_signatures,
        attempts,
        runtime_replacements,
        script_paths,
        final_result.status,
        final_result.reason,
    )
    print(f"[+] Adaptive hook trace written: {trace_path}")
    print(f"[+] App hook result written: {app_hook_result_path}")
    print(f"[+] Full hook script written: {script_paths['full']}")
    print(f"[+] Fill-in hook script written: {script_paths['template']}")
    print(f"[+] Safe signatures: {len(safe_signatures)}; rejected signatures: {len(rejected_signatures)}")
    return safe_signatures


def run_one_sdk_pair(pair: ApkPair, cfg: AppHookerConfig) -> None:
    print(f"\n=== Instrumenting {pair.sdk_id} {pair.sdk_name} ===")
    print(
        "[*] Pair config: "
        f"results_dir={cfg.analyze_results_dir}, hook_results_dir={cfg.hook_results_dir}, "
        f"logs_dir={cfg.logs_dir}, "
        f"install_attacker={cfg.install_attacker}, spawn_attacker={cfg.spawn_attacker}, "
        f"start_frida_server={cfg.start_frida_server}"
    )
    if not pair.attacker:
        print(f"[-] Skipping {pair.sdk_id}: missing attacker APK.")
        return

    print(f"[*] Attacker APK: {pair.attacker}")
    signatures = read_hook_method_signatures(cfg.analyze_results_dir, pair.sdk_id)
    print(f"[+] Loaded {len(signatures)} hook method signature(s).")
    for signature in signatures:
        print(f"    {signature}")

    hook_report = get_runtime_target(pair.attacker, cfg.work_dir)
    if not hook_report.package_name:
        print("[-] Cannot instrument: package name was not detected.")
        return
    runtime_replacements = build_runtime_replacements(pair, cfg, hook_report.package_name)
    install_apk_path = pair.attacker
    identity_clone_apk = prepare_identity_clone_apk(pair, cfg, hook_report, runtime_replacements)
    if identity_clone_apk:
        install_apk_path = identity_clone_apk
        hook_report = get_runtime_target(identity_clone_apk, cfg.work_dir)
        if not hook_report.package_name:
            print("[-] Cannot instrument identity clone: package name was not detected.")
            return
        runtime_replacements = build_runtime_replacements(pair, cfg, hook_report.package_name)
        runtime_replacements["identityCloneEnabled"] = True
        runtime_replacements["identityCloneSourcePackage"] = get_runtime_target(pair.attacker, cfg.work_dir).package_name
        runtime_replacements["identityCloneApk"] = str(identity_clone_apk)

    if cfg.spawn_attacker:
        print("[*] Spawning attacker app with Frida and loading script.")
    else:
        print("[*] Frida spawn disabled; launching/attaching with fallback mode.")
    if cfg.start_frida_server and not start_frida_server(cfg.frida_server_config):
        print("[-] Cannot continue because frida-server is not running.")
        return

    if cfg.adaptive_hook_filter:
        safe_signatures = run_adaptive_hook_filter(
            pair,
            cfg,
            hook_report,
            runtime_replacements,
            signatures,
            install_apk_path,
        )
        if not cfg.adaptive_run_final:
            print("[*] Adaptive final run disabled; run app_hooker.py again to use the persisted safe hook list.")
            return
        print("[*] Starting final Frida session with adaptive safe hook list.")
        signatures = safe_signatures

    FridaHooker(
        hook_report.package_name,
        hook_report.launch_activity,
        hook_method_signatures=signatures,
        runtime_replacements=runtime_replacements,
    ).run(
        install_apk_path=str(install_apk_path) if cfg.install_attacker else None,
        spawn=cfg.spawn_attacker,
        attach_timeout=12.0,
    )


if __name__ == "__main__":
    run_app_hooker()
