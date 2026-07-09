import argparse
import contextlib
import configparser
import json
import re
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from apk_audit_core import APKAnalyzer, ApkStaticReport, mask_secret, read_api_config
from frida_hooker import PASSIVE_MONITOR_JS


APK_NAME_RE = re.compile(r"^(?P<sdk_id>\d+)-(?P<sdk_name>.+)-(?P<role>demo|attacker)\.apk$", re.I)
ADMOB_APP_ID_RE = re.compile(r"ca-app-pub-\d{16}~\d{10}")
ADMOB_AD_UNIT_ID_RE = re.compile(r"ca-app-pub-\d{16}/\d{10}")


@dataclass
class ApkPair:
    sdk_id: str
    sdk_name: str
    demo: Optional[Path] = None
    attacker: Optional[Path] = None


@dataclass
class ApkAnalyzerConfig:
    sdk_ids: Optional[Set[str]]
    apk_dir: Path
    out_dir: Path
    work_dir: Path
    analyze_results_dir: Path
    logs_dir: Path
    decompile_apk: bool
    use_llm: bool


@dataclass
class HookSelectionResult:
    signatures: List[str]
    trace_lines: List[str]


def discover_pairs(apk_dir: Path) -> Dict[str, ApkPair]:
    pairs: Dict[str, ApkPair] = {}
    for apk in apk_dir.glob("*.apk"):
        match = APK_NAME_RE.match(apk.name)
        if not match:
            continue
        sdk_id = match.group("sdk_id")
        sdk_name = match.group("sdk_name")
        role = match.group("role").lower()
        pair = pairs.setdefault(sdk_id, ApkPair(sdk_id=sdk_id, sdk_name=sdk_name))
        setattr(pair, role, apk)
    return dict(sorted(pairs.items()))


def parse_sdk_ids(value: str, width: int = 4) -> Optional[Set[str]]:
    raw = (value or "").strip()
    if not raw or raw.lower() in {"all", "*"}:
        return None

    selected: Set[str] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = [item.strip() for item in token.split("-", 1)]
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"Invalid SDK id range: {token}")
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Invalid SDK id range with start > end: {token}")
            item_width = max(width, len(start_text), len(end_text))
            for sdk_id in range(start, end + 1):
                selected.add(str(sdk_id).zfill(item_width))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid SDK id: {token}")
            selected.add(token.zfill(max(width, len(token))))
    return selected


def read_analyzer_config(config_path: str, discovered_pairs: Dict[str, ApkPair]) -> ApkAnalyzerConfig:
    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")
    section = "APK_ANALYZER"
    width = max((len(sdk_id) for sdk_id in discovered_pairs), default=4)

    sdk_ids_text = get_config_value(parser, section, "ApkAna_SDK_IDS", "APK_ANALYZER_SDK_IDS", "all")
    try:
        sdk_ids = parse_sdk_ids(sdk_ids_text, width=width)
    except ValueError as exc:
        raise SystemExit(f"[APK_ANALYZER] ApkAna_SDK_IDS is invalid: {exc}") from exc

    return ApkAnalyzerConfig(
        sdk_ids=sdk_ids,
        apk_dir=Path(get_config_value(parser, section, "ApkAna_APK_DIR", "APK_ANALYZER_APK_DIR", "apks")),
        out_dir=Path(get_config_value(parser, section, "ApkAna_RESULTS_DIR", "APK_ANALYZER_RESULTS_DIR", "apk_analyze_reports")),
        work_dir=Path(get_config_value(parser, section, "ApkAna_DECOMPILE_DIR", "APK_ANALYZER_DECOMPILE_DIR", "decompiled_apks")),
        analyze_results_dir=Path(get_config_value(parser, section, "ApkAna_ANALYZE_RESULTS_DIR", "APK_ANALYZER_ANALYZE_RESULTS_DIR", "apk_analyze_rslts")),
        logs_dir=Path(get_config_value(parser, section, "ApkAna_LOGS_DIR", "APK_ANALYZER_LOGS_DIR", "apk_analyze_logs")),
        decompile_apk=get_config_bool(parser, section, "ApkAna_DECOMPILE", "APK_ANALYZER_DECOMPILE", True),
        use_llm=get_config_bool(parser, section, "ApkAna_USE_LLM", "APK_ANALYZER_USE_LLM", False),
    )


def get_config_value(
    parser: configparser.ConfigParser,
    section: str,
    key: str,
    legacy_key: str,
    fallback: str,
) -> str:
    if parser.has_option(section, key):
        return parser.get(section, key)
    return parser.get(section, legacy_key, fallback=fallback)


def get_config_bool(
    parser: configparser.ConfigParser,
    section: str,
    key: str,
    legacy_key: str,
    fallback: bool,
) -> bool:
    if parser.has_option(section, key):
        return parser.getboolean(section, key)
    return parser.getboolean(section, legacy_key, fallback=fallback)


def analyze_apk(
    apk_path: Path,
    work_dir: Path,
    api_key: Optional[str],
    base_url: Optional[str],
    model_name: Optional[str],
    use_llm: bool,
    show_secrets: bool,
    decompile_apk: bool,
) -> ApkStaticReport:
    analyzer = APKAnalyzer(
        str(apk_path),
        str(work_dir / apk_path.stem),
        api_key=api_key,
        base_url=base_url,
        model_name=model_name,
        show_secrets=show_secrets,
    )
    return analyzer.run(use_llm=use_llm, decompile_apk=decompile_apk)


def write_reports(
    out_dir: Path,
    pair: ApkPair,
    demo_report: ApkStaticReport,
    show_secrets: bool,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "sdk_id": pair.sdk_id,
        "sdk_name": pair.sdk_name,
        "demo": demo_report.to_dict(show_secrets=show_secrets),
        "paired_attacker_apk": str(pair.attacker) if pair.attacker else None,
        "note": (
            "This report is for defensive SDK credential exposure and authorization-signal auditing. "
            "It intentionally omits bypass/spoofing instructions."
        ),
    }
    json_path = out_dir / f"{pair.sdk_id}_{pair.sdk_name}_audit.json"
    md_path = out_dir / f"{pair.sdk_id}_{pair.sdk_name}_audit.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(format_markdown(pair, demo_report, show_secrets), encoding="utf-8")
    (out_dir / "frida_passive_monitor.js").write_text(PASSIVE_MONITOR_JS, encoding="utf-8")
    print(f"[+] Wrote {json_path}")
    print(f"[+] Wrote {md_path}")
    print(f"[+] Wrote {out_dir / 'frida_passive_monitor.js'}")


def write_apk_analyze_results(
    analyze_results_dir: Path,
    pair: ApkPair,
    demo_report: ApkStaticReport,
) -> None:
    analyze_results_dir.mkdir(parents=True, exist_ok=True)
    rslt_path = analyze_results_dir / f"{pair.sdk_id}_apk_analyze_rslt.txt"
    full_path = analyze_results_dir / f"{pair.sdk_id}_apk_analyze_full.txt"

    hook_selection = select_hook_method_signatures(demo_report)
    signatures = hook_selection.signatures
    if signatures:
        rslt_path.write_text("\n".join(signatures) + "\n", encoding="utf-8")
    else:
        rslt_path.write_text("# No hook method signatures identified.\n", encoding="utf-8")

    full_lines = [
        f"SDK_ID: {pair.sdk_id}",
        f"SDK_NAME: {pair.sdk_name}",
        f"DEMO_APK: {demo_report.apk_path}",
        f"DEMO_PACKAGE: {demo_report.package_name or 'unknown'}",
        "",
        "HOOK_METHOD_SIGNATURES:",
    ]
    if signatures:
        full_lines.extend(f"- {signature}" for signature in signatures)
    else:
        full_lines.append("- No hook method signatures identified.")

    full_lines.extend([
        "",
        "FRIDA_OBSERVATION_POINTS:",
    ])
    if demo_report.llm_observation_points:
        full_lines.extend(f"- {point}" for point in demo_report.llm_observation_points)
    else:
        full_lines.append("- No structured observation points were extracted from the LLM response.")

    full_lines.extend(["", "HOOK_SELECTION_TRACE:"])
    full_lines.extend(f"- {line}" for line in hook_selection.trace_lines)

    full_lines.extend(["", "STATIC_PROTECTION_EVIDENCE:"])
    if demo_report.protection_hits:
        for kind, entries in demo_report.protection_hits.items():
            full_lines.append(f"\n[{kind}]")
            full_lines.extend(f"- {entry}" for entry in entries[:80])
    else:
        full_lines.append("- No static protection evidence recorded.")

    full_lines.extend(["", "FULL_LLM_AUDIT:", ""])
    full_lines.append(demo_report.llm_audit_text or "LLM analysis was not run or produced no text.")
    full_path.write_text("\n".join(full_lines).rstrip() + "\n", encoding="utf-8")
    print(f"[+] Wrote hook method signatures to {rslt_path}")
    print(f"[+] Wrote full APK analysis result to {full_path}")


AUTH_HEADER_TOKENS = [
    "X-Goog-Api-Key",
    "X-Android-Package",
    "X-Android-Cert",
]

NETWORK_SEND_TOKENS = [
    "HttpURLConnection",
    "URLConnection",
    "setRequestProperty",
    "OkHttpClientTransport",
    "io.grpc.okhttp",
]

HIGH_RISK_PATH_TOKENS = [
    "com/google/android/datatransport",
    "GoogleApiAvailability",
    "GoogleSignatureVerifier",
    "GooglePlayServicesUtil",
    "DynamiteModule",
    "PackageManagerWrapper",
]


def select_hook_method_signatures(report: ApkStaticReport) -> HookSelectionResult:
    trace_lines: List[str] = []
    trace_lines.append(f"LLM observation points: {len(report.llm_observation_points)}")
    signatures = extract_hook_method_signatures(
        report.llm_observation_points,
        report.decompiled_dir,
        trace_lines=trace_lines,
    )
    if signatures:
        trace_lines.append("Static fallback enabled: no")
        return HookSelectionResult(signatures=signatures, trace_lines=trace_lines)

    if report.llm_observation_points:
        trace_lines.append("LLM produced observation points, but filtering/resolution selected no signatures.")
    else:
        trace_lines.append("LLM observation points unavailable; using static auth+network fallback.")
    print("[!] LLM observation points unavailable or empty after filtering; using static auth+network fallback.")

    fallback_signatures = generate_static_fallback_hook_signatures(report, trace_lines)
    trace_lines.append(f"Static fallback selected signatures: {len(fallback_signatures)}")
    print(f"[+] Selected fallback hook signatures: {len(fallback_signatures)}")
    return HookSelectionResult(signatures=fallback_signatures, trace_lines=trace_lines)


def extract_hook_method_signatures(
    points: List[str],
    decompiled_dir: Optional[str] = None,
    trace_lines: Optional[List[str]] = None,
) -> List[str]:
    signatures: List[str] = []
    smali_method = re.compile(r"L[\w/$]+;->[\w$<>]+\(.*?\)\S*")
    java_method = re.compile(r"(?:[A-Za-z_$][\w$]*\.){2,}[A-Za-z_$<][\w$<>]*(?:\([^)]*\))?")
    skipped_observe_only = 0
    skipped_high_risk = 0
    skipped_invalid_action = 0
    legacy_points = 0
    sorted_points = sorted(
        enumerate(points),
        key=lambda item: (-observation_confidence_score(item[1]), item[0]),
    )
    if trace_lines is not None and points:
        trace_lines.append("LLM candidate ordering: confidence descending; original order used as tie-breaker.")

    for _original_index, point in sorted_points:
        fields = [field.strip() for field in point.split("|")]
        should_include, filter_reason = should_include_hook_observation(fields)
        if filter_reason == "legacy":
            legacy_points += 1
        elif filter_reason == "observe_only":
            skipped_observe_only += 1
            continue
        elif filter_reason == "high_risk":
            skipped_high_risk += 1
            continue
        elif filter_reason == "invalid_action":
            skipped_invalid_action += 1
            continue
        elif not should_include:
            continue

        first_field = fields[0] if fields else ""
        match = smali_method.search(first_field) or java_method.search(first_field)
        if match and ("(" in match.group(0) or "->" in match.group(0)):
            add_hook_signature_if_safe(signatures, match.group(0), decompiled_dir, trace_lines)
            continue

        resolved = resolve_class_observation_to_methods(fields, decompiled_dir)
        for signature in resolved:
            add_hook_signature_if_safe(signatures, signature, decompiled_dir, trace_lines)
    if legacy_points:
        print(
            f"[!] {legacy_points} legacy observation point(s) had no hook_action/crash_risk fields; "
            "processed with the old hook-selection logic."
        )
    if skipped_observe_only or skipped_high_risk or skipped_invalid_action:
        print(
            "[+] Filtered LLM observation point(s): "
            f"observe_only={skipped_observe_only}, high_risk={skipped_high_risk}, "
            f"invalid_action={skipped_invalid_action}"
        )
    if trace_lines is not None:
        trace_lines.append(
            "LLM filter counts: "
            f"legacy={legacy_points}, observe_only={skipped_observe_only}, "
            f"high_risk={skipped_high_risk}, invalid_action={skipped_invalid_action}"
        )
        trace_lines.append(f"LLM selected signatures: {len(signatures)}")
    return signatures


def should_include_hook_observation(fields: List[str]) -> Tuple[bool, str]:
    if len(fields) < 5:
        return True, "legacy"

    replace_safety = normalize_observation_token(fields[4])
    crash_risk = observation_crash_risk(fields)
    if replace_safety == "observe_only":
        return False, "observe_only"
    if replace_safety != "replace_safe":
        return False, "invalid_action"
    if crash_risk == "high":
        return False, "high_risk"
    return True, "replace_safe"


def observation_confidence_score(point: str) -> float:
    fields = [field.strip() for field in point.split("|")]
    if len(fields) < 4:
        return -1.0
    return confidence_score(fields[3])


def confidence_score(value: str) -> float:
    normalized = normalize_observation_token(value)
    if not normalized:
        return 0.0
    if normalized in {"very_high", "certain"}:
        return 4.0
    if normalized in {"high", "strong"}:
        return 3.0
    if normalized in {"medium", "moderate", "med"}:
        return 2.0
    if normalized in {"low", "weak"}:
        return 1.0
    if "very_high" in normalized:
        return 4.0
    if "high" in normalized or "strong" in normalized:
        return 3.0
    if "medium" in normalized or "moderate" in normalized:
        return 2.0
    if "low" in normalized or "weak" in normalized:
        return 1.0
    match = re.search(r"\d+(?:\.\d+)?", value or "")
    if not match:
        return 0.0
    number = float(match.group(0))
    if number <= 1.0:
        return number * 3.0
    if number <= 100.0:
        return number / 100.0 * 3.0
    return 0.0


def observation_crash_risk(fields: List[str]) -> str:
    # New paper-aligned format:
    # SmaliMethodName | EvidenceType | SourceLocation | Confidence | ReplaceSafety | AuthChain
    # Legacy format:
    # ClassOrSmaliMethod | signal_type | evidence_file | confidence | hook_action | crash_risk | auth_chain
    if len(fields) >= 7:
        return normalize_observation_token(fields[5])
    return ""


def normalize_observation_token(value: str) -> str:
    normalized = (value or "").strip().lower().replace("-", "_")
    normalized = re.sub(r"\s+", "_", normalized)
    return re.sub(r"[^a-z0-9_]+", "", normalized)


def add_signature(signatures: List[str], signature: str) -> None:
    if signature and signature not in signatures and not signature.lower().startswith("no "):
        signatures.append(signature)


def add_hook_signature_if_safe(
    signatures: List[str],
    signature: str,
    decompiled_dir: Optional[str],
    trace_lines: Optional[List[str]] = None,
) -> None:
    is_safe, reason = is_safe_hook_signature(signature, decompiled_dir)
    if not is_safe:
        if trace_lines is not None:
            trace_lines.append(f"rejected unsafe hook signature: {signature} ({reason})")
        return
    add_signature(signatures, signature)


def is_safe_hook_signature(signature: str, decompiled_dir: Optional[str]) -> Tuple[bool, str]:
    if any(token in signature for token in HIGH_RISK_PATH_TOKENS):
        return False, "high-risk framework/GMS path"

    if "com/google/android/libraries/places/internal/" not in signature:
        return True, "non-Places signature accepted by LLM filter"

    body = find_smali_method_body(signature, decompiled_dir)
    if body is None:
        return True, "method body unavailable"
    if any(token in body for token in AUTH_HEADER_TOKENS):
        return True, "method directly constructs auth headers"
    if "Authorization" in body:
        return True, "method directly constructs Authorization header"
    return False, "Places internal method does not directly construct auth headers"


def find_smali_method_body(signature: str, decompiled_dir: Optional[str]) -> Optional[str]:
    if not decompiled_dir:
        return None
    match = re.match(r"^(L[\w/$]+;)->(.+)$", signature)
    if not match:
        return None
    class_descriptor = match.group(1)
    method_sig = match.group(2)
    class_path = class_descriptor.strip("L;") + ".smali"
    direct = Path(decompiled_dir) / class_path
    candidates = [direct] if direct.is_file() else list(Path(decompiled_dir).glob("**/" + Path(class_path).name))
    for candidate in candidates:
        parsed = parse_smali_methods(candidate)
        if not parsed:
            continue
        declared_class, methods = parsed
        if declared_class != class_descriptor:
            continue
        for candidate_method_sig, body in methods:
            if candidate_method_sig == method_sig:
                return body
    return None


def generate_static_fallback_hook_signatures(
    report: ApkStaticReport,
    trace_lines: List[str],
) -> List[str]:
    signatures: List[str] = []
    if not report.decompiled_dir:
        trace_lines.append("Static fallback skipped: no decompiled APK directory.")
        return signatures

    decompiled_dir = Path(report.decompiled_dir)
    admob_signatures = generate_admob_safe_hook_signatures(report, decompiled_dir, trace_lines)
    if admob_signatures:
        trace_lines.append(f"Static AdMob fallback selected signatures: {len(admob_signatures)}")
        return admob_signatures

    header_entries = report.protection_hits.get("google_android_headers", [])
    network_entries = report.protection_hits.get("network_send", [])
    trace_lines.append(
        f"Static fallback evidence: google_android_headers={len(header_entries)}, network_send={len(network_entries)}"
    )

    for entry in header_entries:
        evidence_file = extract_evidence_smali_path(entry)
        if not evidence_file or not is_low_risk_places_internal_evidence(evidence_file):
            continue
        smali_path = resolve_evidence_path(decompiled_dir, evidence_file)
        if not smali_path:
            continue
        for signature, reason in extract_static_auth_header_methods(smali_path):
            before = len(signatures)
            add_signature(signatures, signature)
            if len(signatures) != before:
                trace_lines.append(f"fallback auth-header: {signature} ({reason}; {evidence_file})")

    network_selected = 0
    for entry in network_entries:
        evidence_file = extract_evidence_smali_path(entry)
        if not evidence_file or not is_low_risk_places_internal_evidence(evidence_file):
            continue
        smali_path = resolve_evidence_path(decompiled_dir, evidence_file)
        if not smali_path:
            continue
        for signature, reason in extract_static_auth_adjacent_network_methods(smali_path):
            before = len(signatures)
            add_signature(signatures, signature)
            if len(signatures) != before:
                network_selected += 1
                trace_lines.append(f"fallback auth-adjacent-network: {signature} ({reason}; {evidence_file})")
            if network_selected >= 3:
                break
        if network_selected >= 3:
            break
    if network_entries and network_selected == 0:
        trace_lines.append("fallback auth-adjacent-network: no low-risk auth-adjacent network methods found.")

    return signatures


def generate_admob_safe_hook_signatures(
    report: ApkStaticReport,
    decompiled_dir: Path,
    trace_lines: List[str],
) -> List[str]:
    if not is_admob_report(report, decompiled_dir):
        return []

    signatures: List[str] = []
    candidates = [
        "Lcom/google/android/gms/ads/internal/util/zzm;->zzaz(Landroid/content/Context;)Ljava/lang/String;",
        "Lcom/google/android/gms/ads/internal/util/zzm;->zzd(Landroid/os/Bundle;)Ljava/lang/String;",
        "Lcom/google/android/gms/ads/BaseAdView;->setAdUnitId(Ljava/lang/String;)V",
        "Lcom/google/android/gms/ads/AdView;->setAdUnitId(Ljava/lang/String;)V",
        "Lcom/google/android/gms/internal/ads/zzze;->setAdUnitId(Ljava/lang/String;)V",
    ]
    for signature in candidates:
        if find_smali_method_body(signature, str(decompiled_dir)) is None:
            trace_lines.append(f"admob fallback unavailable: {signature}")
            continue
        add_signature(signatures, signature)
        trace_lines.append(f"admob fallback selected: {signature}")
    return signatures


def is_admob_report(report: ApkStaticReport, decompiled_dir: Path) -> bool:
    text = " ".join(
        [
            str(report.apk_path or ""),
            str(report.package_name or ""),
            " ".join(report.llm_observation_points or []),
        ]
    ).lower()
    if "admob" in text or "mobileads" in text or "google mobile ads" in text:
        return True
    manifest = decompiled_dir / "AndroidManifest.xml"
    try:
        manifest_text = manifest.read_text(encoding="utf-8", errors="ignore") if manifest.is_file() else ""
    except OSError:
        manifest_text = ""
    if "com.google.android.gms.ads.APPLICATION_ID" in manifest_text:
        return True
    return any(
        ADMOB_APP_ID_RE.search(finding.value or "") or ADMOB_AD_UNIT_ID_RE.search(finding.value or "")
        for finding in report.api_key_findings
    )


def extract_evidence_smali_path(entry: str) -> Optional[str]:
    match = re.match(r"(.+?\.smali):\d+:", entry.replace("\\", "/"))
    return match.group(1) if match else None


def is_low_risk_places_internal_evidence(evidence_file: str) -> bool:
    normalized = evidence_file.replace("\\", "/")
    if "com/google/android/libraries/places/internal/" not in normalized:
        return False
    return not any(token in normalized for token in HIGH_RISK_PATH_TOKENS)


def extract_static_auth_header_methods(smali_path: Path) -> List[Tuple[str, str]]:
    parsed = parse_smali_methods(smali_path)
    if not parsed:
        return []
    class_descriptor, methods = parsed
    selected: List[Tuple[str, str]] = []
    for method_sig, body in methods:
        if is_ignored_smali_method(method_sig):
            continue
        tokens = [token for token in AUTH_HEADER_TOKENS if token in body]
        if not tokens:
            continue
        selected.append((f"{class_descriptor}->{method_sig}", "auth headers: " + ", ".join(tokens)))
    return selected


def extract_static_auth_adjacent_network_methods(smali_path: Path) -> List[Tuple[str, str]]:
    parsed = parse_smali_methods(smali_path)
    if not parsed:
        return []
    class_descriptor, methods = parsed
    class_has_auth_header = False
    try:
        class_text = smali_path.read_text(encoding="utf-8", errors="ignore")
        class_has_auth_header = any(token in class_text for token in AUTH_HEADER_TOKENS)
    except OSError:
        return []

    selected: List[Tuple[str, str]] = []
    for method_sig, body in methods:
        if is_ignored_smali_method(method_sig):
            continue
        if method_sig.endswith("execute(Ljava/lang/Runnable;)V"):
            continue
        network_tokens = [token for token in NETWORK_SEND_TOKENS if token in body]
        if not network_tokens:
            continue
        if class_has_auth_header or any(token in body for token in AUTH_HEADER_TOKENS):
            selected.append((f"{class_descriptor}->{method_sig}", "network sink: " + ", ".join(network_tokens[:2])))
    return selected


def is_ignored_smali_method(method_sig: str) -> bool:
    return "<init>" in method_sig or "<clinit>" in method_sig


def resolve_class_observation_to_methods(fields: List[str], decompiled_dir: Optional[str]) -> List[str]:
    if len(fields) < 3 or not decompiled_dir:
        return []

    class_name = fields[0]
    signal_type = fields[1] if len(fields) > 1 else ""
    evidence_file = fields[2]
    if "(" in class_name or "->" in class_name:
        return []
    if not re.match(r"^(?:[A-Za-z_$][\w$]*\.){2,}[A-Za-z_$][\w$]*$", class_name):
        return []

    smali_path = resolve_evidence_path(Path(decompiled_dir), evidence_file)
    if not smali_path or not smali_path.is_file():
        return []

    class_descriptor = "L" + class_name.replace(".", "/") + ";"
    return extract_relevant_smali_methods(smali_path, class_descriptor, signal_type)


def resolve_evidence_path(decompiled_dir: Path, evidence_file: str) -> Optional[Path]:
    normalized = evidence_file.replace("\\", "/").strip("` ")
    if not normalized.endswith(".smali"):
        return None

    direct = decompiled_dir / Path(normalized)
    if direct.exists():
        return direct

    matches = list(decompiled_dir.glob("**/" + Path(normalized).name))
    for match in matches:
        if match.as_posix().endswith(normalized):
            return match
    return matches[0] if len(matches) == 1 else None


def extract_relevant_smali_methods(smali_path: Path, class_descriptor: str, signal_type: str) -> List[str]:
    parsed = parse_smali_methods(smali_path)
    if not parsed:
        return []
    declared_class, methods = parsed
    class_descriptor = declared_class or class_descriptor

    tokens = signal_search_tokens(signal_type)
    selected: List[str] = []
    for method_sig, body in methods:
        if is_ignored_smali_method(method_sig):
            continue
        if any(token.lower() in body.lower() for token in tokens):
            selected.append(f"{class_descriptor}->{method_sig}")

    return selected


def parse_smali_methods(smali_path: Path) -> Optional[Tuple[str, List[Tuple[str, str]]]]:
    try:
        text = smali_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    class_descriptor = ""
    declared_class = re.search(r"(?m)^\.class\b.*\s(L[\w/$]+;)", text)
    if declared_class:
        class_descriptor = declared_class.group(1)

    methods: List[Tuple[str, str]] = []
    current_decl: Optional[str] = None
    current_lines: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(".method "):
            current_decl = stripped
            current_lines = [line]
            continue
        if current_decl is not None:
            current_lines.append(line)
            if stripped == ".end method":
                method_sig = current_decl.split()[-1]
                methods.append((method_sig, "\n".join(current_lines)))
                current_decl = None
                current_lines = []
    return class_descriptor, methods


def signal_search_tokens(signal_type: str) -> List[str]:
    signal = signal_type.lower()
    tokens = [
        "X-Goog-Api-Key",
        "X-Android-Package",
        "X-Android-Cert",
        "X-Goog-FieldMask",
        "getPackageName",
        "getPackageInfo",
        "signatures",
        "MessageDigest",
        "SHA-1",
        "SHA-256",
    ]
    if "api" in signal or "key" in signal:
        tokens.extend(["API_KEY", "X-Goog-Api-Key"])
    if "package" in signal:
        tokens.extend(["getPackageName", "X-Android-Package", "packageName"])
    if "cert" in signal or "digest" in signal or "sha" in signal or "signature" in signal:
        tokens.extend(["X-Android-Cert", "MessageDigest", "SHA-1", "signatures", "Signature"])
    if "fieldmask" in signal:
        tokens.append("X-Goog-FieldMask")
    if "header" in signal or "network" in signal:
        tokens.extend(["setRequestProperty", "header", "Header"])
    return sorted(set(tokens), key=tokens.index)


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned.strip("._") or "SDK"


def format_markdown(
    pair: ApkPair,
    demo_report: ApkStaticReport,
    show_secrets: bool,
) -> str:
    lines = [
        f"# {pair.sdk_id} {pair.sdk_name} SDK Audit",
        "",
        "## Scope",
        "",
        "- Purpose: defensive audit of exposed SDK credentials and app authorization signals.",
        "- The generated Frida script is passive and does not modify runtime values.",
        "",
        "## Demo APK",
        "",
        f"- Path: `{demo_report.apk_path}`",
        f"- Package: `{demo_report.package_name or 'unknown'}`",
        f"- Launch activity: `{demo_report.launch_activity or 'unknown'}`",
        f"- Cert SHA-1: `{demo_report.cert_sha1 or 'unknown'}`",
        f"- Cert SHA-256: `{demo_report.cert_sha256 or 'unknown'}`",
        "",
        "## Candidate API Keys",
        "",
    ]
    if demo_report.api_key_findings:
        for finding in demo_report.api_key_findings:
            value = finding.value if show_secrets else mask_secret(finding.value)
            lines.append(f"- `{finding.kind}` from `{finding.source}`: `{value}`")
    else:
        lines.append("- No candidate embedded API keys found by static string scanning.")

    lines.extend(["", "## Protection Signal Evidence", ""])
    if demo_report.protection_hits:
        for kind, paths in demo_report.protection_hits.items():
            joined = ", ".join(f"`{path}`" for path in paths[:12])
            more = f" and {len(paths) - 12} more" if len(paths) > 12 else ""
            lines.append(f"- `{kind}`: {joined}{more}")
    else:
        lines.append("- No decompiled-code signal evidence found, or apktool was unavailable.")

    if pair.attacker:
        lines.extend(["", "## Paired Attacker APK", "", f"- Path: `{pair.attacker}`"])

    warnings = demo_report.tool_warnings
    if warnings:
        lines.extend(["", "## Tool Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")

    lines.extend(
        [
            "",
            "## Suggested Defensive Follow-up",
            "",
            "- Confirm exposed API keys are restricted by package name and signing certificate in the SDK provider console.",
            "- Rotate keys that appear in publicly distributed APKs when the provider supports server-side token exchange instead.",
            "- Use the passive monitor while manually triggering the demo flow to verify whether package names, cert digests, or API keys appear in headers, query parameters, Bundles, or GMS/Binder-facing calls.",
        ]
    )
    return "\n".join(lines) + "\n"


def select_pairs(pairs: Dict[str, ApkPair], sdk_ids: Optional[Set[str]]) -> Iterable[ApkPair]:
    if sdk_ids is None:
        return pairs.values()
    missing = sorted(sdk_ids.difference(pairs.keys()))
    if missing:
        print(f"[!] Config selected SDK ids not present in APK dir: {', '.join(missing)}")
    selected = [pair for sdk_id, pair in pairs.items() if sdk_id in sdk_ids]
    if not selected:
        raise SystemExit("No APKs matched [APK_ANALYZER] ApkAna_SDK_IDS.")
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


def run_apk_analyzer() -> None:
    parser = argparse.ArgumentParser(
        description="Defensive APK SDK credential/protection auditor. It does not bypass or spoof SDK checks."
    )
    parser.add_argument("--config", default="config.ini", help="Path to config.ini.")
    args = parser.parse_args()

    config_parser = configparser.ConfigParser()
    config_parser.read(args.config, encoding="utf-8")
    apk_dir = Path(get_config_value(config_parser, "APK_ANALYZER", "ApkAna_APK_DIR", "APK_ANALYZER_APK_DIR", "apks"))
    pairs = discover_pairs(apk_dir)
    if not pairs:
        raise SystemExit(f"No named APKs found in {apk_dir}. Expected files like 0018-NameSDK-demo.apk")
    cfg = read_analyzer_config(args.config, pairs)
    api_key, base_url, model_name = read_api_config(args.config)

    print(
        "[*] APK analyzer config: "
        f"ids={format_selected_ids(cfg.sdk_ids)}, apk_dir={cfg.apk_dir}, "
        f"llm={cfg.use_llm}, decompile={cfg.decompile_apk}"
    )

    for pair in select_pairs(pairs, cfg.sdk_ids):
        log_path = cfg.logs_dir / f"{pair.sdk_id}-apk_analyze.log"
        with tee_to_log(log_path):
            try:
                run_one_sdk_pair(pair, cfg, api_key, base_url, model_name)
            except Exception:
                print("[-] APK analysis failed with an unhandled exception:")
                print(traceback.format_exc())
                raise


def run_one_sdk_pair(
    pair: ApkPair,
    cfg: ApkAnalyzerConfig,
    api_key: Optional[str],
    base_url: Optional[str],
    model_name: Optional[str],
) -> None:
    if not pair.demo:
        print(f"[!] Skipping {pair.sdk_id}: missing demo APK.")
        return
    print(f"\n=== Auditing {pair.sdk_id} {pair.sdk_name} ===")
    print(f"[*] Demo APK: {pair.demo}")
    print(f"[*] Attacker APK: {pair.attacker or 'missing'}")
    print("[*] Stage 1/2: static extraction and decompilation")
    demo_report = analyze_apk(
        pair.demo,
        cfg.work_dir,
        api_key,
        base_url,
        model_name,
        use_llm=cfg.use_llm,
        show_secrets=True,
        decompile_apk=cfg.decompile_apk,
    )

    print("[*] Stage 2/2: writing audit reports")
    write_reports(cfg.out_dir, pair, demo_report, True)
    write_apk_analyze_results(cfg.analyze_results_dir, pair, demo_report)
    print("[*] Analysis complete. Run app_hooker.py when you want to install/spawn the attacker app.")


def format_selected_ids(sdk_ids: Optional[Set[str]]) -> str:
    if sdk_ids is None:
        return "all"
    return ",".join(sorted(sdk_ids))


if __name__ == "__main__":
    run_apk_analyzer()
