import configparser
import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from openai import OpenAI


API_KEY_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
    ("generic_api_key_assignment", re.compile(
        r"(?i)(api[_\- ]?key|apikey|client[_\- ]?key|access[_\- ]?token)"
        r"[^A-Za-z0-9_\-]{0,20}"
        r"([A-Za-z0-9_\-:.]{16,})"
    )),
    ("android_manifest_metadata", re.compile(
        r"(?i)android:name=\"[^\"]*(api[_\- ]?key|apikey|maps|places)[^\"]*\""
        r"\s+android:value=\"([^\"]{6,})\""
    )),
]

PROTECTION_PATTERNS: Dict[str, re.Pattern] = {
    "package_name": re.compile(r"\b(getPackageName|getPackageInfo|packageName)\b"),
    "app_metadata": re.compile(r"\b(getApplicationInfo|metaData|ApplicationInfo)\b"),
    "signing_certificate": re.compile(
        r"\b(GET_SIGNATURES|GET_SIGNING_CERTIFICATES|SigningInfo|signatures|"
        r"getApkContentsSigners|getSigningCertificateHistory)\b"
    ),
    "sha1_sha256_digest": re.compile(r"\b(SHA-1|SHA1|SHA-256|SHA256|MessageDigest)\b"),
    "google_android_headers": re.compile(
        r"(?i)(x-android-package|x-android-cert|x-goog-api-key|x-goog-fieldmask)"
    ),
    "network_send": re.compile(
        r"\b(OkHttpClient|Request\$Builder|HttpURLConnection|Retrofit|Volley|"
        r"URLConnection|Socket|writeTo|enqueue|execute)\b"
    ),
    "binder_or_gms": re.compile(
        r"\b(IBinder|Parcel|transact|DynamiteModule|GoogleApiAvailability|"
        r"GoogleSignatureVerifier|com/google/android/gms)\b"
    ),
}


def run_external(args: List[str], **kwargs) -> subprocess.CompletedProcess:
    tool = shutil.which(args[0])
    if not tool:
        raise FileNotFoundError(args[0])

    if args[0].lower() == "apktool" and tool.lower().endswith((".bat", ".cmd")):
        return run_apktool_jar(tool, args[1:], **kwargs)

    command = [tool] + args[1:]
    if tool.lower().endswith((".bat", ".cmd")):
        return subprocess.run(["cmd.exe", "/d", "/s", "/c", "call", *command], **kwargs)
    return subprocess.run(command, **kwargs)


def run_apktool_jar(apktool_script: str, apktool_args: List[str], **kwargs) -> subprocess.CompletedProcess:
    script_dir = Path(apktool_script).resolve().parent
    jar = script_dir / "apktool.jar"
    if not jar.exists():
        jars = sorted(script_dir.glob("apktool*.jar"), key=lambda path: path.name)
        if jars:
            jar = jars[-1]
    if not jar.exists():
        raise FileNotFoundError(f"No apktool jar found next to {apktool_script}")

    java_exe = shutil.which("java")
    if not java_exe:
        raise FileNotFoundError("java")
    command = [
        java_exe,
        "-Duser.language=en",
        "-Dfile.encoding=UTF8",
        "-jar",
        str(jar),
        *apktool_args,
    ]
    print(f"[*] Running apktool jar: {jar}")
    return subprocess.run(command, **kwargs)


@dataclass
class Finding:
    kind: str
    value: str
    source: str
    masked_value: Optional[str] = None

    def as_dict(self, show_secrets: bool = False) -> Dict[str, str]:
        value = self.value if show_secrets else (self.masked_value or mask_secret(self.value))
        return {"kind": self.kind, "value": value, "source": self.source}


@dataclass
class ApkStaticReport:
    apk_path: str
    package_name: Optional[str] = None
    launch_activity: Optional[str] = None
    cert_sha1: Optional[str] = None
    cert_sha256: Optional[str] = None
    api_key_findings: List[Finding] = field(default_factory=list)
    protection_hits: Dict[str, List[str]] = field(default_factory=dict)
    decompiled_dir: Optional[str] = None
    tool_warnings: List[str] = field(default_factory=list)
    llm_audit_text: Optional[str] = None
    llm_observation_points: List[str] = field(default_factory=list)

    def to_dict(self, show_secrets: bool = False) -> Dict[str, object]:
        return {
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "launch_activity": self.launch_activity,
            "cert_sha1": self.cert_sha1,
            "cert_sha256": self.cert_sha256,
            "api_key_findings": [f.as_dict(show_secrets=show_secrets) for f in self.api_key_findings],
            "protection_hits": self.protection_hits,
            "decompiled_dir": self.decompiled_dir,
            "tool_warnings": self.tool_warnings,
            "llm_observation_points": self.llm_observation_points,
        }


def mask_secret(value: str) -> str:
    if not value:
        return value
    if len(value) <= 10:
        return value[0:2] + "***"
    return value[:6] + "***" + value[-4:]


def read_api_config(config_path: str = "config.ini") -> Tuple[Optional[str], Optional[str], Optional[str]]:
    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")
    if not parser.has_section("API"):
        return None, None, None
    return (
        parser.get("API", "API_KEY", fallback=None),
        parser.get("API", "BASE_URL", fallback=None),
        parser.get("API", "MODEL_NAME", fallback=None),
    )


class APKAnalyzer:
    """Defensive APK credential/protection auditor.

    This class intentionally identifies exposed credentials and authorization-signal
    collection points, but it does not generate bypass or value-replacement logic.
    """

    def __init__(
        self,
        apk_path: str,
        output_dir: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        show_secrets: bool = False,
    ):
        self.apk_path = str(apk_path)
        self.output_dir = str(output_dir)
        self.api_key = api_key
        self.base_url = base_url
        self.model_name = model_name
        self.show_secrets = show_secrets
        self.client = OpenAI(api_key=api_key, base_url=base_url) if api_key and base_url else None

    def run(self, use_llm: bool = True, decompile_apk: bool = True) -> ApkStaticReport:
        report = ApkStaticReport(apk_path=self.apk_path)
        print("[*] Reading APK package/activity metadata...")
        report.package_name, report.launch_activity = self.get_badging()
        print(f"[+] Package: {report.package_name or 'unknown'}")
        print(f"[+] Launch activity: {report.launch_activity or 'unknown'}")
        print("[*] Reading APK signing certificate digests...")
        report.cert_sha1, report.cert_sha256 = self.get_certificate_digests()
        print(f"[+] Cert SHA-1: {report.cert_sha1 or 'unknown'}")
        print(f"[+] Cert SHA-256: {report.cert_sha256 or 'unknown'}")
        report.api_key_findings = self.scan_apk_strings()

        if self.prepare_decompiled_apk(report, decompile_apk=decompile_apk):
            if not report.package_name:
                report.package_name = self.get_manifest_package_name()
            report.protection_hits = self.scan_decompiled_protection_hits()
            if use_llm and self.client:
                print("[*] LLM analysis enabled; preparing focused context...")
                llm_text = self.analyze_with_llm(report)
                if llm_text:
                    report.llm_audit_text = llm_text
                    if llm_text.startswith("[-] Error calling LLM:"):
                        report.tool_warnings.append(llm_text)
                    report.llm_observation_points = extract_llm_observation_points(llm_text)
                    print(f"[+] Extracted {len(report.llm_observation_points)} LLM observation point(s).")
                    Path("analysis_process.md").write_text(llm_text, encoding="utf-8")
                    print("[+] LLM audit saved to analysis_process.md")
            elif use_llm:
                report.tool_warnings.append("LLM skipped: missing API config.")

        return report

    def prepare_decompiled_apk(self, report: ApkStaticReport, decompile_apk: bool) -> bool:
        out = Path(self.output_dir)
        if self.has_decompiled_output():
            report.decompiled_dir = self.output_dir
            if decompile_apk:
                print(f"[*] ApkAna_DECOMPILE=true; rebuilding existing decompiled APK at {self.output_dir}.")
                return self.decompile(report)
            print(f"[+] ApkAna_DECOMPILE=false and reusable decompiled output exists at {self.output_dir}; reusing it.")
            return True

        if decompile_apk:
            if out.exists():
                print(f"[*] Existing decompile directory is incomplete; rebuilding {self.output_dir}.")
            else:
                print(f"[*] No decompile directory found at {self.output_dir}; decompiling.")
        else:
            if out.exists():
                print(
                    f"[*] ApkAna_DECOMPILE=false but existing decompile directory is incomplete; "
                    f"rebuilding {self.output_dir}."
                )
            else:
                print(
                    f"[*] ApkAna_DECOMPILE=false but no reusable decompiled output was found at "
                    f"{self.output_dir}; decompiling once."
                )
        return self.decompile(report)

    def has_decompiled_output(self) -> bool:
        out = Path(self.output_dir)
        if not out.is_dir():
            return False
        manifest = out / "AndroidManifest.xml"
        if not manifest.is_file():
            return False
        return any(path.suffix.lower() == ".smali" for path in out.rglob("*.smali"))

    def decompile(self, report: Optional[ApkStaticReport] = None) -> bool:
        if not shutil.which("apktool"):
            msg = "apktool not found; decompiled smali/XML analysis skipped."
            print(f"[!] {msg}")
            if report:
                report.tool_warnings.append(msg)
            return False

        print(f"[*] Decompiling {self.apk_path} to {self.output_dir}...")
        out = Path(self.output_dir)
        if out.exists():
            shutil.rmtree(out)
        try:
            run_external(
                ["apktool", "d", "-f", self.apk_path, "-o", self.output_dir],
                check=True,
                text=True,
            )
            if report:
                report.decompiled_dir = self.output_dir
            print("[+] Decompilation successful.")
            return True
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if getattr(exc, "stderr", None) else str(exc)
            print(f"[-] Error decompiling APK: {stderr}")
            if report:
                report.tool_warnings.append(f"apktool failed: {stderr}")
            return False

    def get_badging(self) -> Tuple[Optional[str], Optional[str]]:
        if not shutil.which("aapt"):
            return None, None
        try:
            proc = run_external(
                ["aapt", "dump", "badging", self.apk_path],
                check=True,
                capture_output=True,
                text=True,
                errors="replace",
            )
        except subprocess.CalledProcessError:
            return None, None

        package_name = None
        launch_activity = None
        for line in proc.stdout.splitlines():
            if line.startswith("package:"):
                match = re.search(r"name='([^']+)'", line)
                package_name = match.group(1) if match else package_name
            elif line.startswith("launchable-activity:"):
                match = re.search(r"name='([^']+)'", line)
                launch_activity = match.group(1) if match else launch_activity
        return package_name, launch_activity

    def get_certificate_digests(self) -> Tuple[Optional[str], Optional[str]]:
        sha1, sha256 = self._apksigner_digests()
        if sha1 or sha256:
            return sha1, sha256
        return self._keytool_digests()

    def _apksigner_digests(self) -> Tuple[Optional[str], Optional[str]]:
        if not shutil.which("apksigner"):
            return None, None
        try:
            proc = run_external(
                ["apksigner", "verify", "--print-certs", self.apk_path],
                check=True,
                capture_output=True,
                text=True,
                errors="replace",
            )
        except subprocess.CalledProcessError:
            return None, None
        return parse_digest_output(proc.stdout)

    def _keytool_digests(self) -> Tuple[Optional[str], Optional[str]]:
        if not shutil.which("keytool"):
            return None, None
        try:
            proc = run_external(
                ["keytool", "-printcert", "-jarfile", self.apk_path],
                check=True,
                capture_output=True,
                text=True,
                errors="replace",
            )
        except subprocess.CalledProcessError:
            return None, None
        return parse_digest_output(proc.stdout)

    def get_manifest_package_name(self) -> Optional[str]:
        manifest_path = Path(self.output_dir) / "AndroidManifest.xml"
        if not manifest_path.exists():
            return None
        content = manifest_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'package="([^"]+)"', content)
        return match.group(1) if match else None

    def scan_apk_strings(self) -> List[Finding]:
        print("[*] Scanning APK strings for embedded key material...")
        findings: Dict[Tuple[str, str, str], Finding] = {}
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                for info in zf.infolist():
                    if info.file_size > 8 * 1024 * 1024:
                        continue
                    if info.filename.upper().startswith("META-INF/"):
                        continue
                    try:
                        data = zf.read(info)
                    except Exception:
                        continue
                    for text in iter_strings(data):
                        for kind, pattern in API_KEY_PATTERNS:
                            for match in pattern.finditer(text):
                                value = match.group(match.lastindex or 0)
                                value = cleanup_candidate(value)
                                if not is_probable_secret(value):
                                    continue
                                key = (kind, value, info.filename)
                                findings[key] = Finding(kind=kind, value=value, source=info.filename)
        except zipfile.BadZipFile:
            print(f"[-] {self.apk_path} is not a valid APK/ZIP.")
        print(f"[+] Found {len(findings)} candidate key references.")
        return sorted(findings.values(), key=lambda item: (item.kind, item.source, item.value))

    def scan_decompiled_protection_hits(self) -> Dict[str, List[str]]:
        print("[*] Scanning decompiled code for authorization-signal collection...")
        hits: Dict[str, List[str]] = {name: [] for name in PROTECTION_PATTERNS}
        root = Path(self.output_dir)
        scanned = 0
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".smali", ".xml", ".json", ".properties"}:
                continue
            rel = str(path.relative_to(root))
            if is_low_value_path(rel):
                continue
            scanned += 1
            if scanned % 500 == 0:
                print(f"[*] Scanned {scanned} decompiled files...")
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for name, pattern in PROTECTION_PATTERNS.items():
                line_hits = []
                for line_no, line in enumerate(content.splitlines(), start=1):
                    if pattern.search(line):
                        snippet = line.strip().replace("\t", " ")
                        line_hits.append(f"{rel}:{line_no}: {snippet[:140]}")
                        if len(line_hits) >= 3:
                            break
                hits[name].extend(line_hits)
        filtered = {name: paths[:80] for name, paths in hits.items() if paths}
        print(f"[+] Decompiled scan finished: {scanned} files scanned, {len(filtered)} signal categories matched.")
        return filtered

    def collect_llm_context(self, max_chars: int = 180000) -> str:
        print("[*] Selecting smali/XML files for LLM context...")
        chunks: List[str] = []
        total = 0
        manifest = Path(self.output_dir) / "AndroidManifest.xml"
        candidates = [manifest] if manifest.exists() else []
        candidates.extend(select_interesting_files(Path(self.output_dir)))
        print(f"[*] Candidate context files: {len(candidates)}")
        for path in candidates:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            rel = str(path.relative_to(self.output_dir))
            chunk = f"\n\n--- File: {rel} ---\n{content}"
            if total + len(chunk) > max_chars:
                break
            chunks.append(chunk)
            total += len(chunk)
        print(f"[+] Prepared LLM context: {len(chunks)} files, {total} characters.")
        return "".join(chunks)

    def analyze_with_llm(self, report: ApkStaticReport) -> Optional[str]:
        context = self.collect_llm_context()
        if not context:
            return None
        print(f"[*] Sending focused smali/XML context to LLM ({self.model_name}); this may take a while...")
        prompt = (
            "You are helping with defensive security testing of an Android APK owned by the tester.\n"
            "Identify SDK authorization signals that are observable in the app process. Focus on evidence that the SDK reads "
            "or sends API keys, package names, Android certificate digests, manifest meta-data, Binder/Dynamite payloads, "
            "or HTTP headers/query/body fields used by SDK servers.\n\n"
            "Prioritize authorization-chain relevance over broad identity reads. A method is a good replacement candidate "
            "only when it directly builds, writes, or returns values used in a remote SDK authentication/authorization "
            "request. Exclude or mark observe_only for methods that merely support app startup, resource loading, Google "
            "Play Services availability checks, generic PackageManager lookups, local signature integrity verification, "
            "Binder service setup, or Dynamite/module loading without a clear outbound authentication sink. "
            "For each candidate, identify the source -> transform -> sink chain that makes it relevant to remote "
            "authentication.\n\n"
            "Do not provide bypass, spoofing, value replacement, or evasion instructions. Return an audit report with:\n"
            "1. likely exposed credential locations,\n"
            "2. likely protection signals (package name, SHA-1, SHA-256, manifest metadata, Binder/GMS IPC, network fields),\n"
            "3. candidate auth point methods as class/method names,\n"
            "4. confidence and evidence file names, and\n"
            "5. whether each candidate is replace_safe or observe_only.\n\n"
            "At the end, add a section named FRIDA_OBSERVATION_POINTS. In that section, list one candidate "
            "method per line in this format:\n"
            "SmaliMethodName | EvidenceType | SourceLocation | Confidence | ReplaceSafety | AuthChain\n"
            "ReplaceSafety must be exactly replace_safe or observe_only. Use replace_safe only when the evidence shows a "
            "clear connection from an authentication-related source to an outbound SDK authentication sink; otherwise use "
            "observe_only. AuthChain must be a short source -> transform -> sink explanation. Do not include replacement "
            "values, spoofing steps, or bypass logic.\n\n"
            f"Static metadata:\n{json.dumps(report.to_dict(show_secrets=self.show_secrets), ensure_ascii=False, indent=2)}\n\n"
            "Code context follows:\n"
        )
        try:
            completion = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a careful Android SDK security auditor. You help analyze Android SDK authorization "
                            "behavior for defensive security testing. You should focus on evidence-based auditing and "
                            "refuse to provide bypass guidance, spoofing steps, or value-replacement instructions."
                        ),
                    },
                    {"role": "user", "content": prompt + context},
                ],
                max_tokens=4096,
            )
            print("[+] LLM response received.")
            return extract_chat_completion_text(completion)
        except Exception as exc:
            return f"[-] Error calling LLM: {exc}"


def extract_chat_completion_text(completion) -> Optional[str]:
    if completion is None:
        return None
    if isinstance(completion, str):
        return completion
    if isinstance(completion, dict):
        choices = completion.get("choices") or []
        if choices:
            message = choices[0].get("message") or {}
            content = message.get("content")
            if content is not None:
                return content
            text = choices[0].get("text")
            if text is not None:
                return text
        content = completion.get("content")
        return str(content) if content is not None else json.dumps(completion, ensure_ascii=False)

    choices = getattr(completion, "choices", None)
    if choices:
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None) if message is not None else None
        if content is not None:
            return content
        text = getattr(choices[0], "text", None)
        if text is not None:
            return text
    return str(completion)


def extract_llm_observation_points(llm_text: str) -> List[str]:
    points: List[str] = []
    in_points_section = False
    smali_method = re.compile(r"L[\w/$]+;->[\w$<>]+\(.*?\)\S*")
    java_method = re.compile(r"(?:[A-Za-z_$][\w$]*\.){2,}[A-Za-z_$<][\w$<>]*(?:\([^)]*\))?")
    useful_words = re.compile(
        r"(?i)(frida|hook|observe|method|class|package|signature|certificate|"
        r"sha-?1|sha-?256|api.?key|x-android|x-goog|header|metadata|binder|dynamite)"
    )

    structured_points = extract_named_observation_section(llm_text)
    if structured_points:
        return structured_points

    for raw_line in llm_text.splitlines():
        line = raw_line.strip()
        if not line:
            if in_points_section:
                continue
            continue
        normalized_heading = line.strip("#:： -*").upper().replace(" ", "_")
        normalized_heading = re.sub(r"[^A-Z0-9_]+", "", normalized_heading)
        if normalized_heading in {"FRIDA_OBSERVATION_POINTS", "PASSIVE_FRIDA_OBSERVATION_POINTS"}:
            in_points_section = True
            continue
        if in_points_section and line.startswith("#"):
            break

        has_method = smali_method.search(line) or java_method.search(line)
        if in_points_section or (has_method and useful_words.search(line)):
            cleaned = line.lstrip("-*0123456789. \t")
            if cleaned and cleaned not in points:
                points.append(cleaned)

    return points


def extract_named_observation_section(llm_text: str) -> List[str]:
    points: List[str] = []
    in_points_section = False
    for raw_line in llm_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        normalized_heading = line.strip("#:： -*").upper().replace(" ", "_")
        normalized_heading = re.sub(r"[^A-Z0-9_]+", "", normalized_heading)
        if normalized_heading in {"FRIDA_OBSERVATION_POINTS", "PASSIVE_FRIDA_OBSERVATION_POINTS"}:
            in_points_section = True
            continue
        if in_points_section and line.startswith("#"):
            break
        if in_points_section:
            cleaned = line.lstrip("-*0123456789. \t")
            if cleaned and cleaned not in points:
                points.append(cleaned)
    return points


def parse_digest_output(output: str) -> Tuple[Optional[str], Optional[str]]:
    sha1 = None
    sha256 = None
    for line in output.splitlines():
        if "SHA-1" in line or "SHA1" in line:
            match = re.search(r"((?:[A-Fa-f0-9]{2}:){19}[A-Fa-f0-9]{2}|[A-Fa-f0-9]{40})", line)
            if match:
                sha1 = normalize_digest(match.group(1))
        if "SHA-256" in line or "SHA256" in line:
            match = re.search(r"((?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}|[A-Fa-f0-9]{64})", line)
            if match:
                sha256 = normalize_digest(match.group(1))
    return sha1, sha256


def normalize_digest(value: str) -> str:
    return value.replace(":", "").upper()


def iter_strings(data: bytes) -> Iterable[str]:
    ascii_pattern = re.compile(rb"[\x20-\x7e]{6,}")
    utf16_pattern = re.compile((rb"(?:[\x20-\x7e]\x00){6,}"))
    for match in ascii_pattern.finditer(data):
        yield match.group(0).decode("utf-8", errors="ignore")
    for match in utf16_pattern.finditer(data):
        yield match.group(0).decode("utf-16le", errors="ignore")


def cleanup_candidate(value: str) -> str:
    return value.strip().strip("\"'`,;)")


def is_probable_secret(value: str) -> bool:
    if not value or len(value) < 16:
        return False
    if value.lower() in {"android.intent.action.main", "android.intent.category.launcher"}:
        return False
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return bool(digest)


def is_low_value_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    low_value_parts = [
        "/android/support/",
        "/androidx/",
        "/kotlin/",
        "/kotlinx/",
        "/org/intellij/",
        "/org/jetbrains/",
        "/com/android/volley/",
        "/com/bumptech/",
        "/com/google/android/material/",
        "/com/google/common/",
        "/com/google/gson/",
        "/com/squareup/",
        "/okhttp3/",
        "/okio/",
        "/res/drawable",
        "/res/mipmap",
    ]
    return any(part in f"/{normalized}" for part in low_value_parts)


def select_interesting_files(root: Path) -> List[Path]:
    scored: List[Tuple[int, Path]] = []
    interesting = re.compile(
        r"(?i)(api|key|cert|sign|digest|sha|package|metadata|dynamite|binder|"
        r"google|places|maps|auth|request|http|url|network)"
    )
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".smali", ".xml", ".json", ".properties"}:
            continue
        rel = str(path.relative_to(root))
        if is_low_value_path(rel):
            continue
        score = 0
        if interesting.search(rel):
            score += 4
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for pattern in PROTECTION_PATTERNS.values():
            if pattern.search(text):
                score += 2
        for _, pattern in API_KEY_PATTERNS:
            if pattern.search(text):
                score += 5
        if score:
            scored.append((score, path))
    scored.sort(key=lambda item: (-item[0], str(item[1])))
    return [path for _, path in scored[:60]]
