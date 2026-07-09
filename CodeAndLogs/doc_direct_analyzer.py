"""
Direct LLM Q&A (no crawling, no local docs): for each SDK rank in DocDirectAna_SDK_ID,
look up SDK name and Vendor in SDKList.csv, then ask the remote model whether that SDK:

1. Supports Android
2. Typically requires an API-style credential (and credential name if yes)

Reads [API] and [DOC_DIRECT_ANALYZER] from config.ini.
Logs: doc_direct_analyze_logs/{rank}-doc_direct_analyze.log

Run from repo root:
  python doc_direct_analyzer.py
  python doc_direct_analyzer.py 0025
  python doc_direct_analyzer.py 0001-0003
"""

from __future__ import annotations

import configparser
import csv
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from openai import OpenAI

DOC_DIRECT_ANALYZE_LOG_DIR = "doc_direct_analyze_logs"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 90.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY_SECONDS = 6.0
SUMMARY_JSON_KEYS = frozenset(
    {"supports_android", "has_api_credential", "credential_name"}
)
DELIMITER = "---CONCISE_SUMMARY_START---"


def setup_sdk_doc_direct_analyze_logger(sdk_id: str, log_dir: str = DOC_DIRECT_ANALYZE_LOG_DIR):
    """Console + file ``{sdk_id}-doc_direct_analyze.log`` under log_dir (overwrite each run)."""
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{sdk_id}-doc_direct_analyze.log")
    lg = logging.getLogger(f"doc_direct_analyze.{sdk_id}")
    lg.handlers.clear()
    lg.setLevel(logging.INFO)
    lg.propagate = False
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh = logging.FileHandler(log_path, encoding="utf-8", mode="w")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    lg.addHandler(fh)
    lg.addHandler(sh)
    lg.info("Log file: %s", os.path.abspath(log_path))
    return lg


def _log_usage(logger: logging.Logger | None, completion) -> dict:
    """Record remote LLM token usage; return usage dict (possibly empty)."""
    usage = completion.get("usage") if isinstance(completion, dict) else getattr(completion, "usage", None)
    if usage is None:
        msg = "LLM token usage: not reported by API (completion.usage is missing)."
        if logger is not None:
            logger.warning(msg)
        else:
            print(f"[-] {msg}")
        return {}
    out = {
        "prompt_tokens": int((usage.get("prompt_tokens") if isinstance(usage, dict) else getattr(usage, "prompt_tokens", 0)) or 0),
        "completion_tokens": int((usage.get("completion_tokens") if isinstance(usage, dict) else getattr(usage, "completion_tokens", 0)) or 0),
        "total_tokens": int((usage.get("total_tokens") if isinstance(usage, dict) else getattr(usage, "total_tokens", 0)) or 0),
    }
    msg = (
        f"LLM token usage: prompt_tokens={out['prompt_tokens']} "
        f"completion_tokens={out['completion_tokens']} total_tokens={out['total_tokens']}"
    )
    if logger is not None:
        logger.info(msg)
    else:
        print(f"[*] {msg}")
    return out


def _field(obj, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _content_to_text(content) -> str | None:
    if content is None:
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            text = _field(item, "text")
            if text is not None:
                parts.append(str(text))
        return "\n".join(parts).strip() if parts else None
    return str(content)


def extract_completion_text(completion, logger: logging.Logger | None = None) -> str | None:
    """Accept OpenAI objects, dict responses, or raw-string proxy responses."""
    if isinstance(completion, str):
        if logger:
            logger.warning("LLM API returned raw string response; parsing it directly.")
        return completion

    choices = _field(completion, "choices")
    if choices:
        first = choices[0]
        message = _field(first, "message")
        if message is not None:
            text = _content_to_text(_field(message, "content"))
            if text:
                return text
        text = _content_to_text(_field(first, "text"))
        if text:
            return text

    text = _content_to_text(_field(completion, "content"))
    if text:
        return text

    if logger:
        logger.warning("LLM API returned unsupported response type: %s", type(completion).__name__)
    return None


def parse_sdk_ids(sdk_id_str: str) -> list[str]:
    """Same rules as doc_analyzer: comma list and numeric ranges like 0002-0004."""
    sdk_ids: list[str] = []
    parts = [p.strip() for p in sdk_id_str.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            subparts = part.split("-")
            if len(subparts) == 2 and subparts[0].isdigit() and subparts[1].isdigit():
                start = int(subparts[0])
                end = int(subparts[1])
                padding = len(subparts[0])
                for i in range(start, end + 1):
                    sdk_ids.append(f"{i:0{padding}d}")
            else:
                sdk_ids.append(part)
        else:
            sdk_ids.append(part.zfill(4) if part.isdigit() else part)
    seen: set[str] = set()
    unique: list[str] = []
    for rid in sdk_ids:
        if rid not in seen:
            seen.add(rid)
            unique.append(rid)
    return unique


def load_sdk_rows(csv_path: Path) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rank = (row.get("SDK Rank") or "").strip()
            name = (row.get("SDK") or "").strip()
            vendor = (row.get("Vendor") or "").strip()
            if rank:
                rows[rank.zfill(4)] = (name, vendor)
    return rows


def _is_summary_object(data: dict) -> bool:
    return SUMMARY_JSON_KEYS.issubset(data.keys())


def is_valid_summary_file(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = parse_summary_json(path.read_text(encoding="utf-8"))
    except OSError:
        return False
    return bool(data and _is_summary_object(data))


def _cfg_bool(cfg: configparser.ConfigParser, section: str, option: str, default: bool) -> bool:
    try:
        return cfg.getboolean(section, option)
    except (configparser.Error, ValueError):
        return default


def _cfg_float(cfg: configparser.ConfigParser, section: str, option: str, default: float) -> float:
    try:
        value = cfg.get(section, option).strip()
        return float(value) if value else default
    except (configparser.Error, ValueError):
        return default


def _cfg_int(cfg: configparser.ConfigParser, section: str, option: str, default: int) -> int:
    try:
        value = cfg.get(section, option).strip()
        return int(value) if value else default
    except (configparser.Error, ValueError):
        return default


def parse_summary_json(text: str) -> dict | None:
    """Parse concise-summary JSON from raw or fenced model output."""
    text = text.strip()
    if not text:
        return None
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        while lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
        if text.lower().startswith("json"):
            nl = text.find("\n")
            if nl != -1:
                text = text[nl + 1 :].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _format_summary_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False)


def _extract_trailing_summary_json(text: str) -> tuple[str, dict] | None:
    """If analysis is followed by a JSON object, return (analysis, parsed dict)."""
    start = text.rfind("{")
    while start >= 0:
        chunk = text[start:]
        data = parse_summary_json(chunk)
        if data and _is_summary_object(data):
            detailed = text[:start].strip()
            return detailed, data
        start = text.rfind("{", 0, start)
    return None


def split_llm_response(
    response: str,
    logger: logging.Logger | None = None,
) -> tuple[str | None, str | None]:
    """
    Return (detailed_analysis, concise_json_text).
    Handles delimiter split, JSON-only replies, and JSON appended after analysis.
    """
    text = response.strip()
    if not text:
        return None, None

    if DELIMITER in text:
        head, tail = text.split(DELIMITER, 1)
        detailed = head.strip() or None
        data = parse_summary_json(tail)
        if data and _is_summary_object(data):
            return detailed, _format_summary_json(data)
        if logger:
            logger.warning(
                "Delimiter present but concise section is not valid summary JSON; "
                "trying fallback parsers."
            )

    data = parse_summary_json(text)
    if data and _is_summary_object(data):
        if logger:
            logger.info("Recovered summary JSON from full response (no delimiter).")
        return None, _format_summary_json(data)

    trailing = _extract_trailing_summary_json(text)
    if trailing:
        detailed, data = trailing
        if logger:
            logger.info("Recovered summary JSON trailing after analysis text.")
        return detailed or None, _format_summary_json(data)

    if re.search(r"SECTION\s+1", text, re.IGNORECASE):
        return text, None
    return text, None


def build_prompt(sdk_name: str, vendor: str) -> str:
    return (
        "You are an expert mobile SDK analyst. Evaluate **only** the product named below using the "
        "method in this prompt (do not copy requirements from other products by the same vendor).\n\n"
        f'  SDK name: "{sdk_name}"\n'
        f'  Vendor: "{vendor}"\n\n'
        "--- Method: what counts as an API credential ---\n"
        "An **API credential** means: for normal use of **this** SDK on Android, the developer must "
        "obtain from the vendor's developer console (or equivalent) an identifier or secret and configure "
        "it in the app - e.g. API Key, App ID, client secret, access token setup, or a shipped config "
        "file whose standard integration purpose is to supply such values - so the app can reach "
        "**vendor-hosted services that this product is built to use**.\n\n"
        "Illustrative contexts (examples only; they do not define a checklist - apply step-by-step reasoning "
        "to the named SDK):\n"
        "- Map, location, or places integrations often expose an API key so requests can reach map tiles, "
        "routing, geocoding, or location endpoints and may be metered or billed by the provider.\n"
        "- Advertising or mediation SDKs may require publisher or ad-unit identifiers to serve inventory "
        "and attribute revenue.\n"
        "- Backend, auth, or multi-service platform SDKs may require project keys or App IDs so the client "
        "can talk to the vendor's cloud.\n"
        "- Social or content-sharing SDKs may require an App ID so the platform knows which application is calling.\n"
        "- Pure client libraries (HTTP, parsing, UI helpers) often need no such credential because work stays on-device.\n"
        "- Some sign-in flows use OAuth client configuration for the **end user's account**; that is user "
        "authentication, not necessarily an API credential for **this SDK's** cloud API unless the product "
        "itself is documented as requiring a separate developer key for its services.\n\n"
        "--- Work through these steps in SECTION 1 (in order) ---\n"
        "1. **Android support** - Is there an official Android library or documented Android integration?\n"
        "**If step 1 is no:** stop here. Do **not** perform steps 2-4. In SECTION 1, explain only why "
        "Android is not supported. In SECTION 2 JSON, set `supports_android` to false, "
        "`has_api_credential` to the string `\"*\"`, and `credential_name` to null "
        "(meaning not applicable on Android).\n"
        "**If step 1 is yes:** continue with steps 2-4 below.\n\n"
        "2. **Service model** - What does this product do in a typical app: mostly on-device, or does it "
        "routinely rely on the vendor's remote APIs or hosted backend as part of standard features?\n"
        "3. **Integration requirement** - According to usual setup for this product, must the developer "
        "register the app and configure a console-issued value? Name the credential type if yes.\n"
        "4. **Scope** - Confirm the credential belongs to **this** product's documented integration, not "
        "only to another product the app might add separately. Package name / signing alone do not count.\n\n"
        "--- JSON fields (three fields only; answer after the steps above) ---\n"
        "supports_android: from step 1 (boolean).\n"
        "If supports_android is **false**:\n"
        "  has_api_credential: \"*\" (string asterisk, not boolean)\n"
        "  credential_name: null\n"
        "If supports_android is **true**:\n"
        "  has_api_credential: from steps 2-4; boolean true/false only.\n"
        "  credential_name: short label if has_api_credential is true, else null.\n"
        "If evidence is weak or conflicting, say so in the analysis and prefer false / null in JSON.\n\n"
        "Respond in TWO SECTIONS separated exactly by the line below (copy it verbatim):\n"
        f"{DELIMITER}\n\n"
        "SECTION 1: Detailed Analysis\n"
        "If step 1 is no: only justify step 1 and note that steps 2-4 are skipped (N/A on Android).\n"
        "If step 1 is yes: follow steps 2-4 with brief justification.\n\n"
        "SECTION 2: Concise Summary\n"
        "Provide ONLY a valid JSON object with **exactly three** keys after the delimiter "
        "(no markdown code fences in SECTION 2).\n"
        "When supports_android is false, example shape:\n"
        '  {"supports_android": false, "has_api_credential": "*", "credential_name": null}\n'
        "When supports_android is true, example shape:\n"
        "{\n"
        '  "supports_android": true,\n'
        '  "has_api_credential": true or false,\n'
        '  "credential_name": "short name only if has_api_credential is true, else null"\n'
        "}\n"
    )

def run_qa(
    client: OpenAI,
    model: str,
    sdk_name: str,
    vendor: str,
    logger: logging.Logger | None = None,
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY_SECONDS,
) -> tuple[str | None, str | None, dict]:
    prompt = build_prompt(sdk_name, vendor)
    msg = f"Querying model={model!r} SDK={sdk_name!r} vendor={vendor!r}"
    if logger:
        logger.info(msg)
    else:
        print(f"[*] {msg}")

    max_retries = max(1, max_retries)
    total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    last_detailed: str | None = None

    for attempt in range(1, max_retries + 1):
        if logger:
            logger.info(
                "LLM request attempt %s/%s (timeout %.1fs)",
                attempt,
                max_retries,
                request_timeout,
            )
        try:
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You analyze mobile SDK integration requirements using the user's definition and "
                            "step-by-step method. Output JSON with exactly three keys: supports_android, "
                            "has_api_credential, credential_name. If supports_android is false, use \"*\" for "
                            "has_api_credential and null for credential_name; do not evaluate credential further."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
                temperature=0.1,
                timeout=request_timeout,
            )
            usage = _log_usage(logger, completion)
            for key in total_usage:
                total_usage[key] += usage.get(key, 0)

            response = extract_completion_text(completion, logger=logger)
            if not response or not response.strip():
                raise RuntimeError("empty model response")

            detailed, concise = split_llm_response(response, logger=logger)
            if detailed:
                last_detailed = detailed
            if concise is not None:
                return detailed, concise, total_usage

            msg = "No valid summary JSON in model response (missing delimiter or three-key JSON)."
            if logger:
                logger.warning(msg)
            else:
                print(f"[-] {msg}")
        except Exception as exc:
            msg = f"LLM error on attempt {attempt}/{max_retries}: {exc}"
            if logger:
                logger.warning(msg)
            else:
                print(f"[-] {msg}")

        if attempt < max_retries:
            delay = retry_delay * (2 ** (attempt - 1))
            if logger:
                logger.info("Retrying after %.1fs...", delay)
            time.sleep(delay)

    return last_detailed, None, total_usage


def backfill_rslt_from_full(results_dir: Path, logger: logging.Logger | None = None) -> int:
    """Write missing *_doc_direct_rslt.txt by parsing existing *_doc_direct_full.txt."""
    results_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for full_path in sorted(results_dir.glob("*_doc_direct_full.txt")):
        rank = full_path.name.split("_", 1)[0]
        rslt_path = results_dir / f"{rank}_doc_direct_rslt.txt"
        if rslt_path.exists():
            continue
        raw = full_path.read_text(encoding="utf-8")
        _detailed, concise = split_llm_response(raw, logger=logger)
        if not concise:
            msg = f"[-] {rank}: cannot parse summary JSON from {full_path.name}"
            if logger:
                logger.warning(msg)
            else:
                print(msg)
            continue
        rslt_path.write_text(concise, encoding="utf-8")
        written += 1
        msg = f"[+] {rank}: wrote {rslt_path.name}"
        if logger:
            logger.info(msg)
        else:
            print(msg)
    summary = f"[*] Backfill complete: {written} rslt file(s) created under {results_dir}"
    if logger:
        logger.info(summary)
    else:
        print(summary)
    return 0 if written > 0 or not list(results_dir.glob("*_doc_direct_full.txt")) else 1


def build_doc_direct_summary(root: Path, results_dir: Path) -> int:
    script = root / "doc_direct_analyze_rslts" / "build_doc_direct_summary.py"
    if not script.exists():
        print(f"[-] Summary builder not found: {script}")
        return 1
    cmd = [
        sys.executable,
        str(script),
        "--dir",
        str(results_dir),
        "--output",
        str(results_dir / "doc_direct_summary.csv"),
    ]
    completed = subprocess.run(cmd, cwd=str(root), text=True)
    return int(completed.returncode)


def main() -> int:
    root = Path(__file__).resolve().parent
    os.chdir(root)

    if len(sys.argv) > 1 and sys.argv[1] in ("--backfill-rslt", "backfill-rslt"):
        cfg = configparser.ConfigParser()
        config_path = root / "config.ini"
        results_dir = root / "doc_direct_analyze_rslts"
        if config_path.exists():
            cfg.read(config_path, encoding="utf-8")
            rel = cfg.get(
                "DOC_DIRECT_ANALYZER",
                "DocDirectAna_RESULTS_DIR",
                fallback="doc_direct_analyze_rslts",
            ).strip()
            results_dir = Path(rel)
            if not results_dir.is_absolute():
                results_dir = root / results_dir
        return backfill_rslt_from_full(results_dir)

    config_path = root / "config.ini"
    if not config_path.exists():
        print(f"[-] Missing {config_path}")
        return 1

    cfg = configparser.ConfigParser()
    cfg.read(config_path, encoding="utf-8")

    try:
        api_key = cfg.get("API", "API_KEY")
        base_url = cfg.get("API", "BASE_URL")
        model_name = cfg.get("API", "MODEL_NAME")
        sdk_id_spec = cfg.get("DOC_DIRECT_ANALYZER", "DocDirectAna_SDK_ID").strip()
        results_rel = cfg.get(
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_RESULTS_DIR",
            fallback="doc_direct_analyze_rslts",
        ).strip()
        sdklist_rel = cfg.get(
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_SDKLIST_PATH",
            fallback="",
        ).strip()
        logs_root_rel = cfg.get(
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_LOGS_DIR",
            fallback=DOC_DIRECT_ANALYZE_LOG_DIR,
        ).strip()
        request_timeout = _cfg_float(
            cfg,
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_REQUEST_TIMEOUT_SECONDS",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )
        max_retries = _cfg_int(
            cfg,
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_MAX_RETRIES",
            DEFAULT_MAX_RETRIES,
        )
        retry_delay = _cfg_float(
            cfg,
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_RETRY_DELAY_SECONDS",
            DEFAULT_RETRY_DELAY_SECONDS,
        )
        skip_existing = _cfg_bool(
            cfg,
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_SKIP_EXISTING",
            True,
        )
        auto_summary = _cfg_bool(
            cfg,
            "DOC_DIRECT_ANALYZER",
            "DocDirectAna_AUTO_SUMMARY",
            True,
        )
    except (configparser.NoOptionError, configparser.NoSectionError) as exc:
        print(f"[-] Config error: {exc}")
        return 1

    if len(sys.argv) > 1:
        sdk_id_spec = sys.argv[1].strip()
    if not sdk_id_spec:
        print("[-] Set [DOC_DIRECT_ANALYZER] DocDirectAna_SDK_ID or pass rank/range as argv.")
        return 1

    if not sdklist_rel:
        sdklist_rel = cfg.get("DOC_COLLECTER", "SDKLIST_PATH", fallback="SDKList.csv").strip()

    csv_path = Path(sdklist_rel)
    if not csv_path.is_absolute():
        csv_path = root / csv_path
    if not csv_path.exists():
        print(f"[-] SDK list not found: {csv_path}")
        return 1

    logs_root = Path(logs_root_rel)
    if not logs_root.is_absolute():
        logs_root = root / logs_root
    logs_root.mkdir(parents=True, exist_ok=True)

    rows = load_sdk_rows(csv_path)
    sdk_ids_to_process = parse_sdk_ids(sdk_id_spec)
    if not sdk_ids_to_process:
        print("[-] No SDK IDs after parsing DocDirectAna_SDK_ID / argv.")
        return 1

    results_dir = Path(results_rel)
    if not results_dir.is_absolute():
        results_dir = root / results_dir
    results_dir.mkdir(parents=True, exist_ok=True)

    client = OpenAI(api_key=api_key, base_url=base_url)
    exit_code = 0
    run_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    for rank in sdk_ids_to_process:
        sdk_logger = setup_sdk_doc_direct_analyze_logger(rank, str(logs_root))
        row = rows.get(rank)
        if not row:
            sdk_logger.warning("Rank %s not found in %s; skipped.", rank, csv_path)
            exit_code = 1
            continue
        sdk_name, vendor = row
        sdk_logger.info(
            "Run start: SDK_ID=%s SDK=%s vendor=%s results_dir=%s model=%s",
            rank,
            sdk_name,
            vendor,
            results_dir,
            model_name,
        )
        sdk_logger.info(
            "Request settings: timeout=%.1fs max_retries=%s retry_delay=%.1fs skip_existing=%s",
            request_timeout,
            max_retries,
            retry_delay,
            skip_existing,
        )

        rslt_path = results_dir / f"{rank}_doc_direct_rslt.txt"
        if skip_existing and is_valid_summary_file(rslt_path):
            sdk_logger.info("Existing valid result found at %s; skipped.", rslt_path)
            sdk_logger.info("SDK log saved to: %s", logs_root / f"{rank}-doc_direct_analyze.log")
            continue

        detailed, concise, usage = run_qa(
            client,
            model_name,
            sdk_name,
            vendor,
            logger=sdk_logger,
            request_timeout=request_timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )
        for k in run_usage:
            run_usage[k] += usage.get(k, 0)

        if detailed:
            full_path = results_dir / f"{rank}_doc_direct_full.txt"
            full_path.write_text(detailed, encoding="utf-8")
            sdk_logger.info("Detailed answer saved to %s", full_path)
            sdk_logger.info("=== Detailed ===\n%s", detailed)
        elif concise:
            sdk_logger.info("Model returned JSON only (no separate analysis section).")
        else:
            sdk_logger.warning("Analysis failed: no detailed text and no summary JSON.")
            exit_code = 1
        if concise:
            rslt_path.write_text(concise, encoding="utf-8")
            sdk_logger.info("JSON summary saved to %s", rslt_path)
            sdk_logger.info("=== Concise Summary ===\n%s", concise)
        else:
            sdk_logger.warning(
                "No %s_doc_direct_rslt.txt written: could not parse summary JSON.",
                rank,
            )
            exit_code = 1
        sdk_logger.info("SDK log saved to: %s", logs_root / f"{rank}-doc_direct_analyze.log")

    print(
        f"[*] Run complete. Logs: {logs_root} | "
        f"LLM token usage total: prompt={run_usage['prompt_tokens']}, "
        f"completion={run_usage['completion_tokens']}, total={run_usage['total_tokens']}"
    )
    if auto_summary:
        summary_code = build_doc_direct_summary(root, results_dir)
        if summary_code != 0:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
