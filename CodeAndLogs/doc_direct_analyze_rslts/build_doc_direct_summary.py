"""
Aggregate doc_direct_analyzer JSON from all *.txt under this folder into one CSV.

Reads ``NNNN_doc_direct_rslt.txt`` (and other ``NNNN_*.txt`` with valid summary JSON).
One row per SDK rank; duplicate ranks prefer ``*_doc_direct_rslt.txt``.

Columns:
  SDK Rank, SDK, supports_android, has_api_credential, credential_name
  (three rightmost columns are the direct-analyzer JSON fields)

When supports_android is false, has_api_credential is written as ``*`` (not applicable on Android);
credential_name is left blank.

Run from repo root:
  python doc_direct_analyze_rslts/build_doc_direct_summary.py
"""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import os
import re
import tempfile
from pathlib import Path


RANK_PREFIX = re.compile(r"^(\d+)_", re.IGNORECASE)
SUMMARY_KEYS = frozenset(
    {
        "supports_android",
        "has_api_credential",
        "credential_name",
    }
)

CSV_COLUMNS = [
    "SDK Rank",
    "SDK",
    "supports_android",
    "has_api_credential",
    "credential_name",
]


def parse_rslt_json(text: str) -> dict | None:
    text = text.strip()
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
            return json.loads(text[start : end + 1])
    return None


def _is_summary_object(data: dict) -> bool:
    return SUMMARY_KEYS.issubset(data.keys())


def _is_false(value) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("false", "0", "no")
    return False


def _row_from_summary(rank: str, sdk_name: str, data: dict) -> dict:
    supports_android = data.get("supports_android")
    credential_name = data.get("credential_name")
    if credential_name is None:
        credential_name = ""
    else:
        credential_name = str(credential_name).strip()

    row = {
        "SDK Rank": rank,
        "SDK": sdk_name,
        "supports_android": supports_android,
        "has_api_credential": data.get("has_api_credential"),
        "credential_name": credential_name,
    }
    if _is_false(supports_android):
        row["has_api_credential"] = "*"
        row["credential_name"] = ""
    return row


def _rank_from_filename(name: str) -> str | None:
    m = RANK_PREFIX.match(name)
    if not m:
        return None
    return f"{int(m.group(1)):04d}"


def _txt_sort_key(path: Path) -> tuple:
    rank = _rank_from_filename(path.name)
    rank_n = int(rank) if rank else 999999
    is_rslt = "_doc_direct_rslt" in path.name.lower()
    return (rank_n, 0 if is_rslt else 1, path.name.lower())


def load_sdk_names(csv_path: Path) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    if not csv_path.exists():
        return rows
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rank = (row.get("SDK Rank") or "").strip()
            name = (row.get("SDK") or "").strip()
            vendor = (row.get("Vendor") or "").strip()
            if rank:
                rows[rank.zfill(4)] = (name, vendor)
    return rows


def resolve_sdklist_path(repo_root: Path) -> Path:
    ini = repo_root / "config.ini"
    if ini.exists():
        cfg = configparser.ConfigParser()
        cfg.read(ini, encoding="utf-8")
        rel = cfg.get("DOC_DIRECT_ANALYZER", "DocDirectAna_SDKLIST_PATH", fallback="").strip()
        if not rel:
            rel = cfg.get("DOC_COLLECTER", "SDKLIST_PATH", fallback="SDKList.csv").strip()
        p = Path(rel)
        return p if p.is_absolute() else repo_root / p
    return repo_root / "SDKList.csv"


def collect_rows(results_dir: Path, sdk_names: dict[str, tuple[str, str]]) -> list[dict]:
    txt_files = sorted(
        (p for p in results_dir.iterdir() if p.is_file() and p.suffix.lower() == ".txt"),
        key=_txt_sort_key,
    )
    by_rank: dict[str, dict] = {}
    skipped_no_rank = 0
    skipped_not_json = 0
    skipped_duplicate = 0

    for path in txt_files:
        rank = _rank_from_filename(path.name)
        if rank is None:
            print(f"[-] Skip {path.name}: filename must start with rank digits (e.g. 0025_...)")
            skipped_no_rank += 1
            continue
        if rank in by_rank:
            skipped_duplicate += 1
            continue

        raw = path.read_text(encoding="utf-8")
        data = parse_rslt_json(raw)
        if data is None or not _is_summary_object(data):
            skipped_not_json += 1
            continue

        sdk_name, _vendor = sdk_names.get(rank, ("", ""))
        by_rank[rank] = _row_from_summary(rank, sdk_name, data)

    if txt_files:
        print(
            f"[*] Scanned {len(txt_files)} .txt file(s); "
            f"included {len(by_rank)} SDK(s); "
            f"skipped {skipped_not_json} without summary JSON, "
            f"{skipped_duplicate} duplicate rank(s), "
            f"{skipped_no_rank} bad filename(s)."
        )
    return [by_rank[r] for r in sorted(by_rank)]


def write_summary_csv(output: Path, rows: list[dict]) -> Path:
    """Write CSV via temp file; on lock, fall back to ``*_new.csv`` with a clear message."""
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        suffix=".csv",
        prefix=".doc_direct_summary_",
        dir=str(output.parent),
    )
    tmp = Path(tmp_path)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        try:
            os.replace(tmp, output)
            return output
        except OSError as exc:
            winerr = getattr(exc, "winerror", None)
            if exc.errno not in (13,) and winerr not in (32, 33):
                raise
            fallback = output.with_name(f"{output.stem}_new{output.suffix}")
            if fallback.exists():
                try:
                    os.remove(fallback)
                except OSError:
                    pass
            os.replace(tmp, fallback)
            tmp = None
            print(
                f"[!] Cannot overwrite (file locked): {output}\n"
                f"    Wrote instead: {fallback}\n"
                f"    Close Excel / IDE preview on doc_direct_summary.csv, then rerun or "
                f"delete the old file and rename {fallback.name}."
            )
            return fallback
    finally:
        if tmp is not None and tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def main() -> int:
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    parser = argparse.ArgumentParser(
        description="Build CSV summary from doc_direct_analyzer rslt files."
    )
    parser.add_argument(
        "-d",
        "--dir",
        type=Path,
        default=here,
        help="Folder containing *_doc_direct_rslt.txt (default: this script's folder)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=here / "doc_direct_summary.csv",
        help="Output CSV path (default: doc_direct_analyze_rslts/doc_direct_summary.csv)",
    )
    args = parser.parse_args()
    results_dir = args.dir.resolve()
    output = args.output.resolve()
    if not output.is_absolute():
        output = repo_root / output

    sdk_names = load_sdk_names(resolve_sdklist_path(repo_root))
    rows = collect_rows(results_dir, sdk_names)
    if not rows:
        print(
            f"[-] No summary JSON found under {results_dir} "
            f"(need NNNN_doc_direct_rslt.txt or other NNNN_*.txt with analyzer JSON)."
        )
        return 1

    written = write_summary_csv(output, rows)
    print(f"[+] Wrote {len(rows)} row(s) to {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
