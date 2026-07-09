This directory contains the APICredCheck implementation, configuration file, execution logs, and intermediate outputs.
All commands below assume that the current working directory is `CodeAndLogs/`.

## Runnable Scripts

- `doc_direct_analyzer.py`: performs SDK Screening over `SDKList.csv`.
- `apk_analyzer.py`: performs Legitimate App Analysis on paired APKs.
- `app_hooker.py`: performs Runtime Validation by installing attacker APKs, generating Frida instrumentation scripts, and observing runtime outcomes.

## Input and Output Directories

- `apks/`: default input directory for legitimate and attacker APK files.
- `doc_direct_analyze_logs/`: logs from SDK Screening.
- `doc_direct_analyze_rslts/`: structured outputs from SDK Screening.
- `apk_analyze_logs/`: logs from Legitimate App Analysis.
- `apk_analyze_reports/`: human-readable Legitimate App Analysis reports.
- `apk_analyze_rslts/`: structured analysis results and profiles consumed by Runtime Validation.
- `app_hook_logs/`: logs from Runtime Validation.
- `app_hook_rslts/`: runtime outcomes, adaptive hook traces, and generated Frida scripts.

## 1. Environment Requirements

APICredCheck is implemented in Python.
The original experiments used Python 3.9.

Install Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

The runtime validation stage additionally requires:

- Android SDK platform tools, especially `adb`.
- Apktool available from the command line.
- A rooted Android device with USB debugging enabled.
- A Frida Python package compatible with the configured `frida-server`.
- A matching `frida-server` binary, such as `frida-server-16.4.10-android-arm64`, placed at the path configured in `config.ini`.

Android Studio and Gradle are needed when rebuilding the legitimate and attacker apps from source.

## 2. Configure `config.ini`

Before running APICredCheck, edit `config.ini`.

In the `[API]` section, replace the redacted LLM key with a valid key:

```ini
[API]
API_KEY = sk-ant-api03-***
BASE_URL = https://api.aicodemirror.com/api/codex/backend-api/codex/v1
MODEL_NAME = gpt-5.4
```

The released file uses `sk-ant-api03-***` as a placeholder.
LLM-assisted SDK screening and auth point inference will fail if this placeholder is not replaced.
Do not commit real keys to the public repository.

The main configuration sections are:

- `[DOC_DIRECT_ANALYZER]`: controls SDK screening over `SDKList.csv`.
- `[APK_ANALYZER]`: controls legitimate APK analysis.
- `[APP_HOOKER]`: controls runtime validation on attacker APKs.

SDK ranges can be specified with comma-separated IDs and ranges, such as `0001,0005,0012-0019`.

## 3. Prepare APK Inputs

APICredCheck expects paired APKs for SDKs that need legitimate app analysis and runtime validation.
Each pair contains:

- a legitimate APK, built with a valid API credential requested from the SDK provider;
- a corresponding attacker APK, built with a different package name, a different signing certificate, and an invalid credential.

For artifact release, real credentials are removed from app source code.
Legitimate app source code uses all-zero credential placeholders, and attacker app source code uses all-one credential placeholders.
To rerun the experiments, request your own API credentials, insert them into the legitimate app projects, rebuild the APKs, and keep the attacker app credential invalid.

Place the APKs in the directory configured by `ApkAna_APK_DIR` and `AppHook_APK_DIR`.
By default, this directory is `apks/`.

APK filenames should follow the naming convention used by the scripts:

```text
0001-GoogleFirebaseSDK-demo.apk
0001-GoogleFirebaseSDK-attacker.apk
```

Here, the four-digit prefix is the SDK rank or ID, `demo` denotes the legitimate APK, and `attacker` denotes the attacker APK.

## 4. Run SDK Screening

SDK screening uses `doc_direct_analyzer.py`.
It reads SDK names and vendors from `SDKList.csv`, queries the configured LLM, and writes structured results.

Run the IDs configured in `config.ini`:

```powershell
python doc_direct_analyzer.py
```

Run a specific SDK or range:

```powershell
python doc_direct_analyzer.py 0001
python doc_direct_analyzer.py 0001-0050
```

Outputs:

- `doc_direct_analyze_logs/`: per-SDK logs.
- `doc_direct_analyze_rslts/`: per-SDK structured outputs.
- `doc_direct_summary.csv` or related summary files, if automatic summary generation is enabled.

## 5. Run Legitimate APK Analysis

Legitimate APK analysis uses `apk_analyzer.py`.
It unpacks and decompiles the legitimate APK, extracts evidence from decompiled code and configuration files, queries the LLM for auth points and replacement safety, and builds the legitimate APK profile used by runtime validation.

Check the `[APK_ANALYZER]` section before running:

```ini
[APK_ANALYZER]
ApkAna_SDK_IDS = 0032
ApkAna_APK_DIR = apks
ApkAna_RESULTS_DIR = apk_analyze_reports
ApkAna_ANALYZE_RESULTS_DIR = apk_analyze_rslts
ApkAna_LOGS_DIR = apk_analyze_logs
ApkAna_DECOMPILE_DIR = decompiled_apks
ApkAna_DECOMPILE = true
ApkAna_USE_LLM = true
```

Run:

```powershell
python apk_analyzer.py --config config.ini
```

Outputs:

- `apk_analyze_logs/`: analysis logs.
- `apk_analyze_reports/`: human-readable reports.
- `apk_analyze_rslts/`: structured analysis results consumed by runtime validation.
- `decompiled_apks/`: decompiled APK files, if decompilation is enabled.

## 6. Run Runtime Validation

Runtime validation uses `app_hooker.py`.
It installs and launches the attacker APK, generates a Frida instrumentation script from the selected hook set and legitimate APK profile, attaches the script to the attacker app process, replaces matched arguments or return values at runtime, and classifies the attempt outcome.

First, connect and authorize the Android device:

```powershell
adb devices
```

Then make sure the configured `frida-server` binary is available.
You can start it explicitly:

```powershell
python frida_server.py --config config.ini
```

Runtime validation can also start `frida-server` automatically if `AppHook_START_FRIDA_SERVER = true`.

Check the `[APP_HOOKER]` section:

```ini
[APP_HOOKER]
AppHook_SDK_IDS = 0001,0005,0012,0017-0019,0022,0023,0028,0032,0036,0037,0047,0049,0050
AppHook_APK_DIR = apks
AppHook_ANALYZE_RESULTS_DIR = apk_analyze_rslts
AppHook_DECOMPILE_DIR = decompiled_apks
AppHook_LOGS_DIR = app_hook_logs
AppHook_RESULTS_DIR = app_hook_rslts
AppHook_INSTALL_ATTACKER = true
AppHook_SPAWN_ATTACKER = true
AppHook_START_FRIDA_SERVER = true
AppHook_FRIDA_SERVER_LOCAL_PATH = frida-server-16.4.10-android-arm64
AppHook_FRIDA_SERVER_REMOTE_PATH = /data/local/tmp/frida-server-16.4.10-android-arm64
AppHook_ADAPTIVE_HOOK_FILTER = true
```

Run:

```powershell
python app_hooker.py --config config.ini
```

Outputs:

- `app_hook_logs/`: runtime validation logs.
- `app_hook_rslts/`: runtime validation results, adaptive hook traces, generated Frida scripts, and final outcomes.

The attacker app reports API invocation states by emitting `APICREDTEST_*` messages through Android logging APIs.
APICredCheck observes these signals with Frida instrumentation and a per-process `adb logcat` fallback monitor.
Each attempt is classified as success, failure, crash, or timeout.

## 7. Result Files

The final release repository also contains a top-level `Results/` directory.
This directory is used to collect summarized results for the paper, including SDK screening results and summarized legitimate app analysis or runtime validation results.

Intermediate outputs remain under `CodeAndLogs/`.
When preparing a public artifact, copy the final summarized CSV or XLSX files from `CodeAndLogs/` into `Results/`.

