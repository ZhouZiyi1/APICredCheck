This directory contains the APICredCheck implementation, configuration file, execution logs, and intermediate outputs.
All commands below assume that the current working directory is `CodeAndLogs/`.

## Runnable Scripts

- `doc_direct_analyzer.py`: performs SDK Screening over `SDKList.csv`.
- `apk_analyzer.py`: performs Legitimate App Analysis on legitimate APK.
- `app_hooker.py`: performs Runtime Validation by installing attacker APKs, generating Frida instrumentation scripts, and observing runtime outcomes.

## Input and Output Directories

- `apks/`: default input directory for legitimate and attacker APK files.
  This release directory includes one sample APK pair; the full released APK example set is under `../Dataset/apks/`.
  The released APKs do not contain real effective API credentials and are provided as examples rather than as binaries that can directly reproduce successful SDK API calls.
- `doc_direct_analyze_logs/`: logs from SDK Screening.
- `doc_direct_analyze_rslts/`: structured outputs from SDK Screening.
- `apk_analyze_logs/`: logs from Legitimate App Analysis.
- `apk_analyze_reports/`: human-readable Legitimate App Analysis reports.
- `apk_analyze_rslts/`: structured analysis results and profiles consumed by Runtime Validation.
- `app_hook_logs/`: logs from Runtime Validation.
- `app_hook_rslts/`: runtime outcomes, adaptive hook traces, and generated Frida scripts.

## Credential Redaction

API credentials appearing in released logs and intermediate result files have been redacted.
For example, a Google API key is shown in the form `AIzaSy*********************************`, where only the prefix is retained and the remaining characters are replaced with `*`.

## 1. Environment Requirements

APICredCheck is implemented in Python.
The original experiments used Python 3.9.

Install Python dependencies:

```powershell
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
API_KEY = sk-ant-api03-**************************************************************************************
BASE_URL = https://api.aicodemirror.com/api/codex/backend-api/codex/v1
MODEL_NAME = gpt-5.4
```

The released file uses `sk-ant-api03-***` as a placeholder.
LLM-assisted SDK screening and auth point inference will fail if this placeholder is not replaced.

The main configuration sections are:

- `[DOC_DIRECT_ANALYZER]`: controls SDK screening over `SDKList.csv`.
- `[APK_ANALYZER]`: controls legitimate APK analysis.
- `[APP_HOOKER]`: controls runtime validation on attacker APKs.

## 3. Prepare APK Inputs

APICredCheck expects paired APKs for SDKs that need legitimate app analysis and runtime validation.
For a full rerun of the original experiment design, each pair should contain:

- a legitimate APK, built with a valid API credential requested from the SDK provider;
- a corresponding attacker APK, built with a different package name, a different signing certificate, and an invalid credential.

For artifact release, real credentials are removed from app source code.
Legitimate app source code uses **all-zero credential placeholders**, and attacker app source code uses **all-one credential placeholders**.
The compiled APKs released under `apks/` and `../Dataset/apks/` also do not contain real, currently effective API credentials.
In particular, the released legitimate APKs are not expected to successfully invoke SDK APIs that require valid provider-issued credentials.
To rerun the experiments, request your own API credentials, insert them into the legitimate app projects, rebuild the legitimate APKs, and keep the attacker app credential invalid.

Place the APKs in the directory configured by `ApkAna_APK_DIR` and `AppHook_APK_DIR`.
By default, this directory is `apks/`.
The default `CodeAndLogs/apks/` directory contains only one sample APK pair.
To use the full released APK set as example inputs, point `ApkAna_APK_DIR` and `AppHook_APK_DIR` to `../Dataset/apks/` or copy the desired APK pairs into `CodeAndLogs/apks/`.

APK filenames should follow the naming convention such as:

```text
0001-GoogleFirebaseSDK-demo.apk
0001-GoogleFirebaseSDK-attacker.apk
```

Here, the four-digit prefix is the SDK rank or ID, `demo` denotes the legitimate APK, and `attacker` denotes the attacker APK.
The released `CodeAndLogs/apks/` directory contains only one pair as an example input.
The full released APK example set is provided under `../Dataset/apks/`.
Those released APKs are sanitized examples; successful SDK API calls require rebuilding the legitimate apps with your own valid credentials.

## 4. Run SDK Screening

SDK screening uses `doc_direct_analyzer.py`.
It reads SDK names and vendors from `SDKList.csv`, queries the remote LLM, and writes structured results.

Configure the SDK IDs to be screened in `config.ini`, you can specify a specific SDK or all SDKs within a given range:
```ini
[DOC_DIRECT_ANALYZER]
DocDirectAna_SDK_ID = 0001,0002,0003,0005-0050
DocDirectAna_SDKLIST_PATH = SDKList.csv
DocDirectAna_RESULTS_DIR = doc_direct_analyze_rslts
DocDirectAna_LOGS_DIR = doc_direct_analyze_logs
```

Other configuration options can remain at their existing default values.

Then run:
```powershell
python doc_direct_analyzer.py
```

Outputs:

- `doc_direct_analyze_logs/`: per-SDK logs.
- `doc_direct_analyze_rslts/`: per-SDK structured outputs.
  - `doc_direct_analyze_rslts/doc_direct_summary.csv`: a summary result file generated by running `build_doc_direct_summary.py` under `doc_direct_analyze_rslts`.

## 5. Run Legitimate APK Analysis

Legitimate APK analysis uses `apk_analyzer.py`.
It unpacks and decompiles the legitimate APK, extracts evidence from decompiled code and configuration files, queries the LLM for auth points and replacement safety, and builds the legitimate APK profile used by runtime validation.

Check the `[APK_ANALYZER]` section before running:

```ini
[APK_ANALYZER]
ApkAna_SDK_IDS = 0001,0005,0017-0019
ApkAna_APK_DIR = apks
ApkAna_RESULTS_DIR = apk_analyze_reports
ApkAna_ANALYZE_RESULTS_DIR = apk_analyze_rslts
ApkAna_LOGS_DIR = apk_analyze_logs
ApkAna_DECOMPILE_DIR = decompiled_apks
```

Other configuration options can remain at their existing default values.

Then run:

```powershell
python apk_analyzer.py
```

Outputs:

- `apk_analyze_logs/`: analysis logs.
- `apk_analyze_reports/`: human-readable reports.
- `apk_analyze_rslts/`: structured analysis results consumed by runtime validation.
- `decompiled_apks/`: decompiled APK files, if decompilation is enabled.

## 6. Run Runtime Validation

Runtime validation uses `app_hooker.py`.

First, make sure the Android device is connected and authorized for USB debugging.

Then, check the `[APP_HOOKER]` section:

```ini
[APP_HOOKER]
AppHook_SDK_IDS = 0001,0005,0012,0017-0019,0022,0023,0028,0032,0036,0037,0047,0049,0050
AppHook_APK_DIR = apks
AppHook_ANALYZE_RESULTS_DIR = apk_analyze_rslts
AppHook_DECOMPILE_DIR = decompiled_apks
AppHook_LOGS_DIR = app_hook_logs
AppHook_RESULTS_DIR = app_hook_rslts
AppHook_FRIDA_SERVER_LOCAL_PATH = frida-server-16.4.10-android-arm64
AppHook_FRIDA_SERVER_REMOTE_PATH = /data/local/tmp/frida-server-16.4.10-android-arm64
AppHook_INSTALL_ATTACKER = true
AppHook_SPAWN_ATTACKER = true
AppHook_START_FRIDA_SERVER = true
```

- When `AppHook_START_FRIDA_SERVER = true`, `app_hooker.py` automatically pushes and starts `frida-server` on the connected device before runtime validation; when it is set to `false`, `app_hooker.py` does not push or start `frida-server` again.
- When `AppHook_INSTALL_ATTACKER = true`, `app_hooker.py` reinstalls the corresponding attacker APK from the `apks/` directory onto the test device, replacing any previously installed version; when it is set to `false`, `app_hooker.py` does not reinstall the attacker APK.

Run:

```powershell
python app_hooker.py --config config.ini
```

Outputs:

- `app_hook_logs/`: runtime validation logs.
- `app_hook_rslts/`: runtime validation results, generated Frida scripts, and final outcomes.
