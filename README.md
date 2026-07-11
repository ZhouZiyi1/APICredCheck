# APICredCheck Artifact

This repository contains the artifact for APICredCheck, an automated framework for evaluating whether API credentials exposed from Android SDK integrations can be abused from unauthorized Android apps.

The artifact is organized into three top-level directories: `Dataset/`, `CodeAndLogs/`, and `Results/`.

## Directory Structure

### Dataset

`Dataset/` contains the data needed for the experiments.
It includes the SDK list used in the study, the released source code of the paired apps, and the released compiled APK files:

- `SDKList.csv`: the ranked SDK list used by APICredCheck.
- `apk_srcs_release/`: source code for all paired legitimate and attacker apps.
- `apks/`: compiled legitimate and attacker APKs corresponding to the released source projects.

In the real experiments, the legitimate apps contained valid API credentials requested by the authors from SDK providers.
For artifact release, these credentials are removed from the released app source code to prevent leakage of author-owned API credentials.
Specifically, credential values in **legitimate app source code** are replaced with **all-zero placeholders**, while credential values in **attacker app source code** are replaced with **all-one placeholders**.

The APKs under `Dataset/apks/` are provided as compiled examples matching the released legitimate and attacker app pairs.
They do **not contain** real, currently effective API credentials.
In particular, the released legitimate APKs should not be expected to successfully invoke SDK APIs that require provider-issued credentials.

To rerun the experiments, users must request their own valid API credentials from the corresponding SDK providers, insert them into the legitimate app projects, rebuild the APKs, and keep the attacker app credentials invalid as required by the experiment design.
Do not commit or publish real API credentials after replacing the placeholders.
See `Dataset/README.md` for the detailed dataset note.

### CodeAndLogs

`CodeAndLogs/` contains the APICredCheck implementation, configuration file, execution logs, and intermediate outputs.

Important files and directories include:

- `config.ini`: configuration options for SDK Screening, Legitimate App Analysis, and Runtime Validation.
  The released LLM API key is redacted; users must replace it with their own valid key before running LLM-assisted steps.
- `SDKList.csv`: the SDK list used by the runnable scripts in this directory.
- `doc_direct_analyzer.py`: performs LLM-assisted SDK Screening over `SDKList.csv`.
- `apk_analyzer.py`: performs Legitimate App Analysis on legitimate APKs.
- `app_hooker.py`: performs Runtime Validation on attacker APKs with Frida-based instrumentation.
- `frida_server.py`: helper script for pushing and starting `frida-server` on a connected Android device.
- `apks/`: default APK input directory for the runnable scripts.
  This directory includes only one legitimate/attacker APK pair as an example, named in the form `0001-GoogleFirebaseSDK-demo.apk` and `0001-GoogleFirebaseSDK-attacker.apk`.
  The full released APK example set is provided under `Dataset/apks/`.
  Released APKs are sample binaries without real effective API credentials; rebuild the legitimate APKs with your own provider-issued credentials before attempting to reproduce successful SDK API calls.
- `doc_direct_analyze_logs/` and `doc_direct_analyze_rslts/`: logs and structured outputs from SDK Screening.
- `apk_analyze_logs/`, `apk_analyze_reports/`, and `apk_analyze_rslts/`: logs, reports, and structured outputs from Legitimate App Analysis.
- `app_hook_logs/` and `app_hook_rslts/`: Runtime Validation logs, outcomes, adaptive hook traces, and generated Frida scripts.

API credentials appearing in released logs and intermediate result files have been redacted.
For example, a Google API key is shown as `AIzaSy*********************************`, where only the prefix is retained and the remaining characters are replaced with `*`.

The summary CSV for SDK Screening, `doc_direct_summary.csv`, is generated under `CodeAndLogs/doc_direct_analyze_rslts/` by running `build_doc_direct_summary.py`.

Detailed running instructions are provided in `CodeAndLogs/README.md`.

### Results

`Results/` contains summarized experimental result spreadsheets used for the paper.

The current result files are:

- `doc_direct_summary.xlsx`: SDK Screening results for the top 1,000 SDKs.
  This file summarizes whether each SDK supports Android and whether it is identified as involving API credentials.
- `validation_rslt.xlsx`: validation results for the top 50 SDKs.
  This file summarizes the top-50 SDK study, including SDK Screening outcomes, Legitimate App Analysis results, Runtime Validation results, and manual inspection results.

See `Results/README.md` for a concise description of these files.

## Security and Ethics Notes

This artifact is intended for defensive security research and reproducibility review.
The released code, logs, and datasets should not contain real API credentials owned by the authors.
Users who rerun the experiments must use their **own developer accounts** and **API credentials**, follow SDK provider terms, and avoid publishing attacker apps or using third-party credentials.

The attacker apps in this artifact are designed only for controlled validation of SDK credential protection mechanisms.
They should not be uploaded to public app stores or used against real applications.
