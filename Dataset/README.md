# Dataset

This directory contains the released dataset for APICredCheck.

- `SDKList.csv`: the ranked SDK list used in the study.
- `apk_srcs_release/`: source code for all paired legitimate and attacker apps.
- `apks/`: compiled APK files corresponding to those app pairs.

The `apk_srcs_release/` directory contains both legitimate app source projects
and their paired attacker app source projects.
All effective API credentials have been removed from these released sources.
Legitimate app credentials are replaced with all-zero placeholders, while
attacker app credentials are replaced with all-one placeholders.

The `apks/` directory contains compiled legitimate and attacker APKs as
examples matching the released source projects.
These APKs do not contain real, currently effective API credentials.
In particular, the released legitimate APKs are not expected to successfully
invoke SDK APIs that require valid provider-issued credentials.

To rebuild runnable legitimate APKs for reproduction, request your own API
credentials from the corresponding SDK providers, place them into the
legitimate app source projects, and compile the APKs yourself.
Keep the paired attacker APKs configured with invalid credentials and different
Android client identities, as required by the experiment design.
Do not commit or publish real credentials after replacing the placeholders.
