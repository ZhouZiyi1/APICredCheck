# Released APKs

This directory contains compiled legitimate and attacker APKs corresponding to
the paired app source projects under `../apk_srcs_release/`.

These APKs are sanitized release examples and do not contain real, currently
effective API credentials. In particular, the legitimate APKs are not expected
to successfully invoke SDK APIs that require valid provider-issued credentials.

To reproduce successful legitimate SDK API calls, request your own credentials
from the SDK providers, insert them into the corresponding legitimate source
projects under `../apk_srcs_release/`, and rebuild the APKs yourself.
Keep the paired attacker APKs configured with invalid credentials and different
Android client identities.
