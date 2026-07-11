# Released App Sources

This directory contains source code for the paired legitimate and attacker apps
used by APICredCheck.

The legitimate source directories are named `<SDK_ID>-<SDK_NAME>`.
The paired attacker source directories are named
`<SDK_ID>-<SDK_NAME>-attacker`.

All effective API credentials have been removed for release.
Legitimate app credentials are represented with all-zero placeholders, while
attacker app credentials are represented with all-one placeholders.

The released legitimate sources therefore cannot be compiled into APKs that
successfully call SDK APIs requiring valid provider-issued credentials unless
you first request your own credentials from the corresponding SDK providers and
insert them into the source projects.
Do not commit or publish real credentials after replacing the placeholders.
