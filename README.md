# TWRP 3.3.0-0 build harness for Samsung SM-J720F

Reproducible build and provenance tooling for the unofficial TWRP 3.3.0-0 release for Samsung Galaxy J7 Duo SM-J720F (`j7duolte`).

The public device tree and recovery release are maintained at:

https://github.com/stefan-qq/android_device_samsung_j7duolte

## Why this repository exists

This repository started as a fork of:

https://github.com/kinguser981/TWRP-Recovery-Builder-2024

That project is designed to be forked and run through GitHub Actions. For the SM-J720F work, the workflow was extended into a device-specific build and provenance harness.

A normal Android/TWRP build can be done locally with the usual `repo`, `envsetup`, `lunch` and `mka recoveryimage` flow. The published SM-J720F binary, however, depends on a specific legacy source combination and a set of narrowly scoped device fixes. Reproducing that exact binary therefore requires more than pointing a generic builder at the device tree.

This fork records and validates:

- the exact TWRP source revision
- the exact `system/core` and `bionic` revisions
- the resolved donor-era manifest
- the exact device-tree revision used by the build
- the J720F-specific source patches
- Samsung recovery image assembly and trailer handling
- build-time checks for USB, ADB, MTP, sideload, SELinux policy and recovery layout
- final image size, hashes and audit metadata

The repository is a build harness, not a separate fork of TWRP itself.

## Current branch

The maintained branch is:

`twrp-3.3`


The release tag is:

`j7duolte-twrp-3.3.0-0-unofficial-r1`

Documentation and CI housekeeping commits can exist after the release tag. The tag remains on the exact source state that produced release r1.

## Release r1 source

```text
Builder:
4e2f5051f72a2feeecdc49a634a25484fc1063a9

Device tree:
86cce8693b77cf79850a3e97d081dbdf8bc63936

TWRP:
b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b

system/core:
274f5e70d16b80fb6d464aeed3294695fb34fb43

bionic:
cb0033e69dd22cb42f7a2d6d87cb38ba45cca7da
```

Release binaries:

```text
recovery.img
deaba0394c093f2a628ac54a0f6f05792a337c9a69c831ecc12b2112eb97b199

recovery.tar
0f9b616499cfbf495f4c9b3dae83faf21be1f91879d1122cdca2416f237977d8
```

Preserved build artifact:

```text
j7duolte-twrp-3.3.0-0-unofficial-r1-build-artifact.zip
SHA256: fb57de09b701b91732dff151e28716e7d827ec9990ddd6adab8a1868638ba4d3
```

The original GitHub Actions run is no longer retained in the Actions history. The released binary and preserved build artifact remain verifiable by the hashes above.

## Workflow

The workflow is:

`.github/workflows/TWRP-3.3-J720F.yml`

The default device tree is:

```text
https://github.com/stefan-qq/android_device_samsung_j7duolte
```

The default device-tree branch is:

```text
twrp-3.3
```

The workflow checks out the pinned recovery source and records the resolved source state used by the build.

## J720F-specific build changes

The release build includes targeted changes for:

- Samsung stock-order ConfigFS and native FunctionFS ADB
- recovery-domain ADB command children
- isolated ADB sync handling
- MTP operation alongside ADB
- sideload handoff and USB recovery
- RTC build-floor handling
- exclusion of the obsolete TWRP App prompt
- raw System Image target support
- safe handling of unsupported non-text `storage.xml`
- two audited recovery-only stock-kernel binary changes

The workflow also contains rejection checks for superseded development approaches so that known-bad configurations are not silently reintroduced.

## Reproducing the release

For release reproduction, start from the release tag and verify every resolved source revision against the values above. The preserved release artifact provides the exact output from the original build.

A build produced from later branch heads is a new build, even if the source differences are only build-system changes.

The released r1 image should always verify as:

```text
deaba0394c093f2a628ac54a0f6f05792a337c9a69c831ecc12b2112eb97b199  recovery.img
0f9b616499cfbf495f4c9b3dae83faf21be1f91879d1122cdca2416f237977d8  recovery.tar
```

## Credits

- TeamWin Recovery Project
- OmniROM and Android Open Source Project contributors
- kinguser981 for the original `TWRP-Recovery-Builder-2024` project

This repository contains unofficial community build tooling and is not affiliated with TeamWin.
