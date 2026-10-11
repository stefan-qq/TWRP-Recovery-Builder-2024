# TWRP 3.3.0-0 build tooling for Samsung Galaxy J7 Duo SM-J720F

Project-specific GitHub Actions build and audit tooling for the unofficial SM-J720F (`j7duolte`) recovery. User documentation, downloads and hardware reports belong in the [device repository](https://github.com/stefan-qq/android_device_samsung_j7duolte).

This repository builds the J720F recovery from a pinned legacy OmniROM/TWRP source combination, applies the recorded device fixes, and packages the Samsung recovery image. It is not a supported general-purpose builder for arbitrary devices and is not affiliated with Team Win or Samsung.

The maintained branch is `twrp-3.3`. The published baseline is **j7duolte-twrp-3.3.0-0-unofficial-r1**.

## Frozen release source

The release tag exists in both repositories and identifies the functional source used for the published image:

| Component | Release commit |
| --- | --- |
| Builder | [4e2f5051f72a2feeecdc49a634a25484fc1063a9](https://github.com/stefan-qq/TWRP-Recovery-Builder-2024/commit/4e2f5051f72a2feeecdc49a634a25484fc1063a9) |
| Device tree | [86cce8693b77cf79850a3e97d081dbdf8bc63936](https://github.com/stefan-qq/android_device_samsung_j7duolte/commit/86cce8693b77cf79850a3e97d081dbdf8bc63936) |
| OmniROM TWRP recovery | [b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b](https://github.com/omnirom/android_bootable_recovery/commit/b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b) |
| OmniROM system/core | [274f5e70d16b80fb6d464aeed3294695fb34fb43](https://github.com/omnirom/android_system_core_old/commit/274f5e70d16b80fb6d464aeed3294695fb34fb43) |
| OmniROM bionic | [cb0033e69dd22cb42f7a2d6d87cb38ba45cca7da](https://github.com/omnirom/android_bionic/commit/cb0033e69dd22cb42f7a2d6d87cb38ba45cca7da) |

Later README changes do not become the source of the existing release. A post-release workflow change updated the default device-tree branch to `twrp-3.3`; it did not rebuild or replace the published image.

## Build path and metadata

The build runs through [TWRP-3.3-J720F.yml](.github/workflows/TWRP-3.3-J720F.yml) on an Ubuntu 22.04 runner. The default device repository is `stefan-qq/android_device_samsung_j7duolte`, branch `twrp-3.3`.

The workflow starts from [minimal-manifest-twrp](https://github.com/minimal-manifest-twrp/platform_manifest_twrp_omni), branch `twrp-7.1`, and records the resolved donor source graph. It then pins the recovery source and checks the critical system/core and bionic revisions against the release values. The manifest describes the donor graph; read it alongside the explicit source pins and patch reports to identify the actual build inputs.

The preserved artifact contains:

| File or directory | Purpose |
| --- | --- |
| `build-metadata.txt` | Actual source commits, device-tree input and build options |
| `recovery-audit/resolved-manifest.xml` | Donor manifest resolved to commit IDs |
| `recovery-audit/resolved-manifest.sha256` | Integrity check for that manifest |
| `recovery-audit/audit.json` | Image layout, size, hashes and audit results |
| `recovery-audit/*patch*` | Applied source changes and patch reports |
| `recovery-audit/sepolicy-*.txt` | Policy domains and relevant access rules |
| `SHA256SUMS.txt` | Image and tar checksums |

The release's resolved manifest SHA256 is:

```text
73be410af98d48fa09e59144fab874ca692abfa5f187bf3b729b26f17fcea06e
```

## Device fixes and audit

The release path includes stock-order Samsung ConfigFS, native FunctionFS ADB, targeted recovery command-child and sync handling, MTP alongside ADB, sideload handoff, RTC build-floor handling, exclusion of the obsolete TWRP App, raw System Image support and the non-text `storage.xml` guard.

The CUL1 stock-derived recovery kernel has two recorded recovery-only binary changes: ADB credential preservation and suppression of the automatic MMS438 boot self-test. They do not modify Android BOOT or vendor partitions.

The workflow applies the source patches, finalizes the Samsung recovery trailer and runs the device tree's [image audit](https://github.com/stefan-qq/android_device_samsung_j7duolte/blob/86cce8693b77cf79850a3e97d081dbdf8bc63936/tools/audit_recovery.py). It checks kernel/DT identity and patch bytes, boot-header geometry, ramdisk contents, USB/ADB configuration, policy and image size. Patch reports, policy checks and source metadata are archived with the output.

Static checks do not replace hardware qualification. The [release qualification report](https://github.com/stefan-qq/android_device_samsung_j7duolte/releases/download/j7duolte-twrp-3.3.0-0-unofficial-r1/QUALIFICATION-SUMMARY.txt) records the device tests. Historical scripts and build labels remain intact for provenance; only the workflow's selected release path defines what was used.

## Artifacts and reproduction

Download the existing recovery from the [device release](https://github.com/stefan-qq/android_device_samsung_j7duolte/releases/tag/j7duolte-twrp-3.3.0-0-unofficial-r1). The original Actions build was `34086555239`; its run has expired, but the exact output ZIP is preserved as a release asset.

SHA256:

```text
deaba0394c093f2a628ac54a0f6f05792a337c9a69c831ecc12b2112eb97b199  recovery.img
0f9b616499cfbf495f4c9b3dae83faf21be1f91879d1122cdca2416f237977d8  recovery.tar
fb57de09b701b91732dff151e28716e7d827ec9990ddd6adab8a1868638ba4d3  j7duolte-twrp-3.3.0-0-unofficial-r1-build-artifact.zip
```

For release analysis or reproduction, use the builder and device release tags, the full resolved manifest, explicit source pins and recorded patches. The original workflow used a historical device-branch name; select the release device commit rather than relying on a current branch default.

The donor manifest branch and some external tooling are mutable. Rerunning a workflow against branch heads does not guarantee byte-identical output. Treat any rerun as a new build and compare its metadata, audits and hashes with the preserved artifact before making a release claim. The preserved ZIP is the verifiable record of the original output.

The workflow can upload an Actions artifact and optionally publish a prerelease. Neither action replaces the maintained device release. There is no reason to rebuild it for documentation changes.

## Credits and maintenance

- [Team Win Recovery Project](https://twrp.me/) for TWRP.
- [OmniROM](https://github.com/omnirom/android_bootable_recovery) and the [Android Open Source Project](https://source.android.com/) for the legacy platform sources.
- [minimal-manifest-twrp](https://github.com/minimal-manifest-twrp/platform_manifest_twrp_omni) for the source manifest.
- [Samsung](https://opensource.samsung.com/) for the kernel platform; the release uses stock-derived CUL1 binaries.
- [kinguser981](https://github.com/kinguser981/TWRP-Recovery-Builder-2024) for the original GitHub Actions builder on which this tooling is based.

The initial build and release development are complete. This repository is in maintenance mode; the tested release path remains frozen. Build fixes, documentation improvements and well-scoped pull requests are welcome. Report device/recovery bugs in the [device issue tracker](https://github.com/stefan-qq/android_device_samsung_j7duolte/issues) with reproduction steps and logs. Build reports should also include source commits, workflow inputs and audit output.
