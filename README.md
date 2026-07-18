# SM-J720F TWRP 3.3 builder

This branch is dedicated to the Samsung Galaxy J7 Duo (`j7duolte`). It builds
the Android 7.1 donor-era TWRP userspace that produced the proven v11 display
and touch result. It does **not** assemble an Android 10 stock-recovery base.

## Workflow

Run:

```text
.github/workflows/TWRP-3.3-J720F.yml
```

Recommended input while testing RC1:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=rc1-v11-functional
PUBLISH_RELEASE=false
```

The workflow pins the recovery source commit used by v11:

```text
b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b
```

It verifies the exact stock J720F kernel and DT, appends the exact Samsung
recovery trailer, enforces the PIT size limit, audits the final ramdisk, and
uploads `recovery.img`, `recovery.tar`, metadata, checksums, and audit output.

## RC1 scope

RC1 targets writable FAT32 microSD, raw EFS/CPEFS backup, ADB-only ConfigFS,
removal of MTP noise, TWRP runtime fstab creation, and uevent reception while
preserving the v11 UI/touch architecture.

Existing Android 10 encrypted `/data` decryption is not claimed. Do not format
`/data` merely to test this build.
