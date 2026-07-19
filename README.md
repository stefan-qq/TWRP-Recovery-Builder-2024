# SM-J720F TWRP 3.3 builder

This branch builds the Android 7.1 donor-era TWRP userspace that produced the
proven v11 display and touch result. It does **not** assemble an Android 10
stock-recovery base.

## RC2.3.1 safe diagnostic workflow

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=rc2.3.1-safe-diagnostics
PUBLISH_RELEASE=false
```

The workflow pins TWRP recovery commit
`b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b`, verifies the exact stock J720F
kernel and DT, appends the Samsung trailer, enforces the PIT limit, audits the
final ramdisk, and uploads the image plus metadata.

RC2.3.1 is a non-release diagnostic build. It removes the blocking
`postrecoveryboot.sh` experiment and restores the original TWRP ORS FIFO code.
The USB snapshot runs asynchronously as an init service in the recovery domain,
writes its marker to `/tmp` immediately, and never invokes TWRP, mounts a
filesystem, restarts ADB, or changes `/data`.
