# SM-J720F TWRP 3.3 builder

This branch builds the Android 7.1 donor-era TWRP userspace that produced the
proven v11 display and touch result. It does **not** assemble an Android 10
stock-recovery base.

## RC2.3 diagnostic workflow

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=rc2.3-runtime-diagnostics
PUBLISH_RELEASE=false
```

The workflow pins TWRP recovery commit
`b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b`, verifies the exact stock J720F
kernel and DT, appends the Samsung trailer, enforces the PIT limit, audits the
final ramdisk, and uploads the image plus metadata.

RC2.3 is a non-release diagnostic build. It preserves the RC1 display, touch,
writable microSD, raw EFS/CPEFS backup, MTP exclusion, and uevent fix. It uses
the CUL1 stock-kernel USB handoff, captures pre/post FunctionFS and ConfigFS
state through `/sbin/postrecoveryboot.sh`, and moves TWRP command FIFOs from
read-only rootfs to `/tmp`. Existing `/data` handling is intentionally unchanged
until the diagnostic report is reviewed.
