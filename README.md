# SM-J720F TWRP 3.3 builder

This branch builds the proven Android 7.1 donor-era TWRP 3.3 userspace with the
exact SM-J720F Android 10 CUL1 kernel and DT.

## USB and userdata fix workflow

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=twrp-3.3-usb-data-fix
PUBLISH_RELEASE=false
```

The boot-supplied runtime DT property reports `androidboot.selinux=enforcing`,
which wins over the recovery image command line before Android init parses rc
actions. The workflow
therefore patches the recovery-only Android 7.1 init binary so SELinux starts
non-enforcing, then verifies the marker in the final ramdisk.

It also verifies that the compiled recovery policy contains permissive
`init`, `recovery`, and `adbd` domains and that the policy copied into the
recovery ramdisk is the one that was audited. The device tree removes the
incorrect legacy `encryptable=footer` userdata flag, retains the working
microSD setup, and keeps MTP disabled until ADB is proven stable on hardware.
