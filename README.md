# TWRP Recovery Builder 2024 — SM-J720F

This branch builds the proven Android 7.1 TWRP 3.3 userspace with the exact
Samsung J720F Android 10 CUL1 kernel and DT.

## Direct FunctionFS trace build

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=twrp-3.3-native-ffs-direct-trace
PUBLISH_RELEASE=false
```

The preceding `su`-policy and `adbd`-domain builds both stopped with only
FunctionFS `ep0`, `sys.usb.ffs.ready=0`, and an unbound UDC. This branch does
not make another transport guess. It source-instruments the exact synced
Android 7.1 adbd and records every decisive FunctionFS operation—endpoint
opens, descriptor/string writes, fallback behavior, errno values, property
publication, and transport registration—directly into recovery tmpfs.

The build also redirects native ADB tracing from `/data/adb` to a fixed `/tmp`
file, records the exact `system/core` commit and source diff, verifies the
markers in the final ramdisk binary, and packages all build-side evidence in
`recovery-audit/`. The phone copies the runtime traces automatically to
`/external_sd/J720F_DIRECT_USB_TRACE/`; a one-line manual collector is also
included. MTP remains excluded until ADB is proven.
