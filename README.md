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

## Trace-readable data diagnostic branch

`twrp-3.3-native-ffs-trace-readable-data` patches only the recovery-policy
copy in the build tree, gives TWRP targeted `/data` access, and labels the
adbd trace files so the recovery collector can read them. It is not a release
branch until USB, ADB, MTP, backup and restore pass hardware testing.

## Forced FunctionFS-entry branch

`twrp-3.3-native-ffs-force-ffs-entry` is based on the first successful readable
trace. adbd entered its event loop and opened the default TCP 5555 transport,
but no `usb_init()` or FunctionFS trace event occurred. The build therefore
instruments `adb/daemon/main.cpp`, bypasses its one-shot ep0 preflight when the
J720F recovery transport marker is present, and forces `usb_init()` to choose
FunctionFS. The existing open thread continues retrying and records exact ep0,
descriptor, endpoint and property results.

## Forced-entry property-read correction

The first forced-entry hardware trace still selected TCP fallback because adbd
read an empty `j720f.usb.transport` value. The device maps the `j720f.` prefix
to `twrp_prop`, but adbd had no read permission for that property area. The
current revision requires `get_prop(adbd, twrp_prop)` in source and in the
expanded compiled policy before packaging the image.

## Root-owned FunctionFS endpoint correction

The forced-entry hardware trace proved that adbd now enters FunctionFS but the
first real `open(ep0, O_RDWR)` fails with `EACCES`. The mounted endpoint was
mode 0600 and owned by `shell:shell`, while this recovery deliberately keeps
adbd as UID/GID 0. The workflow now requires a root-owned FunctionFS mount and
matching root endpoint permissions before it will build or publish an image.

## Samsung stock-order ConfigFS correction

The root-owned endpoint hardware trace showed adbd completing FunctionFS and
publishing `sys.usb.ffs.ready=1`, while both mixed and late-link ConfigFS tests
were rejected with `Config c/1 of g1 needs at least one function`. The exact
CUL1 Samsung recovery creates the `ffs.adb` configuration link before mounting
FunctionFS and keeps it across USB state changes. The workflow now requires
that same order, rejects removal of the link in the `none` action, and binds the
UDC only after native adbd publishes `sys.usb.ffs.ready=1`.
