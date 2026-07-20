# TWRP Recovery Builder 2024 — SM-J720F

This branch builds the proven Android 7.1 donor-era TWRP 3.3 userspace with the
exact Samsung J720F Android 10 CUL1 kernel and DT.

## Native FunctionFS adbd-domain build

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=twrp-3.3-native-ffs-adbd-domain
PUBLISH_RELEASE=false
```

The preceding `su`-policy build still produced only FunctionFS `ep0`, left
`sys.usb.ffs.ready=0`, and never bound the UDC. This branch removes
`--root_seclabel=u:r:su:s0`, so native adbd remains root UID in
`u:r:adbd:s0`. The workflow validates the final expanded recovery policy, not
just the device source files, and packages the matching adbd USB rules in the
audit directory.

The runtime diagnostic service joins Android's `readproc` group and records
the actual adbd PID, context, wait channel, and file descriptors despite the
recovery `/proc` mount using `hidepid=2`. MTP remains excluded until ADB is
proven.
