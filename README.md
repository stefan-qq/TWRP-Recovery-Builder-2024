# SM-J720F TWRP 3.3 builder

This branch builds the proven Android 7.1 donor-era TWRP 3.3 userspace with the
exact SM-J720F Android 10 CUL1 kernel and DT.

## Enforcing-policy workflow

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=twrp-3.3-enforcing-policy
PUBLISH_RELEASE=false
```

Hardware diagnostics proved that the Samsung stock kernel returns to SELinux
enforcing even when Android init initially selects non-enforcing mode. This
workflow therefore does not patch init or depend on permissive domains. The
device tree supplies explicit ConfigFS, FunctionFS, USB-property, FIFO, PTY,
and TWRP-property rules and the build rejects permissive `init`, `recovery`, or
`adbd` domains in the compiled recovery policy.

The pinned TWRP source is patched only to move its ORS FIFOs from read-only
`/sbin` to writable `/tmp`. The final image audit verifies those embedded paths,
the exact stock kernel/DT, the Samsung trailer, the compiled policy copied into
the ramdisk, the safe nonblocking diagnostic service, and the working microSD
layout.

MTP is deliberately kept out of this one root-cause build because it shares the
same ConfigFS/UDC gadget path as ADB. Once that enforcing-policy path enumerates,
MTP can be enabled in a small isolated follow-up. Existing Android 10 userdata
is encrypted ciphertext and is not formatted by this build.
