# SM-J720F TWRP 3.3 builder

This branch builds the proven Android 7.1 donor-era TWRP 3.3 userspace with the
exact SM-J720F Android 10 CUL1 kernel and DT.

## Direct legacy ADB workflow

Run `.github/workflows/TWRP-3.3-J720F.yml` with:

```text
DEVICE_TREE=https://github.com/stefan-qq/android_device_samsung_j7duolte
DEVICE_TREE_BRANCH=twrp-3.3-legacy-adb
PUBLISH_RELEASE=false
```

The enforcing-policy build fixed the TWRP terminal, runtime FIFOs, PTY access,
TWRP properties, safe diagnostics, and ConfigFS creation. Runtime evidence then
showed that FunctionFS never mounted, so `ep0` never appeared and Android 7.1
adbd could not publish `sys.usb.ffs.ready=1`.

The uploaded hybrid recovery uses the same kernel and DT and was observed by the
host when init created the direct ConfigFS `adb.0` function. This workflow keeps
the working TWRP userspace but reproduces that transport deliberately:

- no FunctionFS mount or `ffs.adb` link;
- init creates and links `functions/adb.0`;
- init binds `13600000.dwc3` before starting adbd;
- the pinned Android 7.1 adbd selects its `/dev/android_adb` transport because
  `/dev/usb-ffs/adb/ep0` is absent.

The build verifies that init and adbd are not permissive, records all permissive
domains instead of hiding them, checks both legacy and FunctionFS transport
strings in the adbd binary, and audits the exact stock kernel/DT, Samsung
trailer, writable ORS FIFOs, safe diagnostic service, and microSD layout.

MTP remains excluded for this isolated transport test. It will be enabled only
after the phone enumerates with this direct ADB route, so a second USB function
cannot obscure the result. Existing Android 10 userdata remains encrypted and
is not formatted by this build.
