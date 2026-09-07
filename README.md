# TWRP Recovery Builder 2024 — Samsung SM-J720F / j7duolte

Build and provenance repository for the hardware-qualified unofficial
TWRP 3.3.0-0 recovery for Samsung Galaxy J7 Duo SM-J720F (`j7duolte`).

## Qualified release

Release tag:

`j7duolte-twrp-3.3.0-0-unofficial-r1`

Exact functional builder commit:

`4e2f5051f72a2feeecdc49a634a25484fc1063a9`

Exact device-tree commit:

`86cce8693b77cf79850a3e97d081dbdf8bc63936`

GitHub Actions run:

`34086555239`

Device tree:

https://github.com/stefan-qq/android_device_samsung_j7duolte

## Pinned source revisions

```text
TWRP:
b1a7ae9cd98e6ac3377d1fecc1341b9643a4f15b

system/core:
274f5e70d16b80fb6d464aeed3294695fb34fb43

bionic:
cb0033e69dd22cb42f7a2d6d87cb38ba45cca7da
```

## Exact release artifacts

```text
Actions artifact ZIP
fb57de09b701b91732dff151e28716e7d827ec9990ddd6adab8a1868638ba4d3

recovery.img
deaba0394c093f2a628ac54a0f6f05792a337c9a69c831ecc12b2112eb97b199

recovery.tar
0f9b616499cfbf495f4c9b3dae83faf21be1f91879d1122cdca2416f237977d8
```

The build audit for this release completed with no reported errors or
warnings and identified the image as a release candidate.

## Release provenance

The release tag identifies the exact binary-producing source state.

Later documentation-only commits may exist after the tag. They do not
change the qualified recovery binary and do not require the recovery to
be rebuilt.

The authoritative binary identity is the release artifact hashes above,
together with the tagged builder and device-tree commits.

## Important implementation properties

The qualified build preserves:

- Android 7.1 native FunctionFS adbd
- parent adbd USB architecture
- recovery-domain command children
- permanent `ffs.adb`
- MTP + ADB coexistence
- Samsung stock-order ConfigFS behavior
- sideload minadbd handoff
- MMS438 boot-self-test suppression
- RTC build-floor handling
- adbd credential-preservation kernel patch
- narrow modern non-text `storage.xml` guard

Development tracing, broad permissive SELinux workarounds and speculative
crypto hacks are not part of the release.

## Historical development branches

Earlier USB, FunctionFS, SELinux and trace branches remain available in
Git history for engineering provenance.

They are historical development states and should not be used as the
public release source.

For the public binary, use:

`j7duolte-twrp-3.3.0-0-unofficial-r1`
