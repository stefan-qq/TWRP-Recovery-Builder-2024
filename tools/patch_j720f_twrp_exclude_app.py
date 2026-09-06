#!/usr/bin/env python3
"""Remove the obsolete Official TWRP App path from the pinned J720F TWRP 3.3 UI.

The device tree already sets TW_EXCLUDE_TWRPAPP := true, but the pinned
b1a7ae9 TWRP source predates complete handling of that flag: the APK placeholder
is still defined unconditionally and the portrait reboot flow still enters the
app-check page. This patch makes the flag effective for the APK and removes the
app prompt/settings path from the only theme used by j7duolte (portrait_hdpi).
"""

import argparse
from pathlib import Path

APP_BLOCK = '''#TWRP App "placeholder"
include $(CLEAR_VARS)
LOCAL_MODULE := me.twrp.twrpapp.apk
LOCAL_MODULE_TAGS := eng
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)
'''

APP_BLOCK_PATCHED = '''ifneq ($(TW_EXCLUDE_TWRPAPP), true)
#TWRP App "placeholder"
include $(CLEAR_VARS)
LOCAL_MODULE := me.twrp.twrpapp.apk
LOCAL_MODULE_TAGS := eng
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)
endif
'''

REBOOT_OLD = '''\t\t\t<action>
\t\t\t\t<condition var1="tw_backup_system_size" op="&gt;=" var2="%tw_min_system%"/>
\t\t\t\t<action function="page">appcheck</action>
\t\t\t</action>'''

REBOOT_NEW = '''\t\t\t<action>
\t\t\t\t<condition var1="tw_backup_system_size" op="&gt;=" var2="%tw_min_system%"/>
\t\t\t\t<action function="reboot">%tw_reboot_param%</action>
\t\t\t</action>'''

SETTINGS_ITEM = '''\t\t\t\t<listitem name="{@reboot_install_app_prompt_install=Prompt to install TWRP app on every reboot}">
\t\t\t\t\t<data variable="tw_app_prompt"/>
\t\t\t\t</listitem>
'''


def replace_exact(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one pinned anchor, found {count}")
    return text.replace(old, new, 1)


def verify(recovery: Path) -> None:
    prebuilt = (recovery / "prebuilt/Android.mk").read_text()
    portrait = (recovery / "gui/theme/common/portrait.xml").read_text()

    if APP_BLOCK_PATCHED not in prebuilt:
        raise SystemExit("prebuilt/Android.mk: TWRP App module is not guarded by TW_EXCLUDE_TWRPAPP")
    if prebuilt.count("LOCAL_MODULE := me.twrp.twrpapp.apk") != 1:
        raise SystemExit("prebuilt/Android.mk: unexpected TWRP App module count")

    rebootcheck_start = portrait.index('<page name="rebootcheck">')
    rebootcheck_end = portrait.index('</page>', rebootcheck_start)
    rebootcheck = portrait[rebootcheck_start:rebootcheck_end]
    if '<action function="page">appcheck</action>' in rebootcheck:
        raise SystemExit("portrait.xml: rebootcheck still routes through appcheck")
    if '<action function="reboot">%tw_reboot_param%</action>' not in rebootcheck:
        raise SystemExit("portrait.xml: rebootcheck does not directly reboot when an OS is present")
    if SETTINGS_ITEM in portrait:
        raise SystemExit("portrait.xml: obsolete TWRP App prompt setting is still present")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovery", required=True, help="Path to pinned bootable/recovery checkout")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    recovery = Path(args.recovery)
    prebuilt_path = recovery / "prebuilt/Android.mk"
    portrait_path = recovery / "gui/theme/common/portrait.xml"
    if not prebuilt_path.is_file() or not portrait_path.is_file():
        raise SystemExit("missing pinned TWRP source files")

    if args.verify_only:
        verify(recovery)
        print("Verified J720F TWRP App exclusion and direct reboot flow")
        return

    prebuilt = prebuilt_path.read_text()
    portrait = portrait_path.read_text()

    if APP_BLOCK_PATCHED in prebuilt:
        raise SystemExit("TWRP App exclusion already appears to be applied")

    prebuilt = replace_exact(prebuilt, APP_BLOCK, APP_BLOCK_PATCHED, "prebuilt/Android.mk")
    portrait = replace_exact(portrait, REBOOT_OLD, REBOOT_NEW, "portrait.xml rebootcheck")
    portrait = replace_exact(portrait, SETTINGS_ITEM, "", "portrait.xml app setting")

    prebuilt_path.write_text(prebuilt)
    portrait_path.write_text(portrait)
    verify(recovery)
    print("Excluded Official TWRP App and removed its reboot prompt/settings path")


if __name__ == "__main__":
    main()
