#!/usr/bin/env python3
import argparse
from pathlib import Path

INCLUDE_OLD = '#include <sys/types.h>\n'
INCLUDE_NEW = '#include <sys/types.h>\n#include <sys/time.h>\n'

FUNCTION_HEADER = '''void TWFunc::Fixup_Time_On_Boot(const string& time_paths /* = "" */)\n{\n'''
MARKER = 'J720F RTC build-floor:'

J720F_BLOCK = r'''    // J720F uses the S2MP PMIC RTC as the kernel hctosys source. Some units can
    // retain a very old but otherwise healthy RTC when Android has not booted to
    // correct it. A recovery image cannot infer exact current time offline, but
    // its own build epoch is a trustworthy lower bound: an installed recovery
    // cannot legitimately be running before it was built. If rtc0 is older than
    // that floor, move CLOCK_REALTIME forward (never backward) and persist the
    // correction to rtc0. Once repaired, normal kernel hctosys handles later
    // recovery boots and this block becomes a no-op.
    static bool j720f_rtc_checked = false;
    if (!j720f_rtc_checked) {
        char build_epoch_prop[PROPERTY_VALUE_MAX] = { 0 };
        property_get("ro.bootimage.build.date.utc", build_epoch_prop, "0");

        errno = 0;
        char* end = NULL;
        unsigned long long build_epoch = strtoull(build_epoch_prop, &end, 10);
        bool build_epoch_valid =
            errno == 0 && end != build_epoch_prop && *end == '\0' && build_epoch > 0;

        uint64_t rtc_epoch = 0;
        const std::string rtc_epoch_path = "/sys/class/rtc/rtc0/since_epoch";
        if (!build_epoch_valid) {
            LOGERR("J720F RTC build-floor: invalid ro.bootimage.build.date.utc '%s'\n",
                build_epoch_prop);
        } else if (TWFunc::read_file(rtc_epoch_path, rtc_epoch) != 0) {
            LOGERR("J720F RTC build-floor: unable to read %s\n", rtc_epoch_path.c_str());
        } else {
            LOGINFO("J720F RTC build-floor: rtc=%llu build=%llu\n",
                (unsigned long long)rtc_epoch, build_epoch);

            if (rtc_epoch < build_epoch) {
                // Preserve a clock that another trusted userspace component already
                // advanced beyond the build floor before this function ran.
                time_t current = time(NULL);
                unsigned long long target_epoch = build_epoch;
                if (current > 0 && (unsigned long long)current > target_epoch)
                    target_epoch = (unsigned long long)current;

                struct timeval tv;
                tv.tv_sec = (time_t)target_epoch;
                tv.tv_usec = 0;
                if (settimeofday(&tv, NULL) != 0) {
                    LOGERR("J720F RTC build-floor: settimeofday(%llu) failed: %s\n",
                        target_epoch, strerror(errno));
                } else {
                    LOGINFO("J720F RTC build-floor: repaired CLOCK_REALTIME to %llu\n",
                        target_epoch);
                    if (TWFunc::Exec_Cmd("/sbin/hwclock -w -u -f /dev/rtc0", false) != 0) {
                        LOGERR("J720F RTC build-floor: failed to persist time to /dev/rtc0\n");
                    } else {
                        uint64_t verify_epoch = 0;
                        if (TWFunc::read_file(rtc_epoch_path, verify_epoch) != 0 ||
                            verify_epoch + 2 < target_epoch) {
                            LOGERR("J720F RTC build-floor: rtc0 verification failed after write\n");
                        } else {
                            LOGINFO("J720F RTC build-floor: persisted rtc0=%llu\n",
                                (unsigned long long)verify_epoch);
                        }
                    }
                }
            } else {
                LOGINFO("J720F RTC build-floor: rtc0 already at or after recovery build epoch\n");
            }
            j720f_rtc_checked = true;
        }
    }
'''


def verify(text: str) -> None:
    if text.count(FUNCTION_HEADER) != 1:
        raise SystemExit('twrp-functions.cpp: expected exactly one Fixup_Time_On_Boot definition')
    required = (
        '#include <sys/time.h>',
        MARKER,
        'property_get("ro.bootimage.build.date.utc", build_epoch_prop, "0");',
        'const std::string rtc_epoch_path = "/sys/class/rtc/rtc0/since_epoch";',
        'if (rtc_epoch < build_epoch) {',
        'if (current > 0 && (unsigned long long)current > target_epoch)',
        'settimeofday(&tv, NULL)',
        'TWFunc::Exec_Cmd("/sbin/hwclock -w -u -f /dev/rtc0", false)',
        'verify_epoch + 2 < target_epoch',
    )
    for needle in required:
        if needle not in text:
            raise SystemExit(f'post-patch verification failed: missing {needle}')
    if text.count(MARKER) < 6:
        raise SystemExit('post-patch verification failed: expected J720F RTC diagnostic strings')

    fn = text.index(FUNCTION_HEADER)
    j7 = text.index('static bool j720f_rtc_checked = false;', fn)
    qcom = text.index('#ifdef QCOM_RTC_FIX', fn)
    if not (fn < j7 < qcom):
        raise SystemExit('post-patch verification failed: J720F clock floor must precede QCOM RTC logic')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--recovery', required=True, help='Path to pinned bootable/recovery checkout')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()

    path = Path(args.recovery) / 'twrp-functions.cpp'
    if not path.is_file():
        raise SystemExit(f'missing pinned TWRP source: {path}')

    text = path.read_text()
    if args.verify_only:
        verify(text)
        print(f'Verified J720F RTC build-time floor correction: {path}')
        return

    if MARKER in text:
        raise SystemExit('J720F RTC build-time floor correction already appears to be applied')
    if text.count(INCLUDE_OLD) != 1:
        raise SystemExit(
            'twrp-functions.cpp: expected exactly one <sys/types.h> include anchor, '
            f'found {text.count(INCLUDE_OLD)}'
        )
    if text.count(FUNCTION_HEADER) != 1:
        raise SystemExit(
            'twrp-functions.cpp: expected exactly one Fixup_Time_On_Boot definition, '
            f'found {text.count(FUNCTION_HEADER)}'
        )

    patched = text.replace(INCLUDE_OLD, INCLUDE_NEW, 1)
    patched = patched.replace(FUNCTION_HEADER, FUNCTION_HEADER + J720F_BLOCK, 1)
    verify(patched)
    path.write_text(patched)
    print(f'Patched J720F RTC build-time floor correction: {path}')


if __name__ == '__main__':
    main()
