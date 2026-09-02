#!/usr/bin/env python3
import argparse
from pathlib import Path

INCLUDE_OLD = '#include "MtpDatabase.h"\n'
INCLUDE_NEW = '#include "MtpDatabase.h"\n#include "MtpUtils.h"\n'

FUNCTION_MARKER = 'void MtpStorage::queryNodeProperties(std::vector<MtpStorage::PropEntry>& results, Node* node, uint32_t property, int groupCode, MtpStorageID storageID)\n'

HELPER = r'''static void normalizeDatePropertyForMtp(MtpStorage::PropEntry& pe)
{
	if (pe.property == MTP_PROPERTY_DATE_MODIFIED ||
			pe.property == MTP_PROPERTY_DATE_ADDED) {
		char date[20];
		formatDateTime((time_t)pe.intvalue, date, sizeof(date));
		pe.datatype = MTP_TYPE_STR;
		pe.strvalue = date;
	} else if (pe.property == MTP_PROPERTY_ORIGINAL_RELEASE_DATE) {
		char date[20];
		snprintf(date, sizeof(date), "%04llu0101T000000",
				(unsigned long long)pe.intvalue);
		pe.datatype = MTP_TYPE_STR;
		pe.strvalue = date;
	}
}

'''

ALL_OLD = '''\t\t\tpe.property = mtpprop[i].property;\n\t\t\tpe.datatype = mtpprop[i].dataType;\n\t\t\tpe.intvalue = mtpprop[i].valueInt;\n\t\t\tpe.strvalue = mtpprop[i].valueStr;\n\t\t\tresults.push_back(pe);\n'''
ALL_NEW = '''\t\t\tpe.property = mtpprop[i].property;\n\t\t\tpe.datatype = mtpprop[i].dataType;\n\t\t\tpe.intvalue = mtpprop[i].valueInt;\n\t\t\tpe.strvalue = mtpprop[i].valueStr;\n\t\t\tnormalizeDatePropertyForMtp(pe);\n\t\t\tresults.push_back(pe);\n'''

SINGLE_OLD = '''\t\t\tpe.datatype = prop.dataType;\n\t\t\tpe.intvalue = prop.valueInt;\n\t\t\tpe.strvalue = prop.valueStr;\n\t\t\t// TODO: all the special case stuff in MyMtpDatabase::getObjectPropertyValue is missing here\n'''
SINGLE_NEW = '''\t\t\tpe.datatype = prop.dataType;\n\t\t\tpe.intvalue = prop.valueInt;\n\t\t\tpe.strvalue = prop.valueStr;\n\t\t\tnormalizeDatePropertyForMtp(pe);\n\t\t\t// TODO: all the other special case stuff in MyMtpDatabase::getObjectPropertyValue is missing here\n'''


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected exactly one source match, found {count}')
    return text.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--recovery', required=True, help='Path to bootable/recovery checkout')
    args = parser.parse_args()

    path = Path(args.recovery) / 'mtp/legacy/MtpStorage.cpp'
    if not path.is_file():
        raise SystemExit(f'missing pinned TWRP source: {path}')

    text = path.read_text()
    if 'normalizeDatePropertyForMtp' in text:
        raise SystemExit('MTP date-property correction already appears to be applied')

    text = replace_once(text, INCLUDE_OLD, INCLUDE_NEW, 'MtpUtils include')
    text = replace_once(text, FUNCTION_MARKER, HELPER + FUNCTION_MARKER, 'normalization helper insertion')
    text = replace_once(text, ALL_OLD, ALL_NEW, 'all-properties serialization path')
    text = replace_once(text, SINGLE_OLD, SINGLE_NEW, 'single-property-list serialization path')

    required = (
        '#include "MtpUtils.h"',
        'MTP_PROPERTY_DATE_MODIFIED',
        'MTP_PROPERTY_DATE_ADDED',
        'MTP_PROPERTY_ORIGINAL_RELEASE_DATE',
        'pe.datatype = MTP_TYPE_STR;',
        'normalizeDatePropertyForMtp(pe);',
    )
    for needle in required:
        if needle not in text:
            raise SystemExit(f'post-patch verification failed: {needle}')

    if text.count('normalizeDatePropertyForMtp(pe);') != 2:
        raise SystemExit('post-patch verification failed: expected two normalization calls')

    path.write_text(text)
    print(f'Patched legacy TWRP MTP date-property serialization: {path}')


if __name__ == '__main__':
    main()
