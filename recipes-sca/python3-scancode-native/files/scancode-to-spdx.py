#!/usr/bin/env nativepython3
#
# Copyright 2024 Wind River Inc
#
# SPDX-License-Identifier: GPL-2.0-only
#
import argparse
import json
import logging
import sys
import os
import hashlib
from time import time

from licensedcode.detection import get_matches_from_detection_mappings

from license_expression import Licensing
from licensedcode import cache
from spdx_tools.spdx.model import ExtractedLicensingInfo

FORMAT = ("%(asctime)s: %(message)s")
logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, format=FORMAT)

begin = time()


def _parse_licenses(license_detections):
    license_matches = get_matches_from_detection_mappings(license_detections)

    spdx_licenses = []
    extracted_licensing_info = []
    if license_matches:
        all_files_have_no_license = False
        for match in license_matches:
            file_license_expression = match["license_expression"]
            file_license_keys = licensing.license_keys(
                expression=file_license_expression,
                unique=True
            )
            for license_key in file_license_keys:
                file_license = licenses.get(license_key)
                license_key = file_license.key
                spdx_id = file_license.spdx_license_key
                if not spdx_id:
                    spdx_id = f'LicenseRef-scancode-{license_key}'
                is_license_ref = spdx_id.lower().startswith('licenseref-')

                spdx_license = spdx_id
                if is_license_ref:
                    text = match.get('matched_text')
                    # FIXME: replace this with the licensedb URL
                    comment = (
                        f'See details at https://github.com/nexB/scancode-toolkit'
                        f'/blob/develop/src/licensedcode/data/licenses/{license_key}.LICENSE\n'
                    )
                    extracted_license = {
                        'licenseId': spdx_id,
                        # always set some text, even if we did not extract the
                        # matched text
                        'extractedText': text if text else comment,
                        'name': file_license.short_name,
                        'comment': comment
                    }


                    #doc.extracted_licensing_info.append(extracted_license)
                    if extracted_license not in extracted_licensing_info:
                        extracted_licensing_info.append(extracted_license)

                if spdx_license not in spdx_licenses:
                    spdx_licenses.append(spdx_license)

    if not spdx_licenses:
        spdx_licenses = ["NONE"]

    for license_info in spdx_licenses:
        logger.debug("LicenseInfoInFile %s", license_info)
    if extracted_licensing_info:
        logger.debug(f"extracted_licensing_info {extracted_licensing_info}")

    return spdx_licenses, extracted_licensing_info

def _parse_copyrights(file_copyrights):
    file_copyright_text = "NONE"
    if file_copyrights:
        copyrights = []
        for file_copyright in file_copyrights:
            copyright = file_copyright.get('copyright')
            if copyright not in copyrights:
                copyrights.append(copyright)

        # Create a text of copyright statements in the order they appear in
        # the file. Maintaining the order might be useful for provenance
        # purposes.
        file_copyright_text = '\n'.join(copyrights) + '\n'
        logger.debug("copyrights_text: %s" % file_copyright_text)

    return file_copyright_text

def _parse_filetype(fileinfo):
    filetypes = []
    if fileinfo.get("is_binary"):
        filetypes.append("BINARY")
    if fileinfo.get("is_source"):
        filetypes.append("SOURCE")
    if fileinfo.get("is_text"):
        filetypes.append("TEXT")
    if fileinfo.get("is_archive"):
        filetypes.append("ARCHIVE")

    return filetypes

licenses= cache.get_licenses_db()
licensing = Licensing()

def _main_():
    parser = argparse.ArgumentParser(description='Convert Scancode Json to SPDX Json')
    parser.add_argument('--output-spdx-json', dest='output_spdx_json', required=True,
        help='Output SPDX Json file')

    parser.add_argument('--input-scancode-json', dest='input_scancode_json', required=True,
        help='Input Scancode Json file')

    parser.add_argument('-d', '--debug',
                        help = "Enable debug output",
                        action='store_const', const=logging.DEBUG, dest='loglevel', default=logging.INFO)
    args = parser.parse_args()
    logger.setLevel(args.loglevel)

    spdx_json = {}

    if not os.path.exists(args.input_scancode_json):
        logger.error(f"Input Scancode Json file {args.input_scancode_json} not found")
        sys.exit(1)

    with open(args.input_scancode_json) as f:
        scancode_json = json.load(f)

    # Update scancode cache to scancode data if checksum has no change
    for fileinfo in scancode_json.get("files"):
        filename = fileinfo.get("path")
        if fileinfo.get("sha1") is None:
            logger.info(f"Drop {filename} by scancode, no valid sha1")
            continue

        spdx_licenses, extracted_licensing_info = _parse_licenses(fileinfo.get('license_detections'))
        spdx_json[filename] = {
            "licenseInfoInFiles": spdx_licenses,
            "copyrightText": _parse_copyrights(fileinfo.get("copyrights")),
            'hasExtractedLicensingInfos': extracted_licensing_info,
            "SHA1": fileinfo.get("sha1"),
            "fileTypes": _parse_filetype(fileinfo),
        }

    logger.debug(f"spdx_json {spdx_json}")
    logger.info(f"Total {time()-begin} done")
    with open(args.output_spdx_json, "w") as f:
        json.dump(spdx_json, f, indent=2)

def main():
    from scancode import lockfile
    env_spdx_lock = os.getenv('SPDX_LOCK')
    env_spdx_lock_timeout = int(os.getenv('SCANCODE_LOCK_TIMEOUT'))
    if env_spdx_lock and env_spdx_lock_timeout:
        with lockfile.FileLock(env_spdx_lock).locked(timeout=env_spdx_lock_timeout):
            env_spdx_cache = os.getenv('SPDX_JSON_CACHE')
            if env_spdx_cache and os.path.exists(env_spdx_cache):
                print(f"SPDX cache {env_spdx_cache} already exists")
                return 0
            return _main_()
    else:
        print("Failed, please set SCANCODE_LOCK and SCANCODE_LOCK_TIMEOUT")
        return 1


if __name__ == "__main__":
    try:
        ret = main()
    except Exception:
        ret = 1
        import traceback
        traceback.print_exc()
    sys.exit(ret)
