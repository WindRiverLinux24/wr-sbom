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

from scancode.api import get_licenses
from scancode.api import get_copyrights
from scancode.api import get_file_info
from licensedcode.detection import get_matches_from_detection_mappings

from license_expression import Licensing
from licensedcode import cache
from spdx_tools.spdx.model import ExtractedLicensingInfo

FORMAT = ("%(asctime)s: %(message)s")
logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, format=FORMAT)

begin = time()


def _parse_filetype(location):
    fileinfo = get_file_info(location)
    logger.debug(f"{location} {fileinfo}")

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

def _parse_licenses(licensing, licenses, license_detections):
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

# Fucntion: scan licenses from location
# Input: "file_path"
# Return: list ["licensceA", "licenseB"],
# Return: list [{'licenseId': <spdx_id>,
#                'extractedText': <text>,
#                'name': <name>,
#                'comment': comment
#               }]
def scan_licenses(location, licensing, licenses):
    ret_licenses = get_licenses(
        location=location,
    )

    file_license_detections = ret_licenses.get('license_detections')
    spdx_licenses, extracted_licensing_info = _parse_licenses(licensing, licenses, file_license_detections)

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

# Fucntion: scan copy rights from location
# Input: "file_path"
# Return: string "CopyrightA\nCopyrightB\nCopyrightC\n"
def scan_copyrights(location):
    ret_copyrights = get_copyrights(
        location=location,
    )
    file_copyrights = ret_copyrights.get('copyrights')
    return _parse_copyrights(file_copyrights)

def scan_checksum_sha256(location):
    ret_info = get_file_info(location)

    logger.debug(f"sha256 {ret_info.get('sha256')}")
    return ret_info.get('sha256')

BUF_SIZE = 65536
def sha256sum(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()

def update_from_cache(spdx_json_cache, scancode_data, ignores=[], ignore_basename=[], no_binary=False):
    if spdx_json_cache and os.path.exists(spdx_json_cache):
        with open(spdx_json_cache) as f:
            scancode_cache = json.load(f)

        for filename in scancode_data:
            if os.path.basename(filename) in ignore_basename:
                logger.info(f"Drop {filename} because of --ignore-basename {os.path.basename(filename)}")
                ignores.append(filename)
                continue

            fileinfo_cache = scancode_cache.get(filename, None)
            if fileinfo_cache is None:
                logger.info(f"Not found {filename} in cache")
                continue

            if no_binary and "BINARY" in fileinfo_cache.get("fileTypes", []):
                logger.info(f"Drop binary {filename} because of --no-binary")
                ignores.append(filename)
                continue

            # Use cache to update if checksum has no change
            if fileinfo_cache.get("SHA256") == sha256sum(filename):
                scancode_data[filename] = fileinfo_cache
                scancode_data[filename]["status"] = "done"
                logger.debug(f"{filename}  {scancode_data[filename]}")
            else:
                scancode_data[filename]["status"] = "undo"
                logger.info(f"{filename} has changed")

        # Remove ignore files from data
        for filename in ignores:
            if filename in scancode_data:
                logger.info(f"Ignore {filename}")
                del scancode_data[filename]

    return

# Scan undo location from scancode_data and fill scan result
# to scancode_data
def scan_undo(scancode_data):
    total_undo = len([key for key,value in scancode_data.items() if value.get("status") == "undo"])
    logger.info(f"total {len(scancode_data.keys())}, scan undo {total_undo}")
    if total_undo == 0:
        return

    licenses= cache.get_licenses_db()
    licensing = Licensing()

    count = 1
    for location in scancode_data:
        if not os.path.exists(location):
            logger.error(f"Source file {location} not found")
            continue

        if scancode_data[location].get("status") == "done":
            logger.debug(f"Skip {location}: {scancode_data[location]}")
            continue

        sha256 = scan_checksum_sha256(location)
        if sha256 is None:
            logger.info(f"Drop {location} by scancode, no valid sha256")
            continue

        start = time()
        logger.info(f"{location} {count}/{total_undo}")
        spdx_licenses, extracted_licensing_info = scan_licenses(location, licensing, licenses)
        scancode_data[location] = {
            "licenseInfoInFiles": spdx_licenses,
            "copyrightText": scan_copyrights(location),
            "hasExtractedLicensingInfos": extracted_licensing_info,
            "SHA256": sha256,
            "fileTypes": _parse_filetype(location),
            "status": "done",
        }
        count += 1
        logger.info(f"{location} {time()-start} done")

    return

def main():
    parser = argparse.ArgumentParser(description='Update SPDX Json from cache or scan. Set license and copyrihts to source file')
    parser.add_argument('--spdx-json', dest='spdx_json', required=True,
        help='The SPDX Json to be updated')

    parser.add_argument('--spdx-json-cache', dest='spdx_json_cache', default=None,
        help='The SPDX Cache, if source file has no change, use cache other than scan for the source file')

    parser.add_argument('--ignore', dest='ignore', default=[], action='append',
        help='Ignore source file to update, repeat --ignore=<file> for multiple files')

    parser.add_argument('--ignore-basename', dest='ignore_basename', default=[], action='append',
        help='Ignore source file with basename <ignore_basename>, repeat --ignore-basename=<file> for multiple files')

    parser.add_argument("--no-binary", help = "Ignore binary in source file", action="store_true", default=False)

    parser.add_argument('-d', '--debug',
                        help = "Enable debug output",
                        action='store_const', const=logging.DEBUG, dest='loglevel', default=logging.INFO)
    args = parser.parse_args()
    logger.setLevel(args.loglevel)
    if not os.path.exists(args.spdx_json):
        logger.error(f"Json file {args.spdx_json} not found")

    with open(args.spdx_json) as f:
        scancode_data = json.load(f)

    update_from_cache(args.spdx_json_cache,
                     scancode_data,
                     args.ignore,
                     args.ignore_basename, 
                     args.no_binary)

    scan_undo(scancode_data)

    logger.debug(f"scancode_data {scancode_data}")
    logger.info(f"Total {time()-begin} done")
    with open(args.spdx_json, "w") as f:
        json.dump(scancode_data, f, indent=2)

if __name__ == "__main__":
    try:
        ret = main()
    except Exception:
        ret = 1
        import traceback
        traceback.print_exc()
    sys.exit(ret)
