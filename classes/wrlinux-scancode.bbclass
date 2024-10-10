# SPDX-License-Identifier: MIT
# Copyright (C) 2024 Wind River Systems, Inc.
#

SBOM_DEPENS ??= " \
    python3-scancode-native:do_populate_sysroot \
    coreutils-native:do_populate_sysroot \
"
do_create_spdx[depends] += "${SBOM_DEPENS}"

# https://docs.yoctoproject.org/dev/ref-manual/variables.html#term-SPDX_PRETTY
SPDX_PRETTY = "1"

SOURCE_NAME ??= "${BPN}"
PACKAGE_NAME ??= "${PN}"
SOURCE_SPDX_JSON ??= "${SPDXDIR}/spdx-source.json"
PACKAGE_SPDX_JSON ??= "${SPDXDIR}/spdx-package.json"
SCANCODE_JSON_CACHE_DIR ??= "${BB_CACHEDIR}"
SPDX_JSON_CACHE_DIR ??= "${BB_CACHEDIR}"
SOURCE_SCANCODE_JSON_CACHE ??= "${SCANCODE_JSON_CACHE_DIR}/scancode/scancode-source-${SOURCE_NAME}-${PV}.json"
PACKAGE_SCANCODE_JSON_CACHE ??= "${SCANCODE_JSON_CACHE_DIR}/scancode/scancode-package-${PACKAGE_NAME}-${PV}.json"
SOURCE_SPDX_JSON_CACHE ??= "${SPDX_JSON_CACHE_DIR}/spdx/spdx-source-${SOURCE_NAME}-${PV}.json"
PACKAGE_SPDX_JSON_CACHE ??= "${SPDX_JSON_CACHE_DIR}/spdx/spdx-package-${PACKAGE_NAME}-${PV}.json"
# Do not scan files listed in SCANCODE_SOURCE_IGNORES
SCANCODE_SOURCE_IGNORES ??= ""
SCANCODE_PACKAGE_IGNORES ??= ""
# Shadow scan files listed in SCANCODE_SOURCE_SHADOWS
SCANCODE_SOURCE_SHADOWS ??= ""
SCANCODE_PACKAGE_SHADOWS ??= ""
SCANCODE_TIMEOUT ??= "3600"
SCANCODE_PRECOESSES_NUMBER ??= "${BB_NUMBER_THREADS}"
SCANCODE_EXTRA_OPTIONS ??= "--processes ${SCANCODE_PRECOESSES_NUMBER} --max-in-memory -1 --timeout ${SCANCODE_TIMEOUT}"
SCANCODE_MAX_READ_LINES ??= "10240"
SCANCODE_MAX_FILE_SIZE ??= "10240"
SCANCODE_LOCK_TIMEOUT ??= "36000"
SCANCODE_SOURCE_LOCK ??= "${BB_CACHEDIR}/scancode-${SOURCE_NAME}-${PV}.lock"
SCANCODE_PACKAGE_LOCK ??= "${BB_CACHEDIR}/scancode-${PACKAGE_NAME}-${PV}.lock"
SPDX_SOURCE_LOCK ??= "${BB_CACHEDIR}/spdx-${SOURCE_NAME}-${PV}.lock"
SPDX_PACKAGE_LOCK ??= "${BB_CACHEDIR}/spdx-${PACKAGE_NAME}-${PV}.lock"
SCANCODE_POOL_LOCK ??= "${BB_CACHEDIR}/scancode-pool.lock"
SCANCODE_SEMAPHORE ?= "${BB_CACHEDIR}/scancode.semaphore"
SCANCODE_MAX ??= "5"
NO_SCANCODE_JSON_CACHE ??= "0"

def init_spdx(prefix, doc, spdx_json):
    import json
    # data = {
    #   "<fileName>": {
    #     "status": "undo"|"done",
    #     "SHA256": "<checksumValue>"
    #   }
    # }
    data = {}
    for spdx_file in doc.files:
        if "SOURCE" in spdx_file.fileTypes or "BINARY" in spdx_file.fileTypes:
            fileName = os.path.join(prefix,spdx_file.fileName)
            data[fileName] = {"status": "undo"}
            for checksum in spdx_file.checksums:
                if checksum.algorithm == "SHA256":
                    data[fileName]["SHA256"] = checksum.checksumValue

    with open(spdx_json, "w") as f:
        json.dump(data, f, indent=2)

    if len(data) == 0:
        return False

    return True

def update_doc(spdx_json, prefix, doc, spdx_pkg):
    import json
    # spdx_data = {
    #   "<fileName>": {
    #     "status": "undo"|"done",
    #     "SHA256": "<checksumValue>",
    #     "licenseInfoInFiles": ["XXXX"],
    #     "hasExtractedLicensingInfos": [],
    #     "copyrightText": "YYYY",
    #     "fileTypes": "TEXT|SOURCE|BINARY",
    #   }
    # }
    spdx_data = {}
    with open(spdx_json) as f:
        spdx_data = json.load(f)

    licenseInfoFromFiles = []
    copyrightTexts = []
    for spdx_file in doc.files:
        result = spdx_data.get(os.path.join(prefix, spdx_file.fileName), None)
        if result and result.get("status") == "done":
            spdx_file.licenseInfoInFiles = result.get("licenseInfoInFiles", [])
            spdx_file.copyrightText = result.get("copyrightText", "")
            spdx_file.fileTypes = result.get("fileTypes")
            extract_licenses = result.get("hasExtractedLicensingInfos", [])
            for extract_license in extract_licenses:
                extracted_info = oe.spdx.SPDXExtractedLicensingInfo()
                extracted_info.name = extract_license.get("name")
                extracted_info.comment = extract_license.get("comment")
                extracted_info.licenseId = extract_license.get("licenseId")
                extracted_info.extractedText = extract_license.get("extractedText")
                doc.hasExtractedLicensingInfos.append(extracted_info)

            for license in spdx_file.licenseInfoInFiles:
                if license == "NONE" or license in licenseInfoFromFiles:
                    continue
                licenseInfoFromFiles.append(license)

            for copyright in spdx_file.copyrightText.split("\n"):
                if not copyright or copyright == "NONE" or copyright in copyrightTexts:
                    continue
                copyrightTexts.append(copyright)

    spdx_pkg.licenseInfoFromFiles = licenseInfoFromFiles
    if not spdx_pkg.licenseInfoFromFiles:
        spdx_pkg.licenseInfoFromFiles = ["NOASSERTION"]
    spdx_pkg.copyrightText = "\n".join(copyrightTexts)
    if spdx_pkg.copyrightText:
        spdx_pkg.copyrightText += "\n"
    else:
        spdx_pkg.copyrightText = "NOASSERTION"

    return

do_spdx_source_cache() {
    export EXTRACTCODE_LIBARCHIVE_PATH="${STAGING_LIBDIR_NATIVE}/libarchive.so"
    export EXTRACTCODE_7Z_PATH="${STAGING_BINDIR_NATIVE}/7z"
    export TYPECODE_LIBMAGIC_PATH="${STAGING_LIBDIR_NATIVE}/libmagic.so"
    export TYPECODE_LIBMAGIC_DB_PATH="${STAGING_DATADIR_NATIVE}/misc/magic.mgc"
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"
    export SCANCODE_LICENSE_INDEX_CACHE="${TOPDIR}"
    export SCANCODE_CACHE="${TOPDIR}"
    export SCANCODE_LOCK_TIMEOUT="${SCANCODE_LOCK_TIMEOUT}"
    export SCANCODE_LOCK="${SCANCODE_SOURCE_LOCK}"
    export SCANCODE_POOL_LOCK="${SCANCODE_POOL_LOCK}"
    export SCANCODE_SEMAPHORE="${SCANCODE_SEMAPHORE}"
    export SCANCODE_MAX="${SCANCODE_MAX}"
    export SCANCODE_JSON_CACHE="${SOURCE_SCANCODE_JSON_CACHE}"
    export SPDX_JSON_CACHE="${SOURCE_SPDX_JSON_CACHE}"
    export SPDX_LOCK="${SPDX_SOURCE_LOCK}"

    cd ${SPDXWORK}

    # No run if spdx cache is available
    if [ "${NO_SCANCODE_JSON_CACHE}" = "0" ] && [ -e "$SPDX_JSON_CACHE" ]; then
        echo "No run, spdx cache is available"
        exit 0
    fi

    # Generate cache if scancode cache is not available
    if [ "${NO_SCANCODE_JSON_CACHE}" != "0" ] || [ ! -e "$SCANCODE_JSON_CACHE" ]; then
        cmd=""
        # Ignore files for scancode to scan
        for pattern in ${SCANCODE_SOURCE_IGNORES} ${SCANCODE_SOURCE_SHADOWS}; do
            cmd="$cmd --ignore=*/$pattern"
        done

        mkdir -p $(dirname $SCANCODE_JSON_CACHE)

        # Run scancode to generate json
        echo "scancode --strip-root -lci $cmd ${SCANCODE_EXTRA_OPTIONS} --json-pp $SCANCODE_JSON_CACHE ."
        scancode --strip-root -lci $cmd ${SCANCODE_EXTRA_OPTIONS} --json-pp $SCANCODE_JSON_CACHE .
        if [ $? -ne 0 ]; then
            echo "Call scancode failed, ret $?"
            exit 1
        fi
    fi

    # Convert scancode json to spdx json as cache
    mkdir -p $(dirname $SPDX_JSON_CACHE)
    echo "scancode-to-spdx.py --input-scancode-json $SCANCODE_JSON_CACHE --output-spdx-json $SPDX_JSON_CACHE"
    scancode-to-spdx.py --input-scancode-json $SCANCODE_JSON_CACHE --output-spdx-json $SPDX_JSON_CACHE
    if [ $? -ne 0 ]; then
        echo "Call scancode-to-spdx failed, ret $?"
        exit 1
    fi
}

do_spdx_package_cache() {
    export EXTRACTCODE_LIBARCHIVE_PATH="${STAGING_LIBDIR_NATIVE}/libarchive.so"
    export EXTRACTCODE_7Z_PATH="${STAGING_BINDIR_NATIVE}/7z"
    export TYPECODE_LIBMAGIC_PATH="${STAGING_LIBDIR_NATIVE}/libmagic.so"
    export TYPECODE_LIBMAGIC_DB_PATH="${STAGING_DATADIR_NATIVE}/misc/magic.mgc"
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"
    export SCANCODE_LICENSE_INDEX_CACHE="${TOPDIR}"
    export SCANCODE_CACHE="${TOPDIR}"
    export SCANCODE_LOCK_TIMEOUT="${SCANCODE_LOCK_TIMEOUT}"
    export SCANCODE_LOCK="${SCANCODE_PACKAGE_LOCK}"
    export SCANCODE_POOL_LOCK="${SCANCODE_POOL_LOCK}"
    export SCANCODE_SEMAPHORE="${SCANCODE_SEMAPHORE}"
    export SCANCODE_MAX="${SCANCODE_MAX}"
    export SCANCODE_JSON_CACHE="${PACKAGE_SCANCODE_JSON_CACHE}"
    export SPDX_JSON_CACHE="${PACKAGE_SPDX_JSON_CACHE}"
    export SPDX_LOCK="${SPDX_PACKAGE_LOCK}"

    cd ${PKGDEST}

    # No run if spdx cache is available
    if [ "${NO_SCANCODE_JSON_CACHE}" = "0" ] && [ -e "$SPDX_JSON_CACHE" ]; then
        echo "No run, spdx cache is available"
        exit 0
    fi

    # Generate cache if scancode cache is not available
    if [ "${NO_SCANCODE_JSON_CACHE}" != "0" ] || [ ! -e "$SCANCODE_JSON_CACHE" ]; then
        cmd=""
        # Ignore files for scancode to scan
        for pattern in ${SCANCODE_PACKAGE_IGNORES} ${SCANCODE_PACKAGE_SHADOWS}; do
            cmd="$cmd --ignore=*/$pattern"
        done

        mkdir -p $(dirname $SCANCODE_JSON_CACHE)

        # Run scancode to generate json
        echo "scancode --strip-root -lci $cmd ${SCANCODE_EXTRA_OPTIONS} --json-pp $SCANCODE_JSON_CACHE ."
        scancode --strip-root -lci $cmd ${SCANCODE_EXTRA_OPTIONS} --json-pp $SCANCODE_JSON_CACHE .
        if [ $? -ne 0 ]; then
            echo "Call scancode failed, ret $?"
            exit 1
        fi
    fi

    # Convert scancode json to spdx json as cache
    mkdir -p $(dirname $SPDX_JSON_CACHE)
    echo "scancode-to-spdx.py --input-scancode-json $SCANCODE_JSON_CACHE --output-spdx-json $SPDX_JSON_CACHE"
    scancode-to-spdx.py --input-scancode-json $SCANCODE_JSON_CACHE --output-spdx-json $SPDX_JSON_CACHE
    if [ $? -ne 0 ]; then
        echo "Call scancode-to-spdx failed, ret $?"
        exit 1
    fi
}

do_spdx_source() {
    export EXTRACTCODE_LIBARCHIVE_PATH="${STAGING_LIBDIR_NATIVE}/libarchive.so"
    export EXTRACTCODE_7Z_PATH="${STAGING_BINDIR_NATIVE}/7z"
    export TYPECODE_LIBMAGIC_PATH="${STAGING_LIBDIR_NATIVE}/libmagic.so"
    export TYPECODE_LIBMAGIC_DB_PATH="${STAGING_DATADIR_NATIVE}/misc/magic.mgc"
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"
    export SCANCODE_LICENSE_INDEX_CACHE="${TOPDIR}"
    export SCANCODE_CACHE="${TOPDIR}"
    export SPDX_JSON_CACHE="${SOURCE_SPDX_JSON_CACHE}"
    export SPDX_JSON="${SOURCE_SPDX_JSON}"

    cd ${SPDXWORK}

    # Apply cache
    cmd="--spdx-json-cache $SPDX_JSON_CACHE"

    # Ignore .gitignore and .gitattributes
    cmd="$cmd --ignore-basename .gitignore --ignore-basename .gitattributes"

    # Ignore files SCANCODE_SOURCE_IGNORES and SCANCODE_SOURCE_SHADOWS to scan
    for pattern in ${SCANCODE_SOURCE_IGNORES} ${SCANCODE_SOURCE_SHADOWS}; do
        for f in $(ls */$pattern); do
            cmd="$cmd --ignore=$f"
        done
    done

    echo "update-spdx.py --spdx-json $SPDX_JSON $cmd"
    update-spdx.py --spdx-json $SPDX_JSON $cmd

    # Shadow scan files, scan part of files conditionally.
    # If file size > SCANCODE_MAX_FILE_SIZE, scan SCANCODE_MAX_READ_LINES lines
    if [ -n "${SCANCODE_SOURCE_SHADOWS}" ]; then
        cmd=""
        # Ignore files SCANCODE_SOURCE_IGNORES for shadow scan
        for pattern in ${SCANCODE_SOURCE_IGNORES}; do
            for f in $(ls */$pattern); do
                cmd="$cmd --ignore=$f"
            done
        done

        echo "update-spdx.py --spdx-json $SPDX_JSON $cmd"
        SCANCODE_MAX_FILE_SIZE=${SCANCODE_MAX_FILE_SIZE} SCANCODE_MAX_READ_LINES=${SCANCODE_MAX_READ_LINES} \
        update-spdx.py --spdx-json $SPDX_JSON $cmd
    fi
}

do_spdx_package() {
    export EXTRACTCODE_LIBARCHIVE_PATH="${STAGING_LIBDIR_NATIVE}/libarchive.so"
    export EXTRACTCODE_7Z_PATH="${STAGING_BINDIR_NATIVE}/7z"
    export TYPECODE_LIBMAGIC_PATH="${STAGING_LIBDIR_NATIVE}/libmagic.so"
    export TYPECODE_LIBMAGIC_DB_PATH="${STAGING_DATADIR_NATIVE}/misc/magic.mgc"
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"
    export SCANCODE_LICENSE_INDEX_CACHE="${TOPDIR}"
    export SCANCODE_CACHE="${TOPDIR}"
    export SPDX_JSON_CACHE="${PACKAGE_SPDX_JSON_CACHE}"
    export SPDX_JSON="${PACKAGE_SPDX_JSON}"

    cd ${PKGDEST}

    # Apply cache
    cmd="--spdx-json-cache $SPDX_JSON_CACHE"

    # Ignore .gitignore and .gitattributes
    cmd="$cmd --ignore-basename .gitignore --ignore-basename .gitattributes"

    # Ignore binary file in packages
    cmd="$cmd --no-binary"

    # Ignore files SCANCODE_PACKAGE_IGNORES and SCANCODE_PACKAGE_SHADOWS to scan
    for pattern in ${SCANCODE_PACKAGE_IGNORES} ${SCANCODE_PACKAGE_SHADOWS}; do
        for f in $(ls */$pattern); do
            cmd="$cmd --ignore=$f"
        done
    done

    echo "update-spdx.py --spdx-json $SPDX_JSON $cmd"
    update-spdx.py --spdx-json $SPDX_JSON $cmd

    # Shadow scan files, scan part of files conditionally.
    # If file size > SCANCODE_MAX_FILE_SIZE, scan SCANCODE_MAX_READ_LINES lines
    if [ -n "${SCANCODE_PACKAGE_SHADOWS}" ]; then
        cmd=""
        # Ignore files SCANCODE_PACKAGE_IGNORES for shadow scan
        for pattern in ${SCANCODE_PACKAGE_IGNORES}; do
            for f in $(ls */$pattern); do
                cmd="$cmd --ignore=$f"
            done
        done

        echo "update-spdx.py --spdx-json $SPDX_JSON $cmd"
        SCANCODE_MAX_FILE_SIZE=${SCANCODE_MAX_FILE_SIZE} SCANCODE_MAX_READ_LINES=${SCANCODE_MAX_READ_LINES} \
        update-spdx.py --spdx-json $SPDX_JSON $cmd
    fi
}


def set_spdx(d, spdx_json):
    # spdx_json = {
    #   "<fileName>": {
    #     "status": "undo"|"done",
    #     "SHA256": "<checksumValue>",
    #     "licenseInfoInFiles": ["XXXX"],
    #     "hasExtractedLicensingInfos": [],
    #     "copyrightText": "YYYY",
    #     "fileTypes": "TEXT|SOURCE|BINARY",
    #   }
    # }
    if spdx_json == d.getVar("SOURCE_SPDX_JSON"):
        bb.build.exec_func('do_spdx_source', d)
    elif spdx_json == d.getVar("PACKAGE_SPDX_JSON"):
        bb.build.exec_func('do_spdx_package', d)

def scan_sources(d, source_dir):
    bb.note("Scan Sources")
    if source_dir and os.path.exists(source_dir):
        bb.build.exec_func('do_spdx_source_cache', d)
    bb.note("Scan Sources Done")

def scan_packages(d, package_dir):
    bb.note("Scan Packages")
    if package_dir and os.path.exists(package_dir):
        bb.build.exec_func('do_spdx_package_cache', d)
    bb.note("Scan Packages Done")

def scan_set_spdx(d, scan_dir, doc, spdx_pkg):
    bb.note(f"Scan SPDX Files at {scan_dir}")
    if str(scan_dir) == d.getVar("SPDXWORK"):
        spdx_json = d.getVar("SOURCE_SPDX_JSON")
        prefix = ""
    elif str(scan_dir).startswith(d.getVar("PKGDEST")):
        spdx_json = d.getVar("PACKAGE_SPDX_JSON")
        prefix = scan_dir.name

    if not init_spdx(prefix, doc, spdx_json):
        bb.note("No Scan Source")
        return
    set_spdx(d, spdx_json)
    update_doc(spdx_json, prefix, doc, spdx_pkg)
    bb.note(f"Scan SPDX Files done")

python do_create_spdx:prepend() {
    d.setVar("SCAN_SOURCES_HOOK", scan_sources)
    d.setVar("SCAN_PACKAGES_HOOK", scan_packages)
    d.setVar("SCAN_SET_SPDX_HOOK", scan_set_spdx)
}
