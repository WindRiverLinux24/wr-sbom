# SPDX-License-Identifier: MIT
# Copyright (C) 2024 Wind River Systems, Inc.
#

SBOM_DEPENS ??= " \
    python3-scancode-native:do_populate_sysroot \
    coreutils-native:do_populate_sysroot \
"
do_prepare_scancode_tools[depends] += "${SBOM_DEPENS}"
addtask do_prepare_scancode_tools before do_create_spdx

python do_prepare_scancode_tools() {
    import shutil
    if not shutil.which("scancode"):
        bb.fatal("The command scancode not found")
}
SSTATETASKS += "do_prepare_scancode_tools"
do_prepare_scancode_tools[sstate-inputdirs] = ""
do_prepare_scancode_tools[sstate-outputdirs] = ""
python do_prepare_scancode_tools_setscene () {
    sstate_setscene(d)
}

# https://docs.yoctoproject.org/dev/ref-manual/variables.html#term-SPDX_PRETTY
SPDX_PRETTY = "1"

# https://docs.yoctoproject.org/dev/ref-manual/variables.html#term-SPDX_INCLUDE_SOURCES
SPDX_INCLUDE_SOURCES = "1"

# Scan source file
SPDX_SCAN_SOURCE ??= "1"
# Scan package
SPDX_SCAN_PACKAGE ??= "0"
# Scan sysroot (SPDX 3.0 only)
SPDX_SCAN_SYSROOT ??= "0"

SOURCE_NAME ??= "${BPN}"
PACKAGE_NAME ??= "${PN}"
SYSROOT_NAME ??= "${PN}"
SOURCE_SPDX_JSON ??= "${SPDXDIR}/spdx-source.json"
PACKAGE_SPDX_JSON ??= "${SPDXDIR}/spdx-package.json"
SYSROOT_SPDX_JSON ??= "${SPDXDIR}/spdx-sysroot.json"
SCANCODE_JSON_CACHE_DIR ??= "${BB_CACHEDIR}"
SPDX_JSON_CACHE_DIR ??= "${BB_CACHEDIR}"
SYSROOT_JSON_CACHE_DIR ??= "${BB_CACHEDIR}"
SOURCE_SCANCODE_JSON_CACHE ??= "${SCANCODE_JSON_CACHE_DIR}/scancode/scancode-source-${SOURCE_NAME}-${PV}.json"
PACKAGE_SCANCODE_JSON_CACHE ??= "${SCANCODE_JSON_CACHE_DIR}/scancode/scancode-package-${PACKAGE_NAME}-${PV}.json"
SYSROOT_SCANCODE_JSON_CACHE ??= "${SCANCODE_JSON_CACHE_DIR}/scancode/scancode-sysroot-${SYSROOT_NAME}-${PV}.json"
SOURCE_SPDX_JSON_CACHE ??= "${SPDX_JSON_CACHE_DIR}/spdx/spdx-source-${SOURCE_NAME}-${PV}.json.xz"
PACKAGE_SPDX_JSON_CACHE ??= "${SPDX_JSON_CACHE_DIR}/spdx/spdx-package-${PACKAGE_NAME}-${PV}.json.xz"
SYSROOT_SPDX_JSON_CACHE ??= "${SPDX_JSON_CACHE_DIR}/spdx/spdx-sysroot-${SYSROOT_NAME}-${PV}.json.xz"
# Do not scan files listed in SCANCODE_SOURCE_IGNORES
SCANCODE_SOURCE_IGNORES ??= ""
SCANCODE_PACKAGE_IGNORES ??= ""
SCANCODE_SYSROOT_IGNORES ??= ""
# Shadow scan files listed in SCANCODE_SOURCE_SHADOWS
SCANCODE_SOURCE_SHADOWS ??= ""
SCANCODE_PACKAGE_SHADOWS ??= ""
SCANCODE_SYSROOT_SHADOWS ??= ""
SCANCODE_TIMEOUT ??= "3600"
SCANCODE_PRECOESSES_NUMBER ??= "${BB_NUMBER_THREADS}"
SCANCODE_EXTRA_OPTIONS ??= "--processes ${SCANCODE_PRECOESSES_NUMBER} --max-in-memory -1 --timeout ${SCANCODE_TIMEOUT}"
SCANCODE_MAX_READ_LINES ??= "10240"
SCANCODE_MAX_FILE_SIZE ??= "10240"
SCANCODE_LOCK_TIMEOUT ??= "36000"
SCANCODE_SOURCE_LOCK ??= "${BB_CACHEDIR}/scancode-${SOURCE_NAME}-${PV}.lock"
SCANCODE_PACKAGE_LOCK ??= "${BB_CACHEDIR}/scancode-${PACKAGE_NAME}-${PV}.lock"
SCANCODE_SYSROOT_LOCK ??= "${BB_CACHEDIR}/scancode-${SYSROOT_NAME}-${PV}.lock"
SPDX_SOURCE_LOCK ??= "${BB_CACHEDIR}/spdx-${SOURCE_NAME}-${PV}.lock"
SPDX_PACKAGE_LOCK ??= "${BB_CACHEDIR}/spdx-${PACKAGE_NAME}-${PV}.lock"
SPDX_SYSROOT_LOCK ??= "${BB_CACHEDIR}/spdx-${SYSROOT_NAME}-${PV}.lock"
SCANCODE_POOL_LOCK ??= "${BB_CACHEDIR}/scancode-pool.lock"
SCANCODE_SEMAPHORE ?= "${BB_CACHEDIR}/scancode.semaphore"
SCANCODE_MAX ??= "5"
NO_SCANCODE_JSON_CACHE ??= "0"

require conf/sbom.conf

def init_spdx2(prefix, doc, spdx_json):
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

def init_spdx3(prefix, spdx_files, spdx_json):
    import json

    # data = {
    #   "<fileName>": {
    #     "spdxId": <spdxId>
    #     "status": "undo"|"done",
    #     "SHA256": "<checksumValue>"
    #   }
    # }
    data = {}
    for spdx_file in spdx_files:
        if not isinstance(spdx_file, oe.spdx30.software_File):
            continue

        fileName = os.path.join(prefix,spdx_file.name)
        data[fileName] = {"status": "undo"}
        data[fileName]["spdxId"] = spdx_file.spdxId
        for v in spdx_file.verifiedUsing:
            if v.algorithm == oe.spdx30.HashAlgorithm.sha256:
                data[fileName]["SHA256"] = v.hashValue
                continue

    with open(spdx_json, "w") as f:
        json.dump(data, f, indent=2)

    if len(data) == 0:
        return False

    return True

def _add_license_text(objset, name, license_text):
    if name.startswith("LicenseRef-"):
        name = name.removeprefix("LicenseRef-")

    lic = objset.find_filter(
        oe.spdx30.simplelicensing_SimpleLicensingText,
        name=name,
    )

    if lic is not None:
        bb.note(f"add_license_text: {name} already existed in objset")
        return lic

    lic = objset.add(
        oe.spdx30.simplelicensing_SimpleLicensingText(
            _id=objset.new_spdxid("license-text", name),
            creationInfo=objset.doc.creationInfo,
            name=name,
            simplelicensing_licenseText=license_text,
        )
    )
    return lic

def _add_license_expression(objset, license_expression, license_text, license_data):
    if license_text:
        _license_text_map = {
            license_expression: _add_license_text(
                                    objset,
                                    license_expression,
                                    license_text
                                )._id
        }

        return objset.new_license_expression(
            license_expression, license_data, _license_text_map
        )

    return objset.new_license_expression(license_expression, license_data)

def update_objset(spdx_json, prefix, objset, build_objset, spdx_files, license_data):
    import json
    # spdx_data = {
    #   "<fileName>": {
    #     "status": "undo"|"done",
    #     "SHA256": "<checksumValue>",
    #     "licenseInfoInFiles": ["XXXX"],
    #     "hasExtractedLicensingInfos": [],
    #     "copyrightText": "YYYY",
    #     "fileTypes": "TEXT|SOURCE|BINARY",
    #     "spdxId": <spdxId>
    #   }
    # }
    spdx_data = {}
    with open(spdx_json) as f:
        spdx_data = json.load(f)

    # _lic_data = {
    #    "<license_expression>": "<license expression object>"
    # }
    _lic_data = {}
    for lic in build_objset.foreach_type(oe.spdx30.simplelicensing_LicenseExpression):
        _lic_data[lic.simplelicensing_licenseExpression] = lic

    # Add copyright text, new licesne expression and customized license text
    for spdx_file in spdx_files:
        result = spdx_data.get(os.path.join(prefix, spdx_file.name), None)
        if result and result.get("status") == "done":
            # Add copyrightText to spdx file object
            if result.get("copyrightText", "NONE") != "NONE":
                spdx_file.software_copyrightText = result.get("copyrightText")
            for license in result.get("licenseInfoInFiles"):
                if license in _lic_data or license == "NONE":
                    continue

                # Add licesne expression object and customized license text object
                # to build object
                license_text = ""
                for extra_lic in result.get("hasExtractedLicensingInfos"):
                    if extra_lic["licenseId"] == license:
                        license_text = extra_lic.get("simplelicensing_licenseText") or extra_lic.get("extractedText")
                    break
                lic = _add_license_expression(build_objset, license, license_text, license_data)
                _lic_data[license] = lic

    # _spdx_data = {
    #   "<file's spdxId>": {
    #     "status": "undo"|"done",
    #     "SHA256": "<checksumValue>",
    #     "license_objects": [<license expression object>],
    #     "license_spdxIds": [<license expression string>]
    #     "fileName": "<fileName>"
    #     "spdx_file": "<spdx_file>"
    #   }
    # }
    _spdx_data = {}
    for fileName in spdx_data:
        spdxId = spdx_data[fileName]["spdxId"]
        _spdx_data[spdxId] = {}
        _spdx_data[spdxId]["fileName"] = fileName
        _spdx_data[spdxId]["SHA256"] = spdx_data[fileName]["SHA256"]
        _spdx_data[spdxId]["status"] = "undo"
        _spdx_data[spdxId]["license_objects"] = []
        _spdx_data[spdxId]["license_spdxIds"] = []
        for license in spdx_data[fileName].get("licenseInfoInFiles", []):
            if license == "NONE":
                continue
            lic_obj = _lic_data[license]
            _spdx_data[spdxId]["license_objects"].append(lic_obj)
            _spdx_data[spdxId]["license_spdxIds"].append(lic_obj.spdxId)

    for spdx_file in spdx_files:
        spdxId = spdx_file.spdxId
        if spdxId not in _spdx_data:
             continue
        _spdx_data[spdxId]["spdx_file"] = spdx_file

    # If hasDeclaredLicense Relationship object existed, append license expression
    # objects to `to', and remove `NoneElement' if available
    for rel in objset.foreach_filter(
        oe.spdx30.Relationship,
        relationshipType=oe.spdx30.RelationshipType.hasDeclaredLicense,
    ):
        spdxId = rel.from_.spdxId
        if spdxId not in _spdx_data:
            continue

        license_objects = _spdx_data[spdxId]["license_objects"]
        _spdx_data[spdxId]["status"] = "done"
        if not license_objects:
            continue

        # Remove `NoneElement' if available
        rel.to = [to for to in rel.to if to != oe.spdx30.Element.NoneElement]

        # Remove `NoAssertionElement' if available
        rel.to = [to for to in rel.to if to != oe.spdx30.Element.NoAssertionElement]

        # Append license expression objects to rel.to
        for lic in license_objects:
            if lic not in rel.to:
                rel.to.append(lic)

    # Add new hasDeclaredLicense Relationship object if status is undo
    file_counter = 0
    for spdxId in _spdx_data:
        if _spdx_data[spdxId]["status"] == "undo":
            _spdx_data[spdxId]["status"] = "done"
            if objset == build_objset:
                # The build objset requires license objects
                licenses = _spdx_data[spdxId].get("license_objects")
            else:
                # The pkg objset requires license spdxIds otherwise
                # failed because of duplicated license objects
                # in build objset and pkg object
                licenses = _spdx_data[spdxId].get("license_spdxIds")

            if not licenses:
                continue

            spdx_file = _spdx_data[spdxId]["spdx_file"]
            objset.new_relationship(
                [spdx_file],
                oe.spdx30.RelationshipType.hasDeclaredLicense,
                licenses,
            )
            file_counter += 1

    bb.debug(1, f"Added {file_counter} hasDeclaredLicense relationship to {objset.doc._id}")

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

do_spdx_sysroot_cache() {
    export EXTRACTCODE_LIBARCHIVE_PATH="${STAGING_LIBDIR_NATIVE}/libarchive.so"
    export EXTRACTCODE_7Z_PATH="${STAGING_BINDIR_NATIVE}/7z"
    export TYPECODE_LIBMAGIC_PATH="${STAGING_LIBDIR_NATIVE}/libmagic.so"
    export TYPECODE_LIBMAGIC_DB_PATH="${STAGING_DATADIR_NATIVE}/misc/magic.mgc"
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"
    export SCANCODE_LICENSE_INDEX_CACHE="${TOPDIR}"
    export SCANCODE_CACHE="${TOPDIR}"
    export SCANCODE_LOCK_TIMEOUT="${SCANCODE_LOCK_TIMEOUT}"
    export SCANCODE_LOCK="${SCANCODE_SYSROOT_LOCK}"
    export SCANCODE_POOL_LOCK="${SCANCODE_POOL_LOCK}"
    export SCANCODE_SEMAPHORE="${SCANCODE_SEMAPHORE}"
    export SCANCODE_MAX="${SCANCODE_MAX}"
    export SCANCODE_JSON_CACHE="${SYSROOT_SCANCODE_JSON_CACHE}"
    export SPDX_JSON_CACHE="${SYSROOT_SPDX_JSON_CACHE}"
    export SPDX_LOCK="${SPDX_SYSROOT_LOCK}"

    cd ${COMPONENTS_DIR}/${PACKAGE_ARCH}/${PN}

    # No run if spdx cache is available
    if [ "${NO_SCANCODE_JSON_CACHE}" = "0" ] && [ -e "$SPDX_JSON_CACHE" ]; then
        echo "No run, spdx cache is available"
        exit 0
    fi

    # Generate cache if scancode cache is not available
    if [ "${NO_SCANCODE_JSON_CACHE}" != "0" ] || [ ! -e "$SCANCODE_JSON_CACHE" ]; then
        cmd=""
        # Ignore files for scancode to scan
        for pattern in ${SCANCODE_SYSROOT_IGNORES} ${SCANCODE_SYSROOT_SHADOWS}; do
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

do_spdx_sysroot() {
    export EXTRACTCODE_LIBARCHIVE_PATH="${STAGING_LIBDIR_NATIVE}/libarchive.so"
    export EXTRACTCODE_7Z_PATH="${STAGING_BINDIR_NATIVE}/7z"
    export TYPECODE_LIBMAGIC_PATH="${STAGING_LIBDIR_NATIVE}/libmagic.so"
    export TYPECODE_LIBMAGIC_DB_PATH="${STAGING_DATADIR_NATIVE}/misc/magic.mgc"
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY="1"
    export SCANCODE_LICENSE_INDEX_CACHE="${TOPDIR}"
    export SCANCODE_CACHE="${TOPDIR}"
    export SPDX_JSON_CACHE="${SYSROOT_SPDX_JSON_CACHE}"
    export SPDX_JSON="${SYSROOT_SPDX_JSON}"

    cd ${COMPONENTS_DIR}/${PACKAGE_ARCH}/${PN}

    # Apply cache
    cmd="--spdx-json-cache $SPDX_JSON_CACHE"

    # Ignore .gitignore and .gitattributes
    cmd="$cmd --ignore-basename .gitignore --ignore-basename .gitattributes"

    # Ignore binary file in sysroot
    cmd="$cmd --no-binary"

    # Ignore files SCANCODE_SYSROOT_IGNORES and SCANCODE_SYSROOT_SHADOWS to scan
    for pattern in ${SCANCODE_SYSROOT_IGNORES} ${SCANCODE_SYSROOT_SHADOWS}; do
        for f in $(ls $pattern); do
            cmd="$cmd --ignore=$f"
        done
    done

    echo "update-spdx.py --spdx-json $SPDX_JSON $cmd"
    update-spdx.py --spdx-json $SPDX_JSON $cmd

    # Shadow scan files, scan part of files conditionally.
    # If file size > SCANCODE_MAX_FILE_SIZE, scan SCANCODE_MAX_READ_LINES lines
    if [ -n "${SCANCODE_SYSROOT_SHADOWS}" ]; then
        cmd=""
        # Ignore files SCANCODE_SYSROOT_IGNORES for shadow scan
        for pattern in ${SCANCODE_SYSROOT_IGNORES}; do
            for f in $(ls $pattern); do
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
    #     "spdxId": "<spdxId>|''"
    #   }
    # }
    if spdx_json == d.getVar("SOURCE_SPDX_JSON"):
        bb.build.exec_func('do_spdx_source', d)
    elif spdx_json == d.getVar("PACKAGE_SPDX_JSON"):
        bb.build.exec_func('do_spdx_package', d)
    elif spdx_json == d.getVar("SYSROOT_SPDX_JSON"):
        bb.build.exec_func('do_spdx_sysroot', d)

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

def scan_sysroot(d, source_dir):
    bb.note("Scan Sysroot")
    if source_dir and os.path.exists(source_dir):
        bb.build.exec_func('do_spdx_sysroot_cache', d)
    bb.note("Scan Sysroot Done")

def scan_set_spdx2(d, scan_dir, doc, spdx_pkg):
    bb.note(f"Scan SPDX 2.2 Files at {scan_dir}")
    if str(scan_dir) == d.getVar("SPDXWORK"):
        if d.getVar("SPDX_SCAN_SOURCE") != "1":
            bb.note("Skip source scan")
            return
        spdx_json = d.getVar("SOURCE_SPDX_JSON")
        prefix = ""
    elif str(scan_dir).startswith(d.getVar("PKGDEST")):
        if d.getVar("SPDX_SCAN_PACKAGE") != "1":
            bb.note("Skip package scan")
            return
        spdx_json = d.getVar("PACKAGE_SPDX_JSON")
        prefix = scan_dir.name

    if not init_spdx2(prefix, doc, spdx_json):
        bb.note("No Scan Source")
        return
    set_spdx(d, spdx_json)
    update_doc(spdx_json, prefix, doc, spdx_pkg)
    bb.note(f"Scan SPDX 2.2 Files done")

def scan_set_spdx3(d, scan_dir, objset, build_objset, spdx_files, license_data):
    import oe.spdx30
    import oe.sbom30

    bb.note(f"Scan SPDX {d.getVar('SPDX_VERSION')} Files at {scan_dir}")
    if str(scan_dir) == d.getVar("SPDXWORK"):
        if d.getVar("SPDX_SCAN_SOURCE") != "1":
            bb.note("Skip source scan")
            return
        spdx_json = d.getVar("SOURCE_SPDX_JSON")
        prefix = ""
    elif str(scan_dir).startswith(d.getVar("PKGDEST")):
        if d.getVar("SPDX_SCAN_PACKAGE") != "1":
            bb.note("Skip package scan")
            return
        spdx_json = d.getVar("PACKAGE_SPDX_JSON")
        prefix = scan_dir.name
    elif str(scan_dir) == d.expand("${COMPONENTS_DIR}/${PACKAGE_ARCH}/${PN}"):
        if d.getVar("SPDX_SCAN_SYSROOT") != "1":
            bb.note("Skip sysroot scan")
            return
        spdx_json = d.getVar("SYSROOT_SPDX_JSON")
        prefix = ""

    if not init_spdx3(prefix, spdx_files, spdx_json):
        bb.note("No Scan Source")
        return
    set_spdx(d, spdx_json)
    update_objset(spdx_json, prefix, objset, build_objset, spdx_files, license_data)
    bb.note(f"Scan SPDX {d.getVar('SPDX_VERSION')} Files done")

python do_create_spdx:prepend() {
    if d.getVar("SPDX_SCAN_SOURCE") == "1":
        d.setVar("SCAN_SOURCES_HOOK", scan_sources)
    if d.getVar("SPDX_SCAN_PACKAGE") == "1":
        d.setVar("SCAN_PACKAGES_HOOK", scan_packages)
    if d.getVar("SPDX_SCAN_SYSROOT") == "1":
        d.setVar("SCAN_SYSROOT_HOOK", scan_sysroot)
    if d.getVar("SPDX_VERSION").startswith("3.0"):
        d.setVar("SCAN_SET_SPDX_HOOK", scan_set_spdx3)
    else:
        d.setVar("SCAN_SET_SPDX_HOOK", scan_set_spdx2)
}
