SUMMARY = "POSIX parameter expansion in Python"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=86d3f3a95c324c9479bd8986968f4327"

PYPI_PACKAGE = "parameter-expansion-patched"

SRC_URI[sha256sum] = "ff5dbc89fbde582f3336562d196b710771e92baa7b6d59356a14b085a0b6740b"

inherit pypi
inherit setuptools3
inherit native

UPSTREAM_CHECK_REGEX = "/${PYPI_PACKAGE}/(?P<pver>(\d+[\.\-_]*)+(b\d+))/"
