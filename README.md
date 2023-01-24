# wr-sbom

To use this tool, start from an standard oe-init-build-env
environment and in the BBPATH directory. Execute the script

$ <path to layers>/wr-sbom/bin/lxbomtool.py

usage: lxsbomtool.py [-h] [-d] [-q] [-D DB_FILE] [-i IMAGE] [-p PACKAGE]

Image manifest utility

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug output
  -q, --quiet           Print only errors
  -D DB_FILE, --db_file DB_FILE
                        IP Matching Database
  -i IMAGE, --image IMAGE
                        Image name to create SBOM from
  -p PACKAGE, --package PACKAGE
                        Scan package not image

Maintenance
-----------
The maintainer of this layer is Wind River Systems, Inc.
Contact <support@windriver.com> or your support representative for more
information on submitting changes and patches.

