# wr-sbom
Use wr-sbom OpenEmbedded/Yocto layer to generate Software Bill of Materials (SBOM) of [Software Package Data Exchange (SPDX)](https://spdx.dev) format for Yocto-based projects.

It inherits the implement of [OpenEmbedded/Yocto SBOM](https://docs.yoctoproject.org/dev/dev-manual/sbom.html) to create SBOM file using SPDX v2.2 or v3.0.1 specification. The OpenEmbedded build system can generate a description of all the components you used, their licenses, their dependencies, their sources, the changes that were applied to them and the known vulnerabilities that were fixed.

It integrates [ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) to Yocto projects, which detects licenses and copyrights from source files, packages and sysroots. And fill the scan result to Yocto's SBOM file

----------------------------------------------------------------------------------------
# Supported Yocto Project Versions
- [Wind River Linux LTS24](https://docs.windriver.com/category/os_linux_lts_24)

----------------------------------------------------------------------------------------
## Quick Start

### Requirement
Please create a new project to apply this layer with download layer

### Setup for SPDX 2.2
```bash
setup.sh --templates feature/sbom-2 --layers wr-sbom --dl-layers ...
```

### Setup for SPDX 3.0.1
```bash
setup.sh --templates feature/sbom-3 --layers wr-sbom --dl-layers ...
```

### Generating SBOM File
#### Build image
```bash
bitbake ${image_name}
```

Upon building an image, you will then get:

- For SPDX 2.2, the compressed archive IMAGE-MACHINE.rootfs.spdx.tar.zst in tmp-glibc/deploy/images/MACHINE/
contains the index and the files for the single recipes.  

- For SPDX 3.0.1, SPDX output in JSON format as an IMAGE-MACHINE.rootfs.spdx.json file in
tmp-glibc/deploy/images/MACHINE/ inside the Build Directory.  

#### Build SDK
```bash
bitbake ${image_name} -cpopulate_sdk
```

Upon building an SDK, you will then get:

- For SPDX 2.2, two compressed archives SDK-IMAGE-host.spdx.tar.zst and SDK-IMAGE-target.spdx.tar.zst in
tmp-glibc/deploy/sdk contains the index and the files for the single recipes.  

- For SPDX 3.0.1, SPDX output in JSON format as an SDK-IMAGE.spdx.json file in tmp-glibc/deploy/sdk
inside the Build Directory.  


##
Design

### Integrate [ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) to Yocto projects
This layer adds 50+ native recipes to provide native tool scancode, and insert hooks to oe-core's SBOM to:  

- scan source, package and sysroot  
- set scan result to SPDX file  

The oe-core made use of function add_package_files to collect source, package or sysroot, we set hooks around add_package_files  


### Enable scan source by default
This layer supports to scan source, package and sysroot, but only enable scan source by default, two reasons:  

- In add_package_files, upstream oe-core only collect licenses from source  
- Save built time, it takes a lot of time to call scancode to scan package and sysroot  


### Prebuilt SPDX source cache
Call scancode to scan source will take a lot of time and require mess of CPU/memory resources, especially multiple recipes call scancode parallel.  
Because of source file is stable between builds, save the output of scancode to a file as cache and release with wr-sbom is workable, the wr-sbom download layer provides prebuilt SPDX source cache for customer to save build time and resources  
If multiple recipes use the same source code, such as llvm-project-source, clang and compiler-rt, explicitly set SOURCE_NAME with bpn override to share one source cache  
There are two kinds of cache, one is scancode cache which saves the output of scancode, becuase the size of scancode cache is big that contains many useless values, in order to save disk space, filter out unused values and save as SPDX cache. The Prebuilt SPDX source cache is SPDX cache  

Provide an easy way to create SPDX source cache in build directory:  
For specific recipe
```
bitbake <recipe> -ccreate_spdx_source_cache -f
```

For world build
```
bitbake world --runall=create_spdx_source_cache
```

For all available BSPs
```
../layers/wr-sbom/scripts/create_spdx_source_cache.sh
```


## Basic configuration
### [SPDX_PRETTY](https://docs.yoctoproject.org/dev/ref-manual/variables.html#term-SPDX_PRETTY)
This option makes the SPDX output more human-readable, using identation and newlines
```
SPDX_PRETTY = "1"
```

### [SPDX_INCLUDE_SOURCES](https://docs.yoctoproject.org/dev/ref-manual/variables.html#term-SPDX_INCLUDE_SOURCES)
This option allows to add a description of the source files used to build the host tools and the target packages
```
SPDX_INCLUDE_SOURCES = "1"
```

### SPDX_SCAN_SOURCE
Use [ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) to detects licenses and copyrights from source files
```
SPDX_SCAN_SOURCE = "1"
```

## Advance configuration
### SPDX_SCAN_PACKAGE
Use [ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) to detects licenses and copyrights from package files
```
SPDX_SCAN_PACKAGE = "1"
```

### SPDX_SCAN_PACKAGE (SPDX 3.0.1 only)
Use [ScanCode Toolkit](https://github.com/nexB/scancode-toolkit) to detects licenses and copyrights from sysroot files
```
SPDX_SCAN_SYSROOT = "1"
```

### SCANCODE_PRECOESSES_NUMBER
The option [--processes INTEGER of scancode](https://scancode-toolkit.readthedocs.io/en/stable/cli-reference/core-options.html#core-options), call scancode to use n parallel processes, default is CPU number
```
SCANCODE_PRECOESSES_NUMBER = "<INTEGER>"
```

### SPDX_NUMBER_THREADS
Use SPDX_NUMBER_THREADS to override BB_NUMBER_THREADS, default is a quarter of CPU number
```
SPDX_NUMBER_THREADS = "<INTEGER>"
```

### SCANCODE_MAX
The max number of running scancode in parallel, default is one eighth of CPU number
```
SCANCODE_MAX = "<INTEGER>"
```

### SCANCODE_EXTRA_OPTIONS
Customize options for scancode
```
SCANCODE_EXTRA_OPTIONS = "--<option> <value>"
```

### SCANCODE_SOURCE_IGNORES
The option [--ignore <pattern> of scancode](https://scancode-toolkit.readthedocs.io/en/stable/cli-reference/scan-options-pre.html#all-pre-scan-options), explicitly ask scancode not scan source file for specific recipe
```
SCANCODE_SOURCE_IGNORES:append:bpn-<recipe> = " <file-pattern>"
```

### SCANCODE_PACKAGE_IGNORES
The option [--ignore <pattern> of scancode](https://scancode-toolkit.readthedocs.io/en/stable/cli-reference/scan-options-pre.html#all-pre-scan-options), explicitly ask scancode not scan package file for specific recipe
```
SCANCODE_PACKAGE_IGNORES:append:bpn-<recipe> = " <file-pattern>"
```

### SCANCODE_SYSROOT_IGNORES (SPDX 3.0.1 only)
The option [--ignore <pattern> of scancode](https://scancode-toolkit.readthedocs.io/en/stable/cli-reference/scan-options-pre.html#all-pre-scan-options), explicitly ask scancode not scan sysroot file for specific recipe
```
SCANCODE_SYSROOT_IGNORES:append:bpn-<recipe> = " <file-pattern>"
```

### SCANCODE_SOURCE_SHADOWS
Ask scancode scan part of the source file other than all of it for the specific recipe
```
SCANCODE_SOURCE_SHADOWS:append:bpn-<recipe> = " <file-pattern>"
```

### SCANCODE_PACKAGE_SHADOWS
Ask scancode scan part of the package file other than all of it for the specific recipe
```
SCANCODE_PACKAGE_SHADOWS:append:bpn-<recipe> = " <file-pattern>"
```

### SCANCODE_SYSROOT_SHADOWS (SPDX 3.0.1 only)
Ask scancode scan part of the sysroot file other than all of it for the specific recipe
```
SCANCODE_SYSROOT_SHADOWS:append:bpn-<recipe> = " <file-pattern>"
```

### SCANCODE_MAX_READ_LINES
While scancode scans part of file for the specific recipe, ask scancode scan the max line number of the file, it works for SCANCODE_SOURCE_IGNORES, SCANCODE_SOURCE_SHADOWS and SCANCODE_PACKAGE_SHADOWS, default is 10240 lines
```
SCANCODE_MAX_READ_LINES:bpn-<recipe> = "<INTEGER>"
```

### SCANCODE_MAX_FILE_SIZE
Only if the size of the matching file in SCANCODE_SOURCE_IGNORES, SCANCODE_SOURCE_SHADOWS and SCANCODE_PACKAGE_SHADOWS is bigger than SCANCODE_MAX_FILE_SIZE, ask scancode scan SCANCODE_MAX_READ_LINES lines of the file, default is 10240 byte
```
SCANCODE_MAX_FILE_SIZE:bpn-<recipe> = "<INTEGER>"
```

### NO_SCANCODE_JSON_CACHE
Do not use scancode/spdx cache, disable by default
Globally affected
```
NO_SCANCODE_JSON_CACHE = "1"
```
For specific recipe
```
NO_SCANCODE_JSON_CACHE:bpn-<recipe> = "1"

```

### SOURCE_NAME
The basename of spdx source cache for specific recipe
```
SOURCE_NAME:bpn-<recipe> = "<recipe-name>"
```


## FAQ
### Resolve OOM failure on scancode
Tweak SCANCODE_PRECOESSES_NUMBER, SPDX_NUMBER_THREADS and SCANCODE_MAX to reduce scancode parallel  


### Workaround timeout failure on scancode
If scancode timeout on scanning the particular file for specific recipe, set SCANCODE_SYSROOT_IGNORES to filter out the file from scancode or set SCANCODE_SOURCE_SHADOWS, SCANCODE_MAX_READ_LINES and SCANCODE_MAX_FILE_SIZE to scan a part of the file  


### SPDX License and non-SPDX license
Call scancode to get two kinds of licenses, one is SPDX License from [SPDX license list](https://spdx.org/licenses/), another is non-SPDX license from [scancode-licensedb](https://scancode-licensedb.aboutcode.org/) which has LicenseRef-scancode prefix  


## Examples
Take recipe shadow as example:
- Provide SPDX with and without this layer as comparing  
- Compress SPDX cache as XZ to save disk space 
```
examples/
├── 2.2
│   ├── turn_off
│   │   └── recipe-shadow.spdx.json
│   └── turn_on
│       └── recipe-shadow.spdx.json
├── 3.0.1
│   ├── turn_off
│   │   └── shadow.spdx.json
│   └── turn_on
│       └── shadow.spdx.json
└── cache
    ├── scancode
    │   └── scancode-source-shadow-4.14.2.json
    └── spdx
        └── spdx-source-shadow-4.14.2.json.xz
```

### Analysis all detected licenses and copyrights in SPDX 2.2
In examples/2.2/turn_on/recipe-shadow.spdx.json, search '"packages":', get copyrightText and licenseInfoFromFiles
```
  "packages": [
    { 
      "SPDXID": "SPDXRef-Recipe-shadow",
      "copyrightText": "Copyright (c) 1999-2021 Free Software Foundation, Inc.\nCopyright ...",
...
      "licenseInfoFromFiles": [
        "GPL-2.0-or-later",
        "Autoconf-exception-generic",
        "BSD-3-Clause",
        "GPL-3.0-or-later",
        "Autoconf-exception-generic-3.0",
        "LicenseRef-scancode-warranty-disclaimer",
        "X11",
        "LicenseRef-scancode-public-domain",
        "Libtool-exception",
        "LicenseRef-scancode-unknown-license-reference",
        "MIT",
        "GPL-2.0-only",
        "GPL-3.0-only",
        "GPL-1.0-or-later",
        "LGPL-2.0-or-later",
        "DOC",
        "FSFULLRWD",
        "FSFULLR",
        "FSFUL",
        "Unlicense",
        "TCP-wrappers",
        "BSD-2-Clause",
        "BSD-4-Clause",
        "LicenseRef-scancode-sun-source",
        "LicenseRef-scancode-ldpgpl-1a",
        "LicenseRef-scancode-other-copyleft",
        "eCos-exception-2.0",
        "LicenseRef-scancode-free-unknown",
        "LicenseRef-scancode-other-permissive",
        "ISC",
        "0BSD",
        "Bison-exception-2.2"
      ],
```

For non-standard SPDX licenses which has LicenseRef-scancode prefix, search '"hasExtractedLicensingInfos"' to get the definition  
```
  "hasExtractedLicensingInfos": [
    {  
      "comment": "See details at https://github.com/nexB/scancode-toolkit/blob/develop/src/licensedcode/data/licenses/warranty-disclaimer.LICENSE\n",
      "extractedText": "See details at https://github.com/nexB/scancode-toolkit/blob/develop/src/licensedcode/data/licenses/warranty-disclaimer.LICENSE\n",
      "licenseId": "LicenseRef-scancode-warranty-disclaimer",
      "name": "Generic Bare Warranty Disclaimer"
    },
...
```

### Analysis one source file in SPDX 2.2
Take examples/source/shadow-4.14.2/ltmain.sh for example  
In examples/2.2/turn_on/recipe-shadow.spdx.json, search '"fileName": "shadow-4.14.2/ltmain.sh"' to get copyrightText, fileTypes and licenseInfoInFiles  
```
    {
      "SPDXID": "SPDXRef-SourceFile-shadow-16",
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "e09730adb2d8d37ff7de6a3f51b95a31e53fc7b3"
        },
        {
          "algorithm": "SHA256",
          "checksumValue": "6e45c2fcf6d2b17d8886759eb9af4ce0a16ff444e1abbc50b1f48d37e25ac294"
        }
      ],    
      "copyrightText": "Copyright (c) 1996-2019, 2021-2022 Free Software Foundation, Inc.\nCopyright (c) 2004-2019, 2021 Bootstrap Authors\nCopyright (c) 2010-2019, 2021 Bootstrap Authors\n",
      "fileName": "shadow-4.14.2/ltmain.sh",
      "fileTypes": [
        "SOURCE",
        "TEXT"
      ],    
      "licenseConcluded": "NOASSERTION",
      "licenseInfoInFiles": [
        "GPL-2.0-or-later",
        "Libtool-exception",
        "LicenseRef-scancode-warranty-disclaimer",
        "LicenseRef-scancode-unknown-license-reference",
        "MIT",
        "GPL-2.0-only",
        "BSD-3-Clause",
        "GPL-3.0-only",
        "GPL-1.0-or-later"
      ]     
    }, 
```

### Analysis one source file in SPDX 3.0.1
In examples/3.0.1/turn_on/shadow.spdx.json, search '"name": "shadow-4.14.2/ltmain.sh"' to get copyrightText and spdxId  
And search the spdxId to get hasDeclaredLicense Relationship, pick up one license from "to", such as GPL-2_0-only  
search it to get simplelicensing_LicenseExpression of GPL-2_0-only. For non-standard SPDX license which has   
LicenseRef-scancode prefix, search value from simplelicensing_customIdToUri in simplelicensing_LicenseExpression,  
get simplelicensing_SimpleLicensingText of scancode-warranty-disclaimer  
```
    {
      "type": "software_File",
      "spdxId": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/sourcefile/26",
      "creationInfo": "_:CreationInfo1",
      "extension": [
        {
          "type": "https://rdf.openembedded.org/spdx/3.0/license-scanned"
        },
        {
          "type": "https://rdf.openembedded.org/spdx/3.0/id-alias",
          "https://rdf.openembedded.org/spdx/3.0/alias": "shadow/UNIHASH/sourcefile/26",
          "https://rdf.openembedded.org/spdx/3.0/link-name": "c5d426649256d6327e492fae0886aadd87f60e5a836c5daeac68bc45c942037d"
        },
        {
          "type": "https://rdf.openembedded.org/spdx/3.0/link-extension",
          "https://rdf.openembedded.org/spdx/3.0/link-spdx-id": true, 
          "https://rdf.openembedded.org/spdx/3.0/link-name": "ffe30949bfcd754a74592ad95edfc6dfb5b7148749e1c527221316f0ae8cfb7b"
        }
      ],    
      "name": "shadow-4.14.2/ltmain.sh",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha256",
          "hashValue": "6e45c2fcf6d2b17d8886759eb9af4ce0a16ff444e1abbc50b1f48d37e25ac294"
        }
      ],    
      "software_copyrightText": "Copyright (c) 1996-2019, 2021-2022 Free Software Foundation, Inc.\nCopyright (c) 2004-2019, 2021 Bootstrap Authors\nCopyright (c) 2010-2019, 2021 Bootstrap Authors\n",
      "software_primaryPurpose": "source"
    },
...
    { 
      "type": "Relationship",
      "spdxId": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/relationship/327836a39fcfbb63aa1f3fb2b6bf7eb3",
      "creationInfo": "_:CreationInfo1",
      "extension": [
        { 
          "type": "https://rdf.openembedded.org/spdx/3.0/id-alias",
          "https://rdf.openembedded.org/spdx/3.0/alias": "shadow/UNIHASH/relationship/327836a39fcfbb63aa1f3fb2b6bf7eb3",
          "https://rdf.openembedded.org/spdx/3.0/link-name": "1cfa45686f9adc7ca7e5f82acc672f07e868a1084951497285e5c3007865a587"
        },
        { 
          "type": "https://rdf.openembedded.org/spdx/3.0/link-extension",
          "https://rdf.openembedded.org/spdx/3.0/link-spdx-id": true,
          "https://rdf.openembedded.org/spdx/3.0/link-name": "a4fc4900d30a27619f867b37f950356f3be802873f60bbfc3cc56e7f34ae31a6"
        }
      ],
      "from": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/sourcefile/26",
      "relationshipType": "hasDeclaredLicense",
      "to": [
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/GPL-2_0-or-later",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/Libtool-exception",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/LicenseRef-scancode-warranty-disclaimer/69593fd237b359e455e8ef2acbd5396a",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/LicenseRef-scancode-unknown-license-reference",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/MIT",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/GPL-2_0-only",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/BSD-3-Clause",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/GPL-3_0-only",
        "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/GPL-1_0-or-later"
      ]
    },
...
    {
      "type": "simplelicensing_LicenseExpression",
      "spdxId": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/GPL-2_0-only",
      "creationInfo": "_:CreationInfo1",
      "extension": [
        {     
          "type": "https://rdf.openembedded.org/spdx/3.0/id-alias",
          "https://rdf.openembedded.org/spdx/3.0/alias": "shadow/UNIHASH/license/3_24_0/GPL-2_0-only",
          "https://rdf.openembedded.org/spdx/3.0/link-name": "2c50fc1b89ce7317a19d554077f56fc024b6dfabc432713a30775856e5d7f10a"
        },    
        {     
          "type": "https://rdf.openembedded.org/spdx/3.0/link-extension",
          "https://rdf.openembedded.org/spdx/3.0/link-spdx-id": true, 
          "https://rdf.openembedded.org/spdx/3.0/link-name": "08fa14dabcba7a0077d5122217301791768155d9e06ec3548cb547ba42825303"
        }     
      ],    
      "simplelicensing_licenseExpression": "GPL-2.0-only",
      "simplelicensing_licenseListVersion": "3.24.0"
    },
...
    { 
      "type": "simplelicensing_LicenseExpression",
      "spdxId": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license/3_24_0/LicenseRef-scancode-warranty-disclaimer/69593fd237b359e455e8ef2acbd5396a",
      "creationInfo": "_:CreationInfo1",
      "extension": [
        { 
          "type": "https://rdf.openembedded.org/spdx/3.0/id-alias",
          "https://rdf.openembedded.org/spdx/3.0/alias": "shadow/UNIHASH/license/3_24_0/LicenseRef-scancode-warranty-disclaimer/69593fd237b359e455e8ef2acbd5396a",
          "https://rdf.openembedded.org/spdx/3.0/link-name": "5671c7edc1c1caaa31d361dcc5b9ea278913454cd6eefb34b80749a57efad41d"
        },
        { 
          "type": "https://rdf.openembedded.org/spdx/3.0/link-extension",
          "https://rdf.openembedded.org/spdx/3.0/link-spdx-id": true,
          "https://rdf.openembedded.org/spdx/3.0/link-name": "db88e35d3abb0b183f6d67fc2b589ae3b0a25b4e0f9ee2f79632dff5b31be621"
        }
      ],
      "simplelicensing_customIdToUri": [
        { 
          "type": "DictionaryEntry",
          "key": "LicenseRef-scancode-warranty-disclaimer",
          "value": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license-text/scancode-warranty-disclaimer"
        }
      ],
      "simplelicensing_licenseExpression": "LicenseRef-scancode-warranty-disclaimer",
      "simplelicensing_licenseListVersion": "3.24.0"
    },
...
    { 
      "type": "simplelicensing_SimpleLicensingText",
      "spdxId": "http://spdx.org/spdxdocs/shadow-10e66933-65cf-5a2d-9a1d-99b12a405441/df9b0bcfac0ef9ef1ee7dc0e21838a8794a3a107c5f1f3f73eff34b283b927fb/license-text/scancode-warranty-disclaimer",
      "creationInfo": "_:CreationInfo1",
      "extension": [
        { 
          "type": "https://rdf.openembedded.org/spdx/3.0/id-alias",
          "https://rdf.openembedded.org/spdx/3.0/alias": "shadow/UNIHASH/license-text/scancode-warranty-disclaimer",
          "https://rdf.openembedded.org/spdx/3.0/link-name": "c840ab526f8f99fe199568f7316886be349bc0cf515aad855f3dcd653e6033de"
        },
        { 
          "type": "https://rdf.openembedded.org/spdx/3.0/link-extension",
          "https://rdf.openembedded.org/spdx/3.0/link-spdx-id": true,
          "https://rdf.openembedded.org/spdx/3.0/link-name": "db58cfba9b8e400c19b31d1cba6cffc04b4c64634913c59c17d6ac094ff78656"
        }
      ],
      "name": "scancode-warranty-disclaimer",
      "simplelicensing_licenseText": "---\nkey: warranty-disclaimer\nshort_name: Generic Bare Warranty Disclaimer\nname: Generic Bare Warranty Disclaimer\ncategory: Unstated License\nowner: Unspecified\nnotes: |\n    This is a catch all license for plain, generic warranty disclaimers that do\n    not provide much rights. Often seen in Microsoft code.\nis_generic: yes\nspdx_license_key: LicenseRef-scancode-warranty-disclaimer\n---"
    },

```

### Analysis the reason of detected license in source file
Take examples/source/shadow-4.14.2/ltmain.sh for example  
In examples/cache/scancode/scancode-source-shadow-4.14.2.json, search '"path": "shadow-4.14.2/ltmain.sh"'  
to get license_detections, in which lists the exactly the start_line and end_line for each matching licenses   


***************************************************************************************


Maintenance
-----------
The maintainer of this layer is Wind River Systems, Inc.
Contact <support@windriver.com> or your support representative for more
information on submitting changes and patches.

