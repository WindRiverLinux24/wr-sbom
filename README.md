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


***************************************************************************************


Maintenance
-----------
The maintainer of this layer is Wind River Systems, Inc.
Contact <support@windriver.com> or your support representative for more
information on submitting changes and patches.

