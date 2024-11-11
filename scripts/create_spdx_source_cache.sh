#!/bin/bash
#
# Copyright (C) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

MACHINE="
  genericarm64
  genericx86
  beaglebone-yocto
  genericx86-64
  qemuarmv5
  qemux86-64
  qemuarm64
  qemuriscv64
  qemuppc64
  qemux86
  qemumips
  qemumips64
  qemuarm
  qemuriscv32
  intel-x86-64
  intel-grand-ridge
  nxp-imx8
  intel-snow-ridge
  nxp-ls1028
  nxp-imx6
  nxp-ls1046
  amd-zynqmp
  axxiaarm64
  axxiaarm
  amd-zynq
  marvell-cn10xxx
  marvell-cn96xx
  nxp-s32g
  ti-j78xx
  ti-j72xx
  aptiv-cvc-131
  aptiv-cvc-fl
  nxp-ls1043
  microchip-polarfire-soc
  bcm-2xxx-rpi4
  intel-socfpga-64
  nxp-imx9
  ti-am335x
  amd-snowyowl-64
  nxp-lx2xxx
"
cp -f conf/local.conf conf/local.conf.orig
echo 'WRTEMPLATE += "feature/sbom-3"' >> conf/local.conf
for machine in $MACHINE; do
  echo "MACHINE = '$machine'"
  echo "MACHINE = '$machine'" >> conf/local.conf
  echo "bitbake world --runall=create_spdx_source_cache"
  bitbake world --runall=create_spdx_source_cache
  if [ $? -ne 0 ]; then
    echo "Run failed"
    exit 1
  fi
done

echo "Build recipes excluded from world"
echo "MACHINE = 'intel-x86-64'" >> conf/local.conf
bitbake dpdk lmbench ipmitool frr ifenslave -ccreate_spdx_source_cache -f
bitbake tensorflow tensorflow-estimator tensorflow-lite keras -ccreate_spdx_source_cache -f
echo 'DISTRO_FEATURES:append = " wayland x11"' >> conf/local.conf
bitbake gvfs -ccreate_spdx_source_cache -f
echo 'DISTRO_FEATURES:append = " opengl vulkan"' >> conf/local.conf
bitbake chromium-x11 -ccreate_spdx_source_cache -f

cp -f conf/local.conf conf/local.conf.spdx
cp -f conf/local.conf.orig conf/local.conf

script_dir=$(dirname "${BASH_SOURCE[0]}")
dl_dir="${script_dir}/../../wr-sbom-dl"
if [ ! -d ${dl_dir} ]; then
  echo "${dl_dir} not found"
  exit 1
fi
cd ${dl_dir}
git add scancode-cache/spdx/spdx-source-*.json.xz
git commit -s -m "Update spdx source caches on $(date '+%Y-%m-%d')"
if [ $? -ne 0 ]; then
  echo "No spdx source caches are added"
fi

