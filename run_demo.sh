#!/bin/bash -em

#-------------------------------------------------------------------------------
#
# Script to run a demo using TAP devices
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
USAGE_STRING="run_demo.sh <path-to-project-build> <path-to-proxy>\n
This script runs demo applications that require TAP\n"

if [ "$#" -lt "2" ]; then
    echo -e "${USAGE_STRING}"
    exit 1
fi

PROJECT_PATH=$1
PROXY_PATH=$2

if [ -z ${PROJECT_PATH} ]; then
    echo "ERROR: missing project path"
    exit 1
fi

# default is the zynq7000 platform
IMAGE_PATH=${PROJECT_PATH}/images/capdl-loader-image-arm-zynq7000
if [ ! -f ${IMAGE_PATH} ]; then
    echo "ERROR: missing project image ${IMAGE_PATH}"
    exit 1
fi

if [ ! -f ${PROXY_PATH}/proxy_app ]; then
    echo "ERROR: proxy application path missing!"
    exit 1
fi

shift 2

# check if TAP device is already created and if not, set one up
if [ ! -d "/sys/class/net/tap0/" ]; then
  echo "Missing TAP device!"
  echo -1
fi


QEMU_PARAMS=(
    -machine xilinx-zynq-a9
    -m size=512M
    -nographic
    -s
    -serial pty
    -serial mon:stdio
    -kernel ${IMAGE_PATH}
)

read -p "Please hit 'Enter' to let the holding instance of qemu to continue. You can stop qemu with 'Ctrl-a+x', then you can stop the proxy app with 'Ctrl-c'."

# run QEMU
qemu-system-arm ${QEMU_PARAMS[@]} $@ 2> qemu_stderr.txt &

# try to retrieve the PTS to be given to the proxy app from qemu
while [ -z "${PTS}" ]; do
   if [ -f qemu_stderr.txt ]; then
        PTS=$(cat qemu_stderr.txt | grep -o "/dev/pts/[0-9]" || continue)
    fi
done

# start proxy app
${PROXY_PATH}/proxy_app -c PTY:${PTS} -t 1  > seos_proxy_app.out &

fg # trigger holding qemu
fg # trigger holding proxy_app
