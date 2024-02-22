#
# Demo TLS API
#
# Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.17)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_set_defaults()
os_sdk_setup(CONFIG_FILE "config/SystemConfig.h" CONFIG_PROJECT "system_config")

# Set additional include paths.
CAmkESAddCPPInclude("plat/${PLATFORM}")


#-------------------------------------------------------------------------------
project(demo_tls_api C)

include("plat/${PLATFORM}/plat_nic.cmake")

DeclareCAmkESComponent(DemoApp
    INCLUDES
        config
    SOURCES
        components/DemoApp/src/DemoApp.c
    C_FLAGS
        -Wall -Werror
    LIBS
        system_config
        os_core_api
        lib_debug
        os_crypto
        os_socket_client
        os_tls
        TlsServer_client
)

TlsServer_DeclareCAmkESComponent(
    TlsServer
)

NetworkStack_PicoTcp_DeclareCAmkESComponent(
    NetworkStack_PicoTcp
    C_FLAGS
        -DNetworkStack_PicoTcp_USE_HARDCODED_IPADDR
        -DDEV_ADDR=ETH_ADDR
        -DGATEWAY_ADDR=ETH_GATEWAY_ADDR
        -DSUBNET_MASK=ETH_SUBNET_MASK
)


TimeServer_DeclareCAmkESComponent(
    TimeServer
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

os_sdk_create_CAmkES_system("main.camkes")
