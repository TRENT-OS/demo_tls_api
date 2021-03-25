#
# Demo TLS API
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
os_set_config_file(
    "config/SystemConfig.h"
    CONFIG_PROJECT_NAME "system_config")

#-------------------------------------------------------------------------------
project(demo_tls_api C)

include("plat/${PLATFORM}/plat_nic.cmake")

DeclareCAmkESComponent(demo_OS_Tls
    INCLUDES
        config
        components/TlsRpcServer/src
    SOURCES
        components/Demo/src/demo_OS_Tls.c
    C_FLAGS
        -Wall -Werror
    LIBS
        system_config
        os_core_api
        lib_debug
        os_crypto
        os_network_api
        os_tls
        TlsServer_client
)

TlsServer_DeclareCAmkESComponent(
    TlsServer
    LIBS
        os_crypto
        os_network_api
)

DeclareCAmkESComponent(NwStack
    INCLUDES
        config
    SOURCES
        components/NwStack/src/network_stack.c
    C_FLAGS
        -Wall -Werror
        -DCFG_ETH_ADDR=ETH_1_ADDR
        -DCFG_ETH_GATEWAY_ADDR=ETH_1_GATEWAY_ADDR
        -DCFG_ETH_SUBNET_MASK=ETH_1_SUBNET_MASK
    LIBS
        system_config
        os_core_api
        lib_debug
        os_network_lib
        TimeServer_client
)

DeclareCAmkESComponent(
    Ticker
    SOURCES
        components/Ticker/Ticker.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_debug
        TimeServer_client
)

TimeServer_DeclareCAmkESComponent(
    TimeServer
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
