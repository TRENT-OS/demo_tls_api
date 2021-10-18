#
# Demo TLS API
#
# Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.17)

#-------------------------------------------------------------------------------
os_set_config_file(
    "config/SystemConfig.h"
    CONFIG_PROJECT_NAME "system_config")

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

DeclareCAmkESComponent(DemoApp_TlsClient
    INCLUDES
        config
    SOURCES
        components/DemoApp_TlsClient/src/DemoApp_TlsClient.c
    C_FLAGS
        -Wall -Werror
    LIBS
        system_config
        os_core_api
        lib_debug
        TlsServer_client
        # TlsServer_client does not include the os_tls API functions,
        # for that os_tls is required. os_tls includes not only the api
        # functions but also the tls client lib implementation
        os_tls
        # os_tls uses internally our os_crypto api, so we need to include
        # it here
        os_crypto
        # os_crypto uses in the defaultSendFunc and defaultRecvFunc the network API
        os_socket_client
)


TlsServer_DeclareCAmkESComponent(
    TlsServer
    LIBS
        os_crypto
        os_socket_client
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

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
