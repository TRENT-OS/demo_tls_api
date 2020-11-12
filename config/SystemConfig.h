/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * System libraries configurations
 *
 */
#pragma once


//-----------------------------------------------------------------------------
// Debug
//-----------------------------------------------------------------------------

#if !defined(NDEBUG)
#   define Debug_Config_STANDARD_ASSERT
#   define Debug_Config_ASSERT_SELF_PTR
#else
#   define Debug_Config_DISABLE_ASSERT
#   define Debug_Config_NO_ASSERT_SELF_PTR
#endif

#define Debug_Config_LOG_LEVEL              Debug_LOG_LEVEL_INFO
#define Debug_Config_INCLUDE_LEVEL_IN_MSG
#define Debug_Config_LOG_WITH_FILE_LINE


//-----------------------------------------------------------------------------
// ChanMux
//-----------------------------------------------------------------------------
#define CHANMUX_CHANNEL_NIC_1_CTRL  4
#define CHANMUX_CHANNEL_NIC_1_DATA  5
#define CHANMUX_CHANNEL_NIC_2_CTRL  7
#define CHANMUX_CHANNEL_NIC_2_DATA  8

//    CHANMUX_NUM_CHANNELS        // 9

#define CHANMUX_ID_NIC_1    101
#define CHANMUX_ID_NIC_2    102


//-----------------------------------------------------------------------------
// Memory
//-----------------------------------------------------------------------------

#define Memory_Config_USE_STDLIB_ALLOC

//-----------------------------------------------------------------------------
// NIC driver
//-----------------------------------------------------------------------------
#define NIC_DRIVER_RINGBUFFER_NUMBER_ELEMENTS 16
#define NIC_DRIVER_RINGBUFFER_SIZE                                             \
    (NIC_DRIVER_RINGBUFFER_NUMBER_ELEMENTS * 4096)


//-----------------------------------------------------------------------------
// Network Stack #1
//-----------------------------------------------------------------------------

#define ETH_1_ADDR                  "10.0.0.10"
#define ETH_1_GATEWAY_ADDR          "10.0.0.1"
#define ETH_1_SUBNET_MASK           "255.255.255.0"


//-----------------------------------------------------------------------------
// Network Stack #2
//-----------------------------------------------------------------------------

#define ETH_2_ADDR                  "10.0.0.11"
#define ETH_2_GATEWAY_ADDR          "10.0.0.1"
#define ETH_2_SUBNET_MASK           "255.255.255.0"

//-----------------------------------------------------------------------------
// TLS Server
//-----------------------------------------------------------------------------

#define TLSSERVER_CLIENT_ID         0

//-----------------------------------------------------------------------------
// TimeServer
//-----------------------------------------------------------------------------

#define TIMESERVER_TK_1_ID      1
#define TIMESERVER_TK_2_ID      2
#define TIMESERVER_NS_1_ID      3
#define TIMESERVER_NS_2_ID      4
