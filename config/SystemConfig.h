/*
 * System libraries configurations
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
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

#if !defined(Debug_Config_LOG_LEVEL)
#define Debug_Config_LOG_LEVEL              Debug_LOG_LEVEL_INFO
#endif
#define Debug_Config_INCLUDE_LEVEL_IN_MSG
#define Debug_Config_LOG_WITH_FILE_LINE


//-----------------------------------------------------------------------------
// ChanMux
//-----------------------------------------------------------------------------
#define CHANMUX_CHANNEL_NIC_CTRL  4
#define CHANMUX_CHANNEL_NIC_DATA  5

#define CHANMUX_ID_NIC    101


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
// Network Stack
//-----------------------------------------------------------------------------
#define OS_NETWORK_MAXIMUM_SOCKET_NO 16 

#define ETH_ADDR                  "10.0.0.10"
#define ETH_GATEWAY_ADDR          "10.0.0.1"
#define ETH_SUBNET_MASK           "255.255.255.0"
