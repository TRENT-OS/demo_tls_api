/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "DemoConfig.h"

#include "OS_Crypto.h"
#include "OS_Tls.h"

#include "LibDebug/Debug.h"
#include "OS_Network.h"
#include "OS_NetworkStackClient.h"

#include "TlsRpcServer.h"

#include <camkes.h>
#include <string.h>

#define MAX_BUFFER_SIZE 2048

static OS_Tls_Handle_t              hTls;
static OS_Crypto_Handle_t           hCrypto;
static OS_NetworkSocket_Handle_t    socket;

extern OS_Error_t OS_NetworkAPP_RT(
    OS_Network_Context_t ctx);

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len);

static int
recvFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len);

static OS_Tls_Config_t tlsCfg =
{
    .mode = OS_Tls_MODE_SERVER,
    .library = {
        .socket = {
            .context    = &socket,
            .recv       = recvFunc,
            .send       = sendFunc,
        },
        .flags = OS_Tls_FLAG_DEBUG,
        .crypto = {
            .policy = NULL,
            .caCert = TLS_HOST_CERT,
            .cipherSuites = {
                OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            },
            .cipherSuitesLen = 1
        }
    }
};
static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.entropy = OS_CRYPTO_ASSIGN_Entropy(entropy_rpc, entropy_port)
};
static OS_Network_Socket_t socketCfg =
{
    .domain = OS_AF_INET,
    .type   = OS_SOCK_STREAM,
    .name   = TLS_HOST_IP,
    .port   = TLS_HOST_PORT
};


// Private static functions ----------------------------------------------------

static void
initNetworkClientApi()
{
    static OS_NetworkStackClient_SocketDataports_t config;
    static OS_Dataport_t dataport = OS_DATAPORT_ASSIGN(NwAppDataPort);

    config.number_of_sockets = 1;

    config.dataport = &dataport;
    OS_NetworkStackClient_init(&config);
}

static int
sendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    OS_Error_t err;
    OS_NetworkSocket_Handle_t* sockHandle = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : len;
    if ((err = OS_NetworkSocket_write(*sockHandle, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during socket write...error:%d", err);
        return -1;
    }

    return n;
}

static int
recvFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    OS_Error_t err;
    OS_NetworkSocket_Handle_t* sockHandle = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : len;
    if ((err = OS_NetworkSocket_read(*sockHandle, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during socket read...error:%d", err);
        return -1;
    }

    return n;
}

// Public functions ------------------------------------------------------------

// We need to give the TLS RPC Server the context to use for a specific client;
// we have only one client here, so it is easy.
OS_Tls_Handle_t
tls_rpc_getTls(
    void)
{
    return hTls;
}

OS_Error_t
TlsRpcServer_init(
    void)
{
    OS_Error_t err;
    OS_Dataport_t dataport = OS_DATAPORT_ASSIGN(tlsServerDataport);

    initNetworkClientApi();
    // Apparently this needs to be done in the RPC thread...?!
    OS_NetworkAPP_RT(NULL);

    err = OS_Crypto_init(&hCrypto, &cryptoCfg);
    Debug_ASSERT(OS_SUCCESS == err);

    tlsCfg.dataport               = dataport;
    tlsCfg.library.crypto.handle  = hCrypto;

    err = OS_Tls_init(&hTls, &tlsCfg);
    Debug_ASSERT(OS_SUCCESS == err);

    return 0;
}

OS_Error_t
TlsRpcServer_connectSocket(
    void)
{
    return OS_NetworkSocket_create(NULL, &socketCfg, &socket);
}

OS_Error_t
TlsRpcServer_closeSocket(
    void)
{
    return OS_NetworkSocket_close(socket);
}

OS_Error_t
TlsRpcServer_free(
    void)
{
    OS_Error_t err;

    err = OS_Tls_free(hTls);
    Debug_ASSERT(OS_SUCCESS == err);

    err = OS_Crypto_free(hCrypto);
    Debug_ASSERT(OS_SUCCESS == err);

    return 0;
}
