/**
 *
 * Performs a little demo of usage of the OS TLS API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "DemoConfig.h"
#include "TlsRpcServer.h"

#include "OS_Crypto.h"
#include "OS_Tls.h"
#include "OS_Network.h"
#include "OS_NetworkStackClient.h"

#include "LibDebug/Debug.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 256

extern OS_Error_t
OS_NetworkAPP_RT(
    OS_Network_Context_t ctx);

static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.entropy = OS_CRYPTO_ASSIGN_Entropy(entropy_rpc, entropy_port)
};

// Private functions -----------------------------------------------------------

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
    OS_NetworkSocket_Handle_t* socket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_write(*socket, buf, n, &n)) != OS_SUCCESS)
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
    OS_NetworkSocket_Handle_t* socket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_read(*socket, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during socket read...error:%d", err);
        return -1;
    }

    return n;
}

static OS_Error_t
connectSocket(
    OS_NetworkSocket_Handle_t* socket)
{
    OS_Network_Socket_t socketCfg =
    {
        .domain = OS_AF_INET,
        .type   = OS_SOCK_STREAM,
        .name   = TLS_HOST_IP,
        .port   = TLS_HOST_PORT
    };

    return OS_NetworkSocket_create(NULL, &socketCfg, socket);
}

static OS_Error_t
closeSocket(
    OS_NetworkSocket_Handle_t* socket)
{
    return OS_NetworkSocket_close(*socket);
}

bool
readAndPrintWebPage(
    const OS_Tls_Config_t* config)
{
    OS_Tls_Handle_t hTls;
    const char request[] =
        "GET / HTTP/1.0\r\nHost: www.example.org\r\nConnection: close\r\n\r\n";
    char buffer[4096] = {0};

    OS_Error_t err = OS_Tls_init(&hTls, config);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_init() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("TLS Library successfully initialized");

    err = OS_Tls_handshake(hTls);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_handshake() failed with error code %d", err);
        goto err1;
    }
    Debug_LOG_INFO("TLS handshake succeeded");

    err = OS_Tls_write(hTls, request, strlen(request));
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_write() failed with error code %d", err);
        goto err1;
    }
    Debug_LOG_INFO("HTTP request successfully sent");

    char* needle = buffer;
    size_t read = sizeof(buffer);

    while (read > 0)
    {
        size_t wantedToRead = read;
        err = OS_Tls_read(hTls, needle, &read);
        if (OS_SUCCESS != err)
        {
            Debug_LOG_ERROR("HTTP page retrivial failed while reading, OS_Tls_read returned error code %d, bytes read %zu",
                            err, (size_t) (needle - buffer));
            goto err1;
        }
        else
        {
            Debug_ASSERT(read <= wantedToRead);

            if (0 == read)
            {
                Debug_LOG_WARNING("connection reset by peer");
            }
            else
            {
                needle = &needle[read];
                read = sizeof(buffer) - (needle - buffer);
            }
        }
    }
    // before to print it we make sure it is correctly terminated anyway
    buffer[sizeof(buffer) - 1] = 0;
    Debug_LOG_INFO("Got HTTP Page:\n%s", buffer);
 err1:
 {
    OS_Error_t err = OS_Tls_free(hTls);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_free() failed with error code %d", err);
    }
 }
 err0:
    return (OS_SUCCESS == err);
}

bool
demoAsLibrary(void)
{
    OS_NetworkSocket_Handle_t socket;
    OS_Tls_Config_t tlsConfig =
    {
        .mode = OS_Tls_MODE_LIBRARY,
        .library = {
            .socket = {
                .context    = &socket,
                .recv       = recvFunc,
                .send       = sendFunc,
            },
            .flags = OS_Tls_FLAG_NONE,
            .crypto = {
                .policy = NULL,
                .caCert = TLS_HOST_CERT,
                .cipherSuites = {
                    OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 2
            }
        }
    };

    OS_Error_t err = OS_Crypto_init(&tlsConfig.library.crypto.handle,
                                    &cryptoCfg);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Crypto_init() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("Crypto Library for TLS successfully initialized");

    err = connectSocket(&socket);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("connectSocket() failed with err %d", err);
        goto err1;
    }
    Debug_LOG_INFO("Socket successfully connected");

    if (!readAndPrintWebPage(&tlsConfig))
    {
        Debug_LOG_ERROR("readAndPrintWebPage() failed");
        goto err2;
    }
err2:
{
    OS_Error_t err = closeSocket(&socket);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("closeSocket() failed with error code %d", err);
    }
    else
    {
        Debug_LOG_INFO("Socket successfully closed");
    }
}
err1:
{
    OS_Error_t err = OS_Crypto_free(tlsConfig.library.crypto.handle);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Crypto_free() failed with error code %d", err);
    }
    else
    {
        Debug_LOG_INFO("Crypto Library for TLS Library successfully freed");
    }
}
err0:
    return (OS_SUCCESS == err);
}

OS_Error_t
demoAsComponent(void)
{
    OS_Tls_Config_t tlsConfig =
    {
        .mode = OS_Tls_MODE_CLIENT,
        .dataport = OS_DATAPORT_ASSIGN(tlsClientDataport)
    };

    OS_Error_t err = TlsRpcServer_init();
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("TlsRpcServer_init() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("TLS RPC Server successfully initialized");

    err = TlsRpcServer_connectSocket();
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("TlsRpcServer_connectSocket() failed with error code %d", err);
        goto err1;
    }
    Debug_LOG_INFO("TLS Socket successfully connected");

    if (!readAndPrintWebPage(&tlsConfig))
    {
        Debug_LOG_ERROR("readAndPrintWebPage() failed");
        goto err2;
    }
 err2:
 {
    OS_Error_t err = TlsRpcServer_closeSocket();
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("TlsRpcServer_closeSocket() failed with error code %d", err);
    }
    else
    {
        Debug_LOG_INFO("TLS Socket successfully closed");
    }
 }
 err1:
 {
    OS_Error_t err = TlsRpcServer_free();
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("TlsRpcServer_free() failed with error code %d", err);
    }
    else
    {
        Debug_LOG_INFO("TLS RPC Server successfully freed");
    }
 }
err0:
    return (OS_SUCCESS == err);
}

// Public functions ------------------------------------------------------------
int run(void)
{
    initNetworkClientApi();
    OS_NetworkAPP_RT(NULL);

    Debug_LOG_INFO("Running TLS API in 'library' mode");
    if (!demoAsLibrary())
    {
        Debug_LOG_ERROR("demoAsLibrary() failed");
    }
    Debug_LOG_INFO("Demo TLS API in 'library' mode completed, now running TLS API in 'component' mode");
    if (!demoAsComponent())
    {
        Debug_LOG_ERROR("demoAsComponent() failed");
    }
    Debug_LOG_INFO("Demo completed.");

    return 0;
}
