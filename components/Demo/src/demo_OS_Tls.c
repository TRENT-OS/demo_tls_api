/**
 *
 * Performs a little demo of usage of the OS TLS API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "DemoConfig.h"
#include "TlsServer.h"

#include "OS_Crypto.h"
#include "OS_Tls.h"
#include "OS_Network.h"
#include "OS_NetworkStackClient.h"

#include "lib_debug/Debug.h"

#include <camkes.h>
#include <string.h>

#define MAX_NW_SIZE 256

static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
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
    bool retval = false;
    OS_Tls_Handle_t hTls;
    const char request[] =
        "GET / HTTP/1.0\r\nHost: www.example.org\r\nConnection: close\r\n\r\n";

    OS_Error_t err = OS_Tls_init(&hTls, config);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_init() failed with error code %d", err);
        return false;
    }
    Debug_LOG_INFO("TLS Library successfully initialized");

    err = OS_Tls_handshake(hTls);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_handshake() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("TLS handshake succeeded");

    size_t to_write = strlen(request);
    err = OS_Tls_write(hTls, request, &to_write);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_write() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("HTTP request successfully sent");

    static char buffer[4096] = {0};
    char* needle = buffer;
    size_t read = sizeof(buffer);

    while (read > 0)
    {
        err = OS_Tls_read(hTls, needle, &read);
        switch (err)
        {
        case OS_ERROR_CONNECTION_CLOSED:
            Debug_LOG_WARNING("connection reset by peer");
            read = 0;
            break;
        case OS_SUCCESS:
            needle = &needle[read];
            read = sizeof(buffer) - (needle - buffer);
            break;
        default:
            Debug_LOG_ERROR("HTTP page retrieval failed while reading, "
                            "OS_Tls_read returned error code %d, bytes read %zu",
                            err, (size_t) (needle - buffer));
            goto err0;

        }
    }
    // before to print it we make sure it is correctly terminated anyway
    buffer[sizeof(buffer) - 1] = 0;
    Debug_LOG_INFO("Got HTTP Page:\n%s", buffer);
    retval = true;

err0:
    err = OS_Tls_free(hTls);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_free() failed with error code %d", err);
    }
    return retval;
}

bool
demoAsLibrary(void)
{
    bool retval = false;
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
                .policy     = NULL,
                .caCerts    = TLS_HOST_CERT,
                .cipherSuites =
                OS_Tls_CIPHERSUITE_FLAGS(
                    OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
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
    retval = true;

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
    return retval;
}

OS_Error_t
demoAsComponent(void)
{
    bool retval = false;

    static const if_TlsServer_t tlsServer =
        IF_TLSSERVER_ASSIGN(
            tlsServer_rpc);
    static const OS_Tls_Config_t tlsConfig =
    {
        .mode = OS_Tls_MODE_CLIENT,
        .rpc = IF_OS_TLS_ASSIGN(
            tlsServer_rpc,
            tlsServer_port)
    };

    OS_Error_t err = TlsServer_connect(&tlsServer, TLS_HOST_IP, TLS_HOST_PORT);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("TlsServer_connect() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("TLS Socket successfully connected");

    if (!readAndPrintWebPage(&tlsConfig))
    {
        Debug_LOG_ERROR("readAndPrintWebPage() failed");
        goto err1;
    }
    retval = true;

err1:
    {
        OS_Error_t err = TlsServer_disconnect(&tlsServer);
        if (OS_SUCCESS != err)
        {
            Debug_LOG_ERROR("TlsServer_disconnect() failed with error code %d", err);
        }
        else
        {
            Debug_LOG_INFO("TLS Socket successfully closed");
        }
    }
err0:
    return retval;
}

// Public functions ------------------------------------------------------------
int run(void)
{
    initNetworkClientApi();

    Debug_LOG_INFO("Running TLS API in 'library' mode");
    if (!demoAsLibrary())
    {
        Debug_LOG_ERROR("demoAsLibrary() failed");
        return -1;
    }
    Debug_LOG_INFO("Demo TLS API in 'library' mode completed, now running TLS API in 'component' mode");
    if (!demoAsComponent())
    {
        Debug_LOG_ERROR("demoAsComponent() failed");
        return -1;
    }
    Debug_LOG_INFO("Demo completed successfully.");
    return 0;
}
