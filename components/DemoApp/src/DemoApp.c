/*
 * This demo shows the usage of the TLS API in library and client mode
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "DemoConfig.h"
#include "TlsServer_client.h"

#include "OS_Socket.h"
#include "interfaces/if_OS_Socket.h"

#include "OS_Crypto.h"
#include "OS_Tls.h"


#include "lib_debug/Debug.h"
#include "lib_debug/Debug_OS_Error.h"

#include <camkes.h>
#include <string.h>


static const if_OS_Socket_t networkStackCtx =
    IF_OS_SOCKET_ASSIGN(networkStack);

static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
};

// Private functions -----------------------------------------------------------

static OS_Error_t
doBlockingTlsWrite(
    OS_Tls_Handle_t hTls,
    const void*     data,
    size_t          toWrite)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    size_t writtenLen = 0;

    while (toWrite > 0)
    {
        size_t actualLen = toWrite;
        err = OS_Tls_write(hTls, (data + writtenLen), &actualLen);

        switch (err)
        {
        case OS_SUCCESS:
            toWrite -= actualLen;
            writtenLen += actualLen;
        case OS_ERROR_WOULD_BLOCK:
            break;
        default:
            Debug_LOG_ERROR("OS_Tls_write() failed, code '%s'",
                            Debug_OS_Error_toString(err));
            return err;
        }
    };

    return err;
}

static OS_Error_t
connectSocket(
    OS_Socket_Handle_t* socket)
{
    OS_Error_t err;

    char evtBuffer[128];
    size_t evtBufferSize = sizeof(evtBuffer);
    int numberOfSocketsWithEvents;

    do
    {
        seL4_Yield();
        err = OS_Socket_create(
                  &networkStackCtx,
                  socket,
                  OS_AF_INET,
                  OS_SOCK_STREAM);
    }
    while (err == OS_ERROR_NOT_INITIALIZED);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Socket_create() failed, code %d", err);
        return err;
    }

    const OS_Socket_Addr_t dstAddr =
    {
        .addr = TLS_HOST_IP,
        .port = TLS_HOST_PORT
    };

    err = OS_Socket_connect(*socket, &dstAddr);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Socket_connect() failed, code %d", err);
        OS_Socket_close(*socket);
        return err;
    }

    // wait for socket connected
    //-> read getPendingEvents
    for (;;)
    {
        err = OS_Socket_wait(&networkStackCtx);
        if (err != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Socket_wait() failed, code %d", err);
            return err;
        }

        err = OS_Socket_getPendingEvents(
                  &networkStackCtx,
                  evtBuffer,
                  evtBufferSize,
                  &numberOfSocketsWithEvents);

        if (err != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Socket_getPendingEvents() failed, "
                            " code %d", err);
            break;
        }

        // Due to asynchronous behaviour it could be that we call
        // OS_Socket_getPendingEvents, although the event has already
        // been handled. This is no error.
        if (numberOfSocketsWithEvents == 0)
        {
            Debug_LOG_TRACE("Unexpected number of events from"
                            " OS_Socket_getPendingEvents() failed,"
                            " #events: %d",
                            numberOfSocketsWithEvents);
            continue;
        }

        // we only opened one socket, so if we get more events, this is not ok
        if (numberOfSocketsWithEvents != 1)
        {
            Debug_LOG_ERROR("Unexpected number of events from"
                            " OS_Socket_getPendingEvents() failed,"
                            " #events: %d",
                            numberOfSocketsWithEvents);
            err = OS_ERROR_INVALID_STATE;
            break;
        }

        OS_Socket_Evt_t event;
        memcpy(&event, evtBuffer, sizeof(event));

        if (event.socketHandle != socket->handleID)
        {
            Debug_LOG_ERROR("Unexpected handle received: %d, expected: %d",
                            event.socketHandle,
                            socket->handleID);
            err = OS_ERROR_INVALID_HANDLE;
            break;
        }

        // Socket has been closed by network stack
        if (event.eventMask & OS_SOCK_EV_FIN)
        {
            Debug_LOG_ERROR("OS_Socket_getPendingEvents: "
                            "OS_SOCK_EV_FIN, handle: %d",
                            event.socketHandle);
            err = OS_ERROR_NETWORK_CONN_REFUSED;
            break;
        }

        // Connection event successful - not used in this application
        if (event.eventMask & OS_SOCK_EV_CONN_EST)
        {
            Debug_LOG_INFO("OS_Socket_getPendingEvents: Connection"
                           " established, handle: %d",
                           event.socketHandle);
            err = OS_SUCCESS;
            break;
        }

        // Remote socket requested to be closed is only valid for clients
        if (event.eventMask & OS_SOCK_EV_CLOSE)
        {
            Debug_LOG_ERROR("OS_Socket_getPendingEvents:"
                            " OS_SOCK_EV_CLOSE handle: %d",
                            event.socketHandle);
            err = OS_ERROR_CONNECTION_CLOSED;
            break;
        }

        // Error received - print error
        if (event.eventMask & OS_SOCK_EV_ERROR)
        {
            Debug_LOG_ERROR("OS_Socket_getPendingEvents:"
                            " OS_SOCK_EV_ERROR handle: %d, code: %d",
                            event.socketHandle,
                            event.currentError);
            err = event.currentError;
            break;
        }
    }

    if (err != OS_SUCCESS)
    {
        OS_Socket_close(*socket);
    }

    return err;
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

    do
    {
        seL4_Yield();
        err = OS_Tls_handshake(hTls);
    }
    while (err == OS_ERROR_WOULD_BLOCK);

    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("OS_Tls_handshake() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("TLS handshake succeeded");

    // For the sake of simplicity, the following function does not implement any
    // timeout and will block until all bytes are written or an error occurs.
    err = doBlockingTlsWrite(hTls, request, strlen(request));
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("doBlockingTlsWrite() failed with error code %d", err);
        goto err0;
    }
    Debug_LOG_INFO("HTTP request successfully sent");

    // A couple of assumptions are made for simplification:
    // - The HTTP response is smaller than 4096 bytes
    // - The HTTP server closes the socket after the response (which will cause
    //   an error and exit the Rx-loop).
    static char buffer[4096] = {0};
    size_t remainingLen = sizeof(buffer);
    size_t readLen = 0;

    while (remainingLen > 0)
    {
        size_t actualLen = remainingLen;

        err = OS_Tls_read(hTls, (buffer + readLen), &actualLen);

        switch (err)
        {
        case OS_SUCCESS:
            Debug_LOG_INFO("OS_Tls_read() - bytes read: %zu", actualLen);
            remainingLen -= actualLen;
            readLen += actualLen;
            break;
        case OS_ERROR_WOULD_BLOCK:
            // Donate the remaining timeslice to a thread of the same priority
            // and try to read again with the next turn.
            seL4_Yield();
            break;
        case OS_ERROR_CONNECTION_CLOSED:
            Debug_LOG_WARNING("connection closed by network stack");
            remainingLen = 0;
            break;
        case OS_ERROR_NETWORK_CONN_SHUTDOWN:
            Debug_LOG_WARNING("connection reset by peer");
            remainingLen = 0;
            break;
        default:
            Debug_LOG_ERROR("HTTP page retrieval failed while reading, "
                            "OS_Tls_read returned error code %d, bytes read %zu",
                            err, readLen);
            goto err0;
        }
    }

    // ensure buffer is null-terminated before printing it
    buffer[sizeof(buffer) - 1] = '\0';
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
    OS_Socket_Handle_t socket;
    OS_Tls_Config_t tlsConfig =
    {
        .mode = OS_Tls_MODE_LIBRARY,
        .library = {
            .socket = {
                .context    = &socket,
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
        OS_Socket_close(socket);
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
    OS_Error_t err;
    bool retval = false;

    static const if_TlsServer_t tlsServer =
        IF_TLSSERVER_ASSIGN(tls);
    static const OS_Tls_Config_t tlsConfig =
    {
        .mode = OS_Tls_MODE_CLIENT,
        .rpc = IF_OS_TLS_ASSIGN(tls)
    };

    do
    {
        seL4_Yield();
        err = TlsServer_connect(&tlsServer, TLS_HOST_IP, TLS_HOST_PORT);
    }
    while (err == OS_ERROR_WOULD_BLOCK);

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
            Debug_LOG_ERROR("TlsServer_disconnect() failed with error code %d",
                            err);
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

    Debug_LOG_INFO("Running TLS API in 'library' mode");

    if (!demoAsLibrary())
    {
        Debug_LOG_ERROR("demoAsLibrary() failed");
        return -1;
    }

    Debug_LOG_INFO("Demo TLS API in 'library' mode completed, now running"
                   " TLS API in 'component' mode");

    if (!demoAsComponent())
    {
        Debug_LOG_ERROR("demoAsComponent() failed");
        return -1;
    }

    Debug_LOG_INFO("Demo completed successfully.");

    return 0;
}
