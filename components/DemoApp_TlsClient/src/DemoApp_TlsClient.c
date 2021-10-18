/*
 * Performs a little demo of usage of the OS TLS API
 *
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

#include "DemoConfig.h"
#include "TlsServer_client.h"

#include "OS_Tls.h"

#include "lib_debug/Debug.h"

#include <camkes.h>
#include <string.h>


// Private functions -----------------------------------------------------------

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
        Debug_LOG_ERROR("['%s'] OS_Tls_init() failed with error code %d", get_instance_name(), err);
        return false;
    }
    Debug_LOG_INFO("['%s'] TLS Library successfully initialized", get_instance_name());

    do
    {
        seL4_Yield();
        err = OS_Tls_handshake(hTls);
    }
    while (err == OS_ERROR_WOULD_BLOCK);

    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("['%s'] OS_Tls_handshake() failed with error code %d", get_instance_name(), err);
        goto err0;
    }
    Debug_LOG_INFO("['%s'] TLS handshake succeeded", get_instance_name());

    size_t to_write = strlen(request);

    do
    {
        seL4_Yield();
        err = OS_Tls_write(hTls, request, &to_write);
    }
    while (err == OS_ERROR_WOULD_BLOCK);

    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("['%s'] OS_Tls_write() failed with error code %d", get_instance_name(), err);
        goto err0;
    }
    Debug_LOG_INFO("['%s'] HTTP request successfully sent", get_instance_name());

    static char buffer[4096] = {0};
    char* needle = buffer;
    size_t read = sizeof(buffer);

    while (read > 0)
    {
        do
        {
            seL4_Yield();
            err = OS_Tls_read(hTls, needle, &read);
        }
        while (err == OS_ERROR_WOULD_BLOCK);
        
        Debug_LOG_WARNING("['%s'] bytes read: %d, err: %d", get_instance_name(), read, err);

        switch (err)
        {
        case OS_ERROR_CONNECTION_CLOSED:
            Debug_LOG_WARNING("['%s'] connection reset by peer", get_instance_name());
            read = 0;
            break;
        case OS_SUCCESS:
            needle = &needle[read];
            read = sizeof(buffer) - (needle - buffer);
            break;
        default:
            Debug_LOG_ERROR("['%s'] HTTP page retrieval failed while reading, "
                            "OS_Tls_read returned error code %d, bytes read %zu",
                            get_instance_name(), err, (size_t) (needle - buffer));
            goto err0;

        }
    }

    // ensure buffer is null-terminated before printing it
    buffer[sizeof(buffer) - 1] = '\0';
    Debug_LOG_INFO("['%s'] Got HTTP Page:\n%s", get_instance_name(), buffer);

    retval = true;

err0:
    err = OS_Tls_free(hTls);
    if (OS_SUCCESS != err)
    {
        Debug_LOG_ERROR("['%s'] OS_Tls_free() failed with error code %d", get_instance_name(), err);
    }
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
        Debug_LOG_ERROR("['%s'] TlsServer_connect() failed with error code %d", get_instance_name(), err);
        goto err0;
    }


    Debug_LOG_INFO("['%s'] TLS Socket successfully connected", get_instance_name());

    if (!readAndPrintWebPage(&tlsConfig))
    {
        Debug_LOG_ERROR("['%s'] readAndPrintWebPage() failed", get_instance_name());
        goto err1;
    }
    retval = true;

err1:
    {
        OS_Error_t err = TlsServer_disconnect(&tlsServer);
        if (OS_SUCCESS != err)
        {
            Debug_LOG_ERROR("['%s'] TlsServer_disconnect() failed with error code %d", get_instance_name(), err);
        }
        else
        {
            Debug_LOG_INFO("['%s'] TLS Socket successfully closed", get_instance_name());
        }
    }
err0:
    return retval;
}

// Public functions ------------------------------------------------------------

int run(void)
{

    Debug_LOG_INFO("['%s'] DemoApp_TlsClient starting", get_instance_name());


    if (!demoAsComponent())
    {
        Debug_LOG_ERROR("['%s'] demoAsComponent() failed", get_instance_name());
        return -1;
    }

    Debug_LOG_INFO("['%s'] Demo completed successfully.", get_instance_name());

    return 0;
}
