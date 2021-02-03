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

// PointBlank ROOT CA with openssl
#define TLS_ROOT_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIEETCCAvmgAwIBAgIUBfhiq0X+JX+5oxpL7/ghOUounccwDQYJKoZIhvcNAQEL\r\n" \
"BQAwgZcxCzAJBgNVBAYTAkRFMQwwCgYDVQQIDANOUlcxDDAKBgNVBAcMA0xFVjEZ\r\n" \
"MBcGA1UECgwQU3RlZW4gSGFyYmFjaCBBRzERMA8GA1UECwwIU2VjdXJpdHkxHjAc\r\n" \
"BgNVBAMMFVN0ZWVuIEhhcmJhY2ggUm9vdCBDQTEeMBwGCSqGSIb3DQEJARYPaW5m\r\n" \
"b0BoYXJiYWNoLmRlMB4XDTIwMTEyNTEzNTM0M1oXDTMwMTEyMzEzNTM0M1owgZcx\r\n" \
"CzAJBgNVBAYTAkRFMQwwCgYDVQQIDANOUlcxDDAKBgNVBAcMA0xFVjEZMBcGA1UE\r\n" \
"CgwQU3RlZW4gSGFyYmFjaCBBRzERMA8GA1UECwwIU2VjdXJpdHkxHjAcBgNVBAMM\r\n" \
"FVN0ZWVuIEhhcmJhY2ggUm9vdCBDQTEeMBwGCSqGSIb3DQEJARYPaW5mb0BoYXJi\r\n" \
"YWNoLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7rqjlZoR6ceI\r\n" \
"3KdKK1iu5Ef8+3diAgMhEIywxWv+L1KQ6h38RwwvZPTAaUdmZoLgK0CgeW1MP5co\r\n" \
"7ilIg8bfzs9gtBinQs0cMdGjyR6YAmPPQkOgrZuZBAqJHXTYJA38Z07XBMCucTU1\r\n" \
"xcVodrU3BMxF/3nTkm4TRo9u4qOXxtaZgzwDaRRT1yUmGyu0GM1j3VXGIrWejoMZ\r\n" \
"HiN0sQV8DE5iqs2pE6ObhO6kuge5bfePT2cu6D5fadPbmwrPdkeu+lKC4leutJIu\r\n" \
"iPA81ka099qEtRUch7D+eUqruNOkCxADZgacOlXJohyJfO+x+VThoDr4tZg1v3Mv\r\n" \
"HZDPXao74wIDAQABo1MwUTAdBgNVHQ4EFgQU8uzsQw5jIOuqXgB/Fxj0geNT4eAw\r\n" \
"HwYDVR0jBBgwFoAU8uzsQw5jIOuqXgB/Fxj0geNT4eAwDwYDVR0TAQH/BAUwAwEB\r\n" \
"/zANBgkqhkiG9w0BAQsFAAOCAQEAe7xO19pFodcCMHStDfMSxCPH/cBbeKwsSR/d\r\n" \
"QfWETFHy2MNYlhyw5/G/gtsT614rSEaFOAzOL7XzdrpFaD5G9XlEvlCVPE4NJZMp\r\n" \
"WbwmmyUDvOZJDQ5FXYl4013lJN+R46iHZYlO/VrT7/H5itroiWkirEJEPPSfU4SE\r\n" \
"VtHxz3qQ74i/fE2a611wkAuCLNVHt6J6EAY7fa8UGGwzbkWD72jR76nbbaR/Xd+A\r\n" \
"RkWrsFlnxC8TnHrgCrKVP7oozniSxupsWKRZZn1ApPfRXUyOIRWdUxRkQcE95qMg\r\n" \
"q8HvMfgl4aGs/OWNsaX81g2+VzrmZnYzPOwnMlTeIe4X17H8EA==\r\n" \
"-----END CERTIFICATE-----\r\n"

// PointBlank Intermediate CA
#define TLS_INTERMEDIATE_ROOT_CERT \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIECzCCAvOgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBlzELMAkGA1UEBhMCREUx\r\n" \
"DDAKBgNVBAgMA05SVzEMMAoGA1UEBwwDTEVWMRkwFwYDVQQKDBBTdGVlbiBIYXJi\r\n" \
"YWNoIEFHMREwDwYDVQQLDAhTZWN1cml0eTEeMBwGA1UEAwwVU3RlZW4gSGFyYmFj\r\n" \
"aCBSb290IENBMR4wHAYJKoZIhvcNAQkBFg9pbmZvQGhhcmJhY2guZGUwHhcNMjAx\r\n" \
"MTI1MTQwMDM5WhcNMzAxMTIzMTQwMDM5WjCBkTELMAkGA1UEBhMCREUxDDAKBgNV\r\n" \
"BAgMA05SVzEZMBcGA1UECgwQU3RlZW4gSGFyYmFjaCBBRzERMA8GA1UECwwIU2Vj\r\n" \
"dXJpdHkxIzAhBgNVBAMMGlBvaW50QmxhbmsgSW50ZXJtZWRpYXRlIENBMSEwHwYJ\r\n" \
"KoZIhvcNAQkBFhJpbmZvQHBvaW50YmxhbmsuZGUwggEiMA0GCSqGSIb3DQEBAQUA\r\n" \
"A4IBDwAwggEKAoIBAQDbGZULwjEn+jkr68apS78mO1i0TbfCcsITdWYXRuugO+91\r\n" \
"TlMCaVCyvoD0wg22EYyUvncUpWSX0utaKwQzBHWEQ8vTmy1onQ5pYNToN76hFmz7\r\n" \
"UNzPnqWTlFmhv7kP4Y4lFfmIE3oOISE913YDSZEjGIvxR91GYOp9b+o0jStAy1if\r\n" \
"CbFILNHHi5qiAw5jqCPypxzNuYc3jWi7bLilO341zLqVGkkbblN2J8vtIj/t6Nap\r\n" \
"L/SdkdZN8wJOniFuId5Zf5V2DMxEuccCSj7xnoDN5ShxjZfA4uPsMWRf3+QkeyqP\r\n" \
"VYdCJ9i2DJW20cItqerXHkqSpv+iwjuEKWQfMvaPAgMBAAGjZjBkMB0GA1UdDgQW\r\n" \
"BBQrb2ZxRHKGkHs4X8CVSP91NCJesjAfBgNVHSMEGDAWgBTy7OxDDmMg66peAH8X\r\n" \
"GPSB41Ph4DASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkq\r\n" \
"hkiG9w0BAQsFAAOCAQEA1XgYc5N836Mqvi93VA6LHMyxyp1wg8hR/m/AXPYrIycu\r\n" \
"4yWwgCDPtJNIUYw+H1DLPj/Vb+OPlg++fAtVqipBBwoHCUXqvXNqAwnNJB4ihhFl\r\n" \
"QUEvQMqRMrvNFWXMfhzACgBMxznCmIG9xlBd+jckCqmSOpghREJY6NpSXDnMg4NL\r\n" \
"G/aKPandaK2yvoUiod+WADXO7+967E42sNJEW13deVy/pZfbZ3AlqqL6Ll9LuZRA\r\n" \
"w9mB+VFOMVMwU7ui4DGp8+eXpT1cLtBbrlnUUjMFRdjRDZ2w7cIP2yAOWr85PaPi\r\n" \
"y7gYzwgqn1Hd13LB0NtEJJlQmWr9FSB/4TUu11vaUg==\r\n" \
"-----END CERTIFICATE-----\r\n"

// PointBlank user Cert
#define TLS_USER_CERT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIEGTCCAwGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBlzELMAkGA1UEBhMCREUx\r\n" \
    "DDAKBgNVBAgMA05SVzEMMAoGA1UEBwwDTEVWMRkwFwYDVQQKDBBTdGVlbiBIYXJi\r\n" \
    "YWNoIEFHMREwDwYDVQQLDAhTZWN1cml0eTEeMBwGA1UEAwwVU3RlZW4gSGFyYmFj\r\n" \
    "aCBSb290IENBMR4wHAYJKoZIhvcNAQkBFg9pbmZvQGhhcmJhY2guZGUwHhcNMjAx\r\n" \
    "MTI1MTQwNjU4WhcNMjExMTI1MTQwNjU4WjCBijELMAkGA1UEBhMCREUxDDAKBgNV\r\n" \
    "BAgMA05SVzEZMBcGA1UECgwQU3RlZW4gSGFyYmFjaCBBRzETMBEGA1UECwwKcG9p\r\n" \
    "bnRibGFuazEaMBgGA1UEAwwRcG9pbnRibGFuayBjbGllbnQxITAfBgkqhkiG9w0B\r\n" \
    "CQEWEmluZm9AcG9pbnRibGFuay5kZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\r\n" \
    "AQoCggEBAPJ/bYNWZgTbXRebfkWuvrGgWWF47oeBTeOqXzZVKiU3LjZIBjeqkbtl\r\n" \
    "T5kl+0fSa7Fo0dkznAFelnfAJFVTmQh0KQbis4uiVv7UqAFvE7HMywSTHZjVjyc0\r\n" \
    "KxfeVbgVif4457lIHRyyIQGQkIvrC82qq2yA+1g278SLf/GMBv21zdEzK19evauw\r\n" \
    "H76wwQEMjJRyL5IsrVqkUmL8Ux0aHgsTJ4Hl4N20WIZwcNLhlnBtk03rBwnoRglt\r\n" \
    "jFgTNn/xBqWe87PEMBLOsndIbLjW0kv1vV7FhRNyCh9nlWMYQwlnCUF8OGSL/lss\r\n" \
    "aGxo7h8NcWI+2a4CjfYcUWXfCTNYOS0CAwEAAaN7MHkwCQYDVR0TBAIwADAsBglg\r\n" \
    "hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\r\n" \
    "BBYEFNzyEsuz17M6ykLF4wCYdDzs2r3/MB8GA1UdIwQYMBaAFPLs7EMOYyDrql4A\r\n" \
    "fxcY9IHjU+HgMA0GCSqGSIb3DQEBCwUAA4IBAQBclFBWd7fJn2ez2u3IQAtWtmX9\r\n" \
    "5mTasBavcKyCbKbKWqXX4a85HepTs4axpG4SvIvGZDpKrsHPcfe8hee9UpcjkAgz\r\n" \
    "V+UKmSKUwuM47wGvHt7D+3nSb5kxVj0/o0d3EUui4PfrvHX2dl4ZXI+v8mQFs8r+\r\n" \
    "n/B3X3/s0NwseAbFjxQz+iMTasyfhDut4/iXmdT5/KbjqP72OIFeq+IOYYgWv4ha\r\n" \
    "KaZlFoa/0jF6NXdsIeBpjempXgdiWX35mKdBtuTrNQKHpo5d704ykXlCNNFApcQd\r\n" \
    "AcMZFkF2odW7CZCWn958FfXyUHxX1G7JFzU4WH8nV0CI7GfmC4OEsxGQlNuU\r\n" \
    "-----END CERTIFICATE-----\r\n"

// PointBlank user Key
#define TLS_USER_KEY \
    "-----BEGIN RSA PRIVATE KEY-----\r\n" \
    "MIIEpQIBAAKCAQEA8n9tg1ZmBNtdF5t+Ra6+saBZYXjuh4FN46pfNlUqJTcuNkgG\r\n" \
    "N6qRu2VPmSX7R9JrsWjR2TOcAV6Wd8AkVVOZCHQpBuKzi6JW/tSoAW8TsczLBJMd\r\n" \
    "mNWPJzQrF95VuBWJ/jjnuUgdHLIhAZCQi+sLzaqrbID7WDbvxIt/8YwG/bXN0TMr\r\n" \
    "X169q7AfvrDBAQyMlHIvkiytWqRSYvxTHRoeCxMngeXg3bRYhnBw0uGWcG2TTesH\r\n" \
    "CehGCW2MWBM2f/EGpZ7zs8QwEs6yd0hsuNbSS/W9XsWFE3IKH2eVYxhDCWcJQXw4\r\n" \
    "ZIv+WyxobGjuHw1xYj7ZrgKN9hxRZd8JM1g5LQIDAQABAoIBAH5j6EJiD75MT1L0\r\n" \
    "mnXbREz0VGG3VCuQO3aD4ChDbzoCbrWgCI2O+3H+teQOpc+jXroS9f0NJyyXjjlQ\r\n" \
    "Dh/i+IotcQzDr+0BafJcCEznBg7PvKjfvLdh58D5MdS471iI8WltY2lwqqvAM+/K\r\n" \
    "12v10Csb30koWNh7mbCJPOA6qZIl4iwV23xurpYH3rLEHaQY16gkRgmaty6zEFX5\r\n" \
    "/jY5JFCoC7t5UtaSb1nOxE5VVqeqHgi7KEDI92xpLw6hc/OSJEUrfBV/LLtCw8AC\r\n" \
    "LRmDbBOzQjQFHdnVv6GEi5l0GGmHlperEipnSn+X3B+LOcpuBGhVngbSHCOBAP27\r\n" \
    "wEB0KUECgYEA+bLYsqOxBX1zdpwz3ERzwsY1PP94KHwxFyCp4ov6f2bQ6e38QCnQ\r\n" \
    "98QMC64Kk62nO/vfvvxvT5S+OVtb0GWhiAAS+sd4+DXyU4iI0maVSlTe9qBpfVgU\r\n" \
    "zP+5kcg0vdONSTbCldLzgkNsNwn/y8oxYHZlnpm+2RvAcIz7xq7RbJUCgYEA+J4P\r\n" \
    "lsTs91MbXUE5e/Iib4iRpmYm1ePIz9bB3ias36Lcr551AnpR+84z538XovzOmjX1\r\n" \
    "3pqw+cXoF5YkRppVEmZqCt9ooBBtZgBvrBnNiHOQYln/Q2Gztxxw1bz59cv7ajgw\r\n" \
    "lx72akOXZP8gl23wHYZIIgdq8N9bUeuDglcL3DkCgYEA6gwGbCNcyS2WraWqQpty\r\n" \
    "+i15N2yqPyBxjyERvATCzuobhjmJCMdpVOPQ+p2u0k+iAmqLhePtneVpDDAi9kpc\r\n" \
    "xzJyl9ei/tzp//xpavW2l47H0tn3JwMJtEE6unezX/7MXsTSTUcG8qGp7EkWF/m0\r\n" \
    "oJs5kxi/N5d4oMa1NL0mFaUCgYEAy4A1qmeOv/Na1r5o2zebUEgtUFMVPsawvM9A\r\n" \
    "6SInJvccRPQjOt/882wZuEejhVoBkuDQXGGqswh3rbbMAq6ZK/KAol20OjC4G2II\r\n" \
    "BosoXaSabqbT9semXx/8jDefMr7BEHTl8Qz7Dog9CAJ9HvZyMPiVWqVPt9Jb4XYx\r\n" \
    "syKlJqECgYEA36dDhR3lpi9/7rIAdSfxvlhF1Ij7J5ycv/oOAxdM/oFXNPr1V7gs\r\n" \
    "eEhFIMn+FLcI3PGbHpw1TvK1fSR+CY3JrArXXRrBYIf1NnU7YWsRFUMu3OTgnDPx\r\n" \
    "daHms/FKYpr2759XC+SQudb+7kb9pmKQtL0n0QLBBPXjhWXzWG4u0eo=\r\n" \
    "-----END RSA PRIVATE KEY-----\r\n"
