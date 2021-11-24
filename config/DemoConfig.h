/*
 * TLS demo configuration
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */
#pragma once

#define TLS_HOST_IP     "172.17.0.1"
#define TLS_HOST_PORT   5560

/*
 * Client root cert.
 *
 * Both the client and the server cert have the same root cert. Hence, it is
 * sufficient to trust this root cert to authenticate the server.
 */
#define TLS_CLIENT_ROOT_CERT                                               \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDrTCCApWgAwIBAgIUb63F+BTbaucqFFOSCu/HwcPalqMwDQYJKoZIhvcNAQEL\r\n" \
    "BQAwZjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJheWVybjESMBAGA1UEBwwJT3R0\r\n" \
    "b2JydW5uMRwwGgYDVQQKDBNIRU5TT0xEVCBDeWJlciBHbWJIMRQwEgYDVQQDDAtk\r\n" \
    "ZXYtaGMtcm9vdDAeFw0yMTA4MzAwNzQzMzhaFw0yMjA4MzAwNzQzMzhaMGYxCzAJ\r\n" \
    "BgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU90dG9icnVubjEc\r\n" \
    "MBoGA1UECgwTSEVOU09MRFQgQ3liZXIgR21iSDEUMBIGA1UEAwwLZGV2LWhjLXJv\r\n" \
    "b3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCoJDXsZQL3KjkCyYd\r\n" \
    "kAIbaZwnx0t7JqM7c/HjrPiU2/i/elY7JmzikzUwLCpcG0wQT185TCTybOWh10es\r\n" \
    "bwdeyhwTtzAgFVzp8YYGyJ+UYpToa4cxb74la2NXV8g66qSC6ChwoOO4ILWMMHIS\r\n" \
    "2PfFZQvs9POS4PFy3x5kbsdzxtQ2eucsagAwQ8QlxNEBgFaqWLnAmSptdAo3ToTl\r\n" \
    "inZ6IcMKjX6W4LSvWYosR0ls8rzA1GzAIw/LK2XaEKGd0WtVVdnEAYgUJzbguC1U\r\n" \
    "pm3X15yncgrF3nRMvEi0YtApwp9NVDtxjabw5qEzy6bUZJn1U5EpX7twcJPRHl6Y\r\n" \
    "ByhTAgMBAAGjUzBRMB0GA1UdDgQWBBSsYHyPP6MLz/8gjK1in5QsD9yBZjAfBgNV\r\n" \
    "HSMEGDAWgBSsYHyPP6MLz/8gjK1in5QsD9yBZjAPBgNVHRMBAf8EBTADAQH/MA0G\r\n" \
    "CSqGSIb3DQEBCwUAA4IBAQAPejHIFCC896MacWmBql+lCrcOFAYCmDS92NCQDlbz\r\n" \
    "K0nHjGsI+q0UJmm8F7qfzReenmKl8l4o5i9FqHHDaXHJjO+0sXEz60ZkFy/SaXmz\r\n" \
    "czba3rJAPAQAc3KY3QZxobWYSWso1FX9NT00g4whfrdWCJjDC65rV+0zvl0CBCBU\r\n" \
    "Kt5JlmT1Ywqozg2U9DCa99azNAG5YBeAVxBh+FIESP7SqWE1+EfKr8aIgRNhOF4z\r\n" \
    "p3laRmoVmmA9SP/Z3AYWKuGpHFyakLqq7h9EJSPv6k/eGxm9inwhXOHKu+ZMznQS\r\n" \
    "NE0nuBs/3Ekl/IGHyZbAkcWCPw3wk3MPj6Y7j35sCWF2\r\n"                     \
    "-----END CERTIFICATE-----\r\n"

// Client cert.
#define TLS_CLIENT_CERT                                                    \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDVTCCAj0CFBF465c9x1Db/lEAS8MuY2OPnibPMA0GCSqGSIb3DQEBCwUAMGYx\r\n" \
    "CzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU90dG9icnVu\r\n" \
    "bjEcMBoGA1UECgwTSEVOU09MRFQgQ3liZXIgR21iSDEUMBIGA1UEAwwLZGV2LWhj\r\n" \
    "LXJvb3QwHhcNMjEwODMwMDc0MzM4WhcNMjIwODMwMDc0MzM4WjBoMQswCQYDVQQG\r\n" \
    "EwJERTEPMA0GA1UECAwGQmF5ZXJuMRIwEAYDVQQHDAlPdHRvYnJ1bm4xHDAaBgNV\r\n" \
    "BAoME0hFTlNPTERUIEN5YmVyIEdtYkgxFjAUBgNVBAMMDWRldi1oYy1jbGllbnQw\r\n" \
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7sLXwkdy2IfD0RonWnkcy\r\n" \
    "3xcgQAWfA6JFywsbzb8yIRbcQIVGIeXeoumV07ccxtv/qXoLPif8NfwmGTilWBA2\r\n" \
    "Qqx5feajvCUSN7n7qaJqXrh8IV5HsPGJiJdeXfu6KN+NnLeW7zz04IrYqjphEjYV\r\n" \
    "jWt5Hn1qN8DZ3R8fdG7UWAkZVqnOJvr/ae/UKccBHwxO9lD5iiI1AsQ1x5Kn2dAe\r\n" \
    "NEBx+dcWXXjOKSokUmKcIsE0xOv6hWzoZls5tXqs6PB4z8RS6DwEjRmXo2ujSWZJ\r\n" \
    "eBVd8mDtbh4d9S2QIGGBnergVlquBh0PB3+9B7krHy29bhn6sMerMmYwc8mcA8gd\r\n" \
    "AgMBAAEwDQYJKoZIhvcNAQELBQADggEBALQbAypqp+uwOBCa/5BPbR6ZUY1vbslt\r\n" \
    "4mznGRXTNisXuVxBDpmjt9iuFBQ9PXggVml5GFh/5YFPCrwRxiF60dOtRj1lKh9h\r\n" \
    "7n5/XteQrPNs1jXADhpuDxYnl8UIxgSzgmOcE7hji8BFTtHa3wjTF9Os+2g86lIE\r\n" \
    "huEDaCHuTL4E9ktahsB8G/J/pG1WM6NBp5Ne+hTkjaTX6OeE7nAjV9sUU9hrfV8V\r\n" \
    "f9sj095cHCCXKu5hiASC6SO1qqygMfYo/9DfBHfxZmH3drMfssT0tq1+AJK8JU/P\r\n" \
    "r8HS+HO+Xi5840AzL+xDWHIwOE+c+NsDVQaA3FftMzsBTDVTKZACn5A=\r\n"         \
    "-----END CERTIFICATE-----\r\n"

// CLient private key.
#define TLS_CLIENT_KEY                                                     \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "MIIEpAIBAAKCAQEAu7C18JHctiHw9EaJ1p5HMt8XIEAFnwOiRcsLG82/MiEW3ECF\r\n" \
    "RiHl3qLpldO3HMbb/6l6Cz4n/DX8Jhk4pVgQNkKseX3mo7wlEje5+6mial64fCFe\r\n" \
    "R7DxiYiXXl37uijfjZy3lu889OCK2Ko6YRI2FY1reR59ajfA2d0fH3Ru1FgJGVap\r\n" \
    "zib6/2nv1CnHAR8MTvZQ+YoiNQLENceSp9nQHjRAcfnXFl14zikqJFJinCLBNMTr\r\n" \
    "+oVs6GZbObV6rOjweM/EUug8BI0Zl6Nro0lmSXgVXfJg7W4eHfUtkCBhgZ3q4FZa\r\n" \
    "rgYdDwd/vQe5Kx8tvW4Z+rDHqzJmMHPJnAPIHQIDAQABAoIBAF8zgPWnZsZTbP7a\r\n" \
    "kKv12LNrCTXog3FmzHaOSPIvaF2q/wd1CqTKKOjGxaijnOvRymFhu2/cdTeuwlko\r\n" \
    "zdzAUGjVZNqzC7vdgQg+j+2g26sMpJMB8ep3S+yxBeZt0XNZrBsOdOjwLIEhLAw+\r\n" \
    "PCJktF42P19OIdswsHdRe6neyyCVMHUpdtnhFLeiV8fSYjxtS7yZEuTkhjZSANy9\r\n" \
    "wsnQxgVp9zt4LL50pag6HlWA9R4Aj5XTPqTBe78nTS8Lm1Q94DVKivtgUNbQhhbH\r\n" \
    "7s6eTkvBpCB+RBOFviLRUExD1YM6X8SMe3tbxItR8HmStcLvcBseioN9d6zFvFPA\r\n" \
    "DK+WWQECgYEA4yhm0dIgLSOIML8tk56cqH9imuGJPUgViQKW3M/MslL3V/i9YXsT\r\n" \
    "9Cgh9gs2uAeh2oDvTqr6BCAysJ6+w/NsX2JqngH0UMp95tPu2lT9Lu0+xwrJYuKL\r\n" \
    "TEOPMFBMWxwlFlHnpbUJpv9lnTbg+KTBpiNbYAp4+E+bI4z11KBVPz0CgYEA04Vy\r\n" \
    "DcYmc3kpM6UCh9QuYpBoBOg3BkPHLb+D0wDqqbTANPcbhyEjEsnqwFaJmjsghHLo\r\n" \
    "Ytv/C5AhNkUTMIa+EaAR0lgS89/GzQ2+WeZe2Is3aZH/goS79m3VH3nsn793ymok\r\n" \
    "l17seXTh+ZmsGBLe0rrAa3bBoqSxumzvPJ8fOmECgYEApHTAk9GT1/oshFY0kfY4\r\n" \
    "Jskqw0TbjhFc/fdw72ZGJShpyDfeK+/mT1Kq263crLlh1YaZOpQQM+J3sGUNaWIX\r\n" \
    "qKrg04pIriEbq3zuJQV403uRgprtl/i5rroOtYS88w1aUGF12wNJfKzUjVCI6Zqm\r\n" \
    "VDiu08ZhNCy1/bP02j5F2WUCgYEAj0nbFZGiAp+VVbL2n+UQ9xw0Gv7kJ45Ko6cV\r\n" \
    "Oh9o2EXl3vt23neINvYp3NnCpYRgZtkgq7e0crTUitsIQNtGbtIswH2BeUuidM5W\r\n" \
    "oLf6kF7eztlkaZpZanrE4WnK7fzavXhiCVj4gN65Jkj/198Qq1hveV0dl3xSGaQp\r\n" \
    "/LsegIECgYA1MFVNTrbRVqy5KwMWYdTUP00O8iD91IMU490SxlhmWShBIAufPbG0\r\n" \
    "S+iFkvApBaouuIl97QEzemg2rMyJpXqo67bbWRpo9frwynL2gSMgh7sTV4LGSNmG\r\n" \
    "d1UXa1TlhpnnnNE0EjRvITZj4BJ+uOsCZrES9E3gEIBCXpjeK/OjAw==\r\n"         \
    "-----END RSA PRIVATE KEY-----\r\n"
