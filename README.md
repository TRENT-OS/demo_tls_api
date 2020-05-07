# demo\_tls\_api

## Overview

Provide a demo for the TrentOS-M TLS API

The demo gets a simple web page from www.example.org. First using TLS as a
library local to the demo application component then using TLS as a separate
component (server).

## Build and run
```console
cd <SDK_ROOT_DIR>
./scripts/open_trentos_build_env.sh ./build-system.sh pkg/demos/demo_tls_api/src zynq7000 build-demo_tls_api -DCMAKE_BUILD_TYPE=Debug
./scripts/open_trentos_test_env.sh ./demos/demo_tls_api/src/run_demo.sh build-demo_tls_api bin/
```

