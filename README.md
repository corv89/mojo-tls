# mojo-tls

Mojo TLS bindings for mbedTLS 4.0.0, providing TLS 1.2/1.3 support.

## Status

**Work in Progress** - The C shim is fully functional and tested. The Mojo bindings are written but require Mojo to add support for dynamic library linking.

### What Works

The C shim (`shim/libmojo_tls_shim.dylib`) successfully:
- Initializes PSA Crypto (required for mbedTLS 4.0.0)
- Performs TLS 1.2/1.3 handshakes
- Sends and receives encrypted data
- Loads CA certificate chains

Tested against httpbin.org with TLS 1.2 (TLS 1.3 also supported).

### Current Limitation

Mojo's `external_call` function resolves symbols at JIT compile time, not runtime. This means dynamically loaded libraries (via `dlopen`) cannot provide symbols to `external_call`. Mojo currently doesn't have:
- A `-l` flag to link external libraries
- Runtime symbol resolution for `external_call`
- A way to call through function pointers from `dlsym`

The Mojo code in this repo is structurally correct but cannot actually call the shim until Mojo adds dynamic library support.

## Building the Shim

Prerequisites:
- macOS with Homebrew
- mbedTLS 4.0.0: `brew install mbedtls`

Build:
```bash
cd shim
./build.sh
```

This creates `libmojo_tls_shim.dylib` which wraps mbedTLS functions for FFI use.

## Testing the Shim (C)

A working C test that performs a TLS connection:

```c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *shim = dlopen("./shim/libmojo_tls_shim.dylib", RTLD_NOW);

    // Get and call init function (REQUIRED for mbedTLS 4.0.0)
    int (*tls_init)(void) = dlsym(shim, "mojo_tls_init");
    tls_init();

    // ... rest of TLS operations
}
```

## Using with Python (Workaround)

Since Mojo has Python interop, you can use the shim through Python's ctypes:

```python
import ctypes

shim = ctypes.CDLL("./shim/libmojo_tls_shim.dylib")

# Initialize PSA Crypto first!
shim.mojo_tls_init()

# Now use other functions...
```

## Project Structure

```
mojo-tls/
├── mojo_tls/              # Mojo package (ready when FFI support arrives)
│   ├── __init__.mojo      # Public API exports
│   ├── _lib.mojo          # Library loading (needs FFI update)
│   ├── _ffi/              # Low-level FFI bindings
│   │   ├── constants.mojo # mbedTLS constants and error codes
│   │   ├── ssl.mojo       # SSL/TLS function wrappers
│   │   ├── x509_crt.mojo  # X.509 certificate functions
│   │   └── net_sockets.mojo # Network socket functions
│   ├── error.mojo         # TLSError type
│   ├── tls_config.mojo    # High-level TLSConfig
│   ├── tls_context.mojo   # High-level TLSContext
│   └── tls_stream.mojo    # High-level TLSStream
├── shim/                  # C shim library
│   ├── mojo_tls_shim.h    # Shim header
│   ├── mojo_tls_shim.c    # Shim implementation
│   ├── build.sh           # Build script
│   └── libmojo_tls_shim.dylib  # Built library
├── tests/                 # Test files
└── examples/              # Example code
```

## Key Technical Notes

### mbedTLS 4.0.0 Changes

mbedTLS 4.0.0 uses PSA Crypto internally:
- **MUST call `mojo_tls_init()`** before any TLS operation
- Error codes changed to PSA error codes (e.g., `-137` = `PSA_ERROR_BAD_STATE`)
- Some headers moved to `mbedtls/private/`
- No need for explicit entropy/CSPRNG setup (handled internally)

### Library Dependencies

mbedTLS libraries must be loaded in order:
1. `libmbedcrypto.dylib` - Crypto primitives
2. `libmbedx509.dylib` - Certificate handling
3. `libmbedtls.dylib` - TLS protocol

Our shim handles this by linking against all three.

### Struct Sizes

mbedTLS struct sizes vary by build configuration. The shim provides `mojo_tls_sizeof_*()` functions to query sizes at runtime:
- `ssl_context`: 840 bytes
- `ssl_config`: 352 bytes
- `x509_crt`: 1304 bytes
- `net_context`: 4 bytes

### CA Certificate Path

On macOS with Homebrew:
```
/opt/homebrew/etc/ca-certificates/cert.pem
```

## Future Work

Once Mojo adds dynamic library support, the Mojo bindings will work. The target API:

```mojo
from mojo_tls import TLSStream

fn main() raises:
    var stream = TLSStream.connect("httpbin.org", "443")
    _ = stream.write_all("GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")

    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = stream.read(buf.unsafe_ptr(), 4096)
    print(String(buf.unsafe_ptr(), n))

    print("TLS Version:", stream.get_version())
    stream.close()
```

## License

MIT
