# mojo-tls

TLS 1.3 bindings for Mojo via mbedTLS 4.0.0.

## Features

- TLS 1.3 client and server support
- High-level `TLSStream` for easy client connections
- `TLSListener` for accepting server connections
- Static linking with Mojo's `external_call`
- Platform-detected CA bundle (macOS/Linux)

## Requirements

- macOS or Linux
- mbedTLS 4.0.0: `brew install mbedtls` (macOS)
- Mojo 0.25+

## Quick Start

### Client Example

```mojo
from mojo_tls import TLSStream

fn main() raises:
    var stream = TLSStream.connect("example.com", "443")
    _ = stream.write_all("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = stream.read(buf.unsafe_ptr(), 4096)

    print("TLS Version:", stream.get_version())
    print("Ciphersuite:", stream.get_ciphersuite())
    stream.close()
```

### Server Example

```mojo
from mojo_tls import TLSListener

fn main() raises:
    var listener = TLSListener.bind(
        "server.crt", "server.key",
        "0.0.0.0", "8443"
    )

    var client = listener.accept()
    client.handshake()

    print("TLS Version:", client.get_version())

    # Read request, send response...
    client.close()
    _ = listener
```

## Building

Build and run a test:

```bash
./build.sh tests/test_tls_client.mojo test_client
DYLD_LIBRARY_PATH=/path/to/mojo/runtime/lib ./test_client
```

The build script:
1. Compiles the C shim to a static library
2. Compiles Mojo to an object file (`mojo build --emit object`)
3. Links everything with clang

Build shim with debug output:

```bash
./build.sh --debug tests/test_tls_client.mojo test_client
```

## Project Structure

```
mojo-tls/
├── mojo_tls/              # Mojo package
│   ├── __init__.mojo      # Public API exports
│   ├── _lib.mojo          # Init and struct size validation
│   ├── _ffi/              # Low-level FFI bindings
│   ├── tls_config.mojo    # TLSConfig - SSL configuration
│   ├── tls_context.mojo   # TLSContext, ServerTLSContext
│   ├── tls_stream.mojo    # TLSStream - high-level client
│   ├── tls_listener.mojo  # TLSListener - high-level server
│   └── error.mojo         # TLSError type
├── shim/                  # C shim library
│   ├── mojo_tls_shim.c    # Shim implementation
│   ├── mojo_tls_shim.h    # Shim header
│   └── build.sh           # Shim build script
├── tests/                 # Test files
└── build.sh               # Main build script
```

## Technical Notes

### Static Linking

Mojo's `external_call` resolves symbols at compile time. The C shim wraps mbedTLS functions (prefixed `mojo_tls_*`) and is statically linked into the final binary.

### mbedTLS 4.0.0

- PSA Crypto is initialized automatically via `init_mojo_tls()`
- Struct sizes are validated at init to catch version mismatches
- The shim links against `libmbedtls.a`, `libmbedx509.a`, `libmbedcrypto.a`

### CA Certificate Paths

Automatically detected at compile time:
- macOS: `/opt/homebrew/etc/ca-certificates/cert.pem`
- Linux: `/etc/ssl/certs/ca-certificates.crt`

## License

Apache-2.0
