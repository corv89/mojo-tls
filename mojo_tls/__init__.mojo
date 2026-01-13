"""Mojo TLS bindings for mbedTLS.

This package provides TLS 1.3 support for Mojo via mbedTLS 4.0.0.

Example usage:

    from mojo_tls import TLSStream

    fn main() raises:
        # Simple HTTPS GET request
        var stream = TLSStream.connect("example.com", "443")
        _ = stream.write_all("GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")

        var buf = List[UInt8](capacity=4096)
        buf.resize(4096, 0)
        var n = stream.read(buf.unsafe_ptr(), 4096)
        print(String(buf.unsafe_ptr(), n))

        print("TLS Version:", stream.get_version())
        print("Ciphersuite:", stream.get_ciphersuite())

        stream.close()

For more control, use TLSConfig and TLSContext directly:

    from mojo_tls import TLSConfig, TLSContext

    fn main() raises:
        var config = TLSConfig()
        config.set_client_mode()
        config.set_tls13_only()  # Force TLS 1.3
        config.load_system_ca_chain()

        var ctx = TLSContext(config)
        # ... set up BIO and perform handshake
"""

# High-level API
from .tls_config import TLSConfig, get_system_ca_bundle
from .tls_context import TLSContext
from .tls_stream import TLSStream
from .error import TLSError, check_error

# Constants (re-export commonly used ones)
from ._ffi.constants import (
    # TLS versions
    MBEDTLS_SSL_VERSION_TLS1_2,
    MBEDTLS_SSL_VERSION_TLS1_3,
    # Verification modes
    MBEDTLS_SSL_VERIFY_NONE,
    MBEDTLS_SSL_VERIFY_OPTIONAL,
    MBEDTLS_SSL_VERIFY_REQUIRED,
    # Endpoint types
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_IS_SERVER,
)
