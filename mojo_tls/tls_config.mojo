"""High-level TLS configuration for mbedTLS.

Provides a TLSConfig struct that manages SSL configuration, CA chains,
and certificates with proper RAII cleanup.
"""

from sys.ffi import external_call, c_int, c_char
from memory import UnsafePointer
from pathlib import Path

from ._lib import (
    init_mojo_tls,
    SSL_CONFIG_SIZE,
    X509_CRT_SIZE,
    PK_CONTEXT_SIZE,
)
from ._ffi.constants import (
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT,
    MBEDTLS_SSL_VERIFY_NONE,
    MBEDTLS_SSL_VERIFY_OPTIONAL,
    MBEDTLS_SSL_VERIFY_REQUIRED,
    MBEDTLS_SSL_VERSION_TLS1_2,
    MBEDTLS_SSL_VERSION_TLS1_3,
)
from ._ffi.ssl import (
    ssl_config_init,
    ssl_config_free,
    ssl_config_defaults,
    ssl_conf_authmode,
    ssl_conf_ca_chain,
    ssl_conf_min_version,
    ssl_conf_max_version,
    FFIPtr,
    alloc_ffi,
    free_ffi,
    get_null_ptr,
)
from ._ffi.x509_crt import (
    x509_crt_init,
    x509_crt_free,
    x509_crt_parse,
    x509_crt_parse_file,
)
from .error import check_error


# System CA bundle paths
comptime MACOS_CA_BUNDLE = "/opt/homebrew/etc/ca-certificates/cert.pem"
comptime LINUX_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


fn get_system_ca_bundle() -> String:
    """Get the system CA certificate bundle path.

    Returns:
        Path to the system CA bundle.
    """
    # TODO: Use CompilationTarget.is_macos() when available
    # For now, default to macOS Homebrew path
    return MACOS_CA_BUNDLE


struct TLSConfig(Movable):
    """High-level TLS configuration.

    Manages mbedTLS SSL configuration with proper initialization and cleanup.
    Owns the SSL config, CA chain, and optional own certificate/key.

    Example:
        var config = TLSConfig()
        config.set_client_mode()
        config.load_system_ca_chain()
    """

    var _config: FFIPtr
    var _ca_chain: FFIPtr
    var _own_cert: FFIPtr
    var _pk_ctx: FFIPtr

    var _is_client: Bool
    var _ca_loaded: Bool
    var _own_cert_loaded: Bool

    fn __init__(out self) raises:
        """Initialize a new TLS configuration.

        Raises:
            If library loading or initialization fails.
        """
        # Initialize PSA Crypto if not already done
        init_mojo_tls()

        # Allocate config struct using shim
        self._config = alloc_ffi(SSL_CONFIG_SIZE)

        # Initialize config
        ssl_config_init(self._config)

        # Allocate and init CA chain
        self._ca_chain = alloc_ffi(X509_CRT_SIZE)
        x509_crt_init(self._ca_chain)

        # Allocate own cert (may not be used)
        self._own_cert = alloc_ffi(X509_CRT_SIZE)
        x509_crt_init(self._own_cert)

        # Allocate PK context for private key
        self._pk_ctx = alloc_ffi(PK_CONTEXT_SIZE)
        external_call["mojo_tls_pk_init", NoneType](self._pk_ctx.addr)

        self._is_client = True
        self._ca_loaded = False
        self._own_cert_loaded = False

    fn __moveinit__(out self, owned existing: Self):
        """Move constructor for TLSConfig."""
        self._config = existing._config
        self._ca_chain = existing._ca_chain
        self._own_cert = existing._own_cert
        self._pk_ctx = existing._pk_ctx
        self._is_client = existing._is_client
        self._ca_loaded = existing._ca_loaded
        self._own_cert_loaded = existing._own_cert_loaded

    fn __del__(owned self):
        """Clean up TLS configuration and free resources."""
        # Free PK context
        external_call["mojo_tls_pk_free", NoneType](self._pk_ctx.addr)
        free_ffi(self._pk_ctx)

        # Free own cert
        x509_crt_free(self._own_cert)
        free_ffi(self._own_cert)

        # Free CA chain
        x509_crt_free(self._ca_chain)
        free_ffi(self._ca_chain)

        # Free SSL config
        ssl_config_free(self._config)
        free_ffi(self._config)

    fn set_client_mode(mut self) raises:
        """Configure for TLS client mode.

        Sets up default configuration for a TLS client using TLS (not DTLS).

        Raises:
            If configuration fails.
        """
        var ret = ssl_config_defaults(
            self._config,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT,
        )
        check_error(ret, "ssl_config_defaults")
        self._is_client = True

    fn set_server_mode(mut self) raises:
        """Configure for TLS server mode.

        Sets up default configuration for a TLS server using TLS (not DTLS).

        Raises:
            If configuration fails.
        """
        var ret = ssl_config_defaults(
            self._config,
            MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT,
        )
        check_error(ret, "ssl_config_defaults")
        self._is_client = False

    fn set_verify_mode(mut self, mode: c_int):
        """Set certificate verification mode.

        Args:
            mode: MBEDTLS_SSL_VERIFY_NONE, _OPTIONAL, or _REQUIRED.
        """
        ssl_conf_authmode(self._config, mode)

    fn set_verify_none(mut self):
        """Disable certificate verification (insecure)."""
        self.set_verify_mode(MBEDTLS_SSL_VERIFY_NONE)

    fn set_verify_optional(mut self):
        """Set optional certificate verification."""
        self.set_verify_mode(MBEDTLS_SSL_VERIFY_OPTIONAL)

    fn set_verify_required(mut self):
        """Set required certificate verification (default for clients)."""
        self.set_verify_mode(MBEDTLS_SSL_VERIFY_REQUIRED)

    fn set_min_tls_version(mut self, version: c_int):
        """Set minimum TLS version.

        Args:
            version: MBEDTLS_SSL_VERSION_TLS1_2 or _TLS1_3.
        """
        ssl_conf_min_version(self._config, version)

    fn set_max_tls_version(mut self, version: c_int):
        """Set maximum TLS version.

        Args:
            version: MBEDTLS_SSL_VERSION_TLS1_2 or _TLS1_3.
        """
        ssl_conf_max_version(self._config, version)

    fn set_tls13_only(mut self):
        """Configure to use TLS 1.3 only."""
        self.set_min_tls_version(MBEDTLS_SSL_VERSION_TLS1_3)
        self.set_max_tls_version(MBEDTLS_SSL_VERSION_TLS1_3)

    fn set_tls12_only(mut self):
        """Configure to use TLS 1.2 only."""
        self.set_min_tls_version(MBEDTLS_SSL_VERSION_TLS1_2)
        self.set_max_tls_version(MBEDTLS_SSL_VERSION_TLS1_2)

    fn load_ca_chain_from_file(mut self, path: String) raises:
        """Load CA certificate chain from a file.

        Args:
            path: Path to PEM or DER certificate file.

        Raises:
            If loading fails.
        """
        # Read file content using Mojo's pathlib
        # Note: x509_crt_parse_file has issues when called via FFI, so we read
        # the file ourselves and use x509_crt_parse instead
        var file_path = Path(path)
        var content = file_path.read_text()

        # Create buffer with null terminator (required for PEM parsing)
        var data = content.as_bytes()
        var buf = List[UInt8](capacity=len(data) + 1)
        for i in range(len(data)):
            buf.append(data[i])
        buf.append(0)  # Null terminator

        # Parse from memory buffer
        var ret = x509_crt_parse(self._ca_chain, buf.unsafe_ptr(), len(buf))
        check_error(ret, "x509_crt_parse")

        # Set the CA chain on the config (no CRL)
        ssl_conf_ca_chain(self._config, self._ca_chain, get_null_ptr())
        self._ca_loaded = True

    fn load_system_ca_chain(mut self) raises:
        """Load the system CA certificate bundle.

        Raises:
            If loading fails.
        """
        self.load_ca_chain_from_file(get_system_ca_bundle())

    fn load_ca_chain_from_memory(mut self, pem_data: String) raises:
        """Load CA certificate chain from PEM data in memory.

        Args:
            pem_data: PEM-encoded certificate data (including null terminator).

        Raises:
            If parsing fails.
        """
        var data_bytes = pem_data.as_bytes()
        var data_ptr = data_bytes.unsafe_ptr()
        # PEM parsing requires the null terminator in the length
        var data_len = len(pem_data) + 1

        var ret = x509_crt_parse(self._ca_chain, data_ptr, data_len)
        check_error(ret, "x509_crt_parse")

        # Set the CA chain on the config (no CRL)
        ssl_conf_ca_chain(self._config, self._ca_chain, get_null_ptr())
        self._ca_loaded = True

    fn get_config_ptr(self) -> FFIPtr:
        """Get the underlying SSL config pointer.

        Returns:
            Pointer to mbedtls_ssl_config.
        """
        return self._config
