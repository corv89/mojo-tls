"""High-level TLS configuration for mbedTLS.

Provides a TLSConfig struct that manages SSL configuration, CA chains,
and certificates with proper RAII cleanup.
"""

from sys.ffi import external_call, c_int, c_char
from sys.info import platform_map
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
    ssl_conf_own_cert,
    ssl_conf_min_version,
    ssl_conf_max_version,
    pk_init,
    pk_free,
    pk_parse_key,
    pk_parse_keyfile,
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


# System CA bundle path (compile-time platform selection)
comptime SYSTEM_CA_BUNDLE = platform_map[
    "system_ca_bundle",
    linux="/etc/ssl/certs/ca-certificates.crt",
    macos="/opt/homebrew/etc/ca-certificates/cert.pem",
]()


fn get_system_ca_bundle() -> String:
    """Get the system CA certificate bundle path.

    Returns:
        Path to the system CA bundle (selected at compile time based on target OS).
    """
    return SYSTEM_CA_BUNDLE


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
        pk_init(self._pk_ctx)

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
        # Invalidate source to prevent double-free when it's destroyed
        existing._config = FFIPtr(0)
        existing._ca_chain = FFIPtr(0)
        existing._own_cert = FFIPtr(0)
        existing._pk_ctx = FFIPtr(0)

    fn __del__(owned self):
        """Clean up TLS configuration and free resources."""
        # Skip cleanup if this object was moved-from (pointers are null)
        if not self._config:
            return

        # Free PK context
        pk_free(self._pk_ctx)
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

    fn load_own_certificate(mut self, path: String) raises:
        """Load own certificate chain from a file.

        For servers, this is the server certificate. For clients with
        mutual TLS, this is the client certificate.

        Args:
            path: Path to PEM or DER certificate file.

        Raises:
            If loading fails.
        """
        # Create null-terminated path string
        var path_bytes = path.as_bytes()
        var path_buf = List[UInt8](capacity=len(path_bytes) + 1)
        for i in range(len(path_bytes)):
            path_buf.append(path_bytes[i])
        path_buf.append(0)  # Null terminator
        var path_ptr = path_buf.unsafe_ptr().bitcast[c_char]()

        # Parse certificate into own_cert directly from file
        var ret = x509_crt_parse_file(self._own_cert, path_ptr)
        check_error(ret, "x509_crt_parse_file (own_cert)")

    fn load_own_key(mut self, path: String, password: String = "") raises:
        """Load private key from a file.

        Must be called after load_own_certificate() to associate the
        key with the certificate on the config.

        Args:
            path: Path to PEM or DER private key file.
            password: Optional password for encrypted keys.

        Raises:
            If loading fails.
        """
        # Create null-terminated path string
        var path_bytes = path.as_bytes()
        var path_buf = List[UInt8](capacity=len(path_bytes) + 1)
        for i in range(len(path_bytes)):
            path_buf.append(path_bytes[i])
        path_buf.append(0)  # Null terminator
        var path_ptr = path_buf.unsafe_ptr().bitcast[c_char]()

        # Handle password - always create a buffer (empty = null terminator only)
        # mbedtls expects NULL for no password, but we can pass empty string
        var pwd_buf = List[UInt8](capacity=1)
        if len(password) > 0:
            var pwd_bytes = password.as_bytes()
            pwd_buf = List[UInt8](capacity=len(pwd_bytes) + 1)
            for i in range(len(pwd_bytes)):
                pwd_buf.append(pwd_bytes[i])
        pwd_buf.append(0)  # Null terminator
        var pwd_ptr = pwd_buf.unsafe_ptr().bitcast[c_char]()

        # Parse private key (empty password string works like NULL for unencrypted keys)
        var ret = pk_parse_keyfile(self._pk_ctx, path_ptr, pwd_ptr)
        check_error(ret, "pk_parse_keyfile")

        # Now set the certificate + key on the config
        ret = ssl_conf_own_cert(self._config, self._own_cert, self._pk_ctx)
        check_error(ret, "ssl_conf_own_cert")

        self._own_cert_loaded = True

    fn load_own_cert_and_key(
        mut self, cert_path: String, key_path: String, password: String = ""
    ) raises:
        """Load own certificate and private key from files.

        Convenience method that calls load_own_certificate() and
        load_own_key() in sequence.

        Args:
            cert_path: Path to certificate file.
            key_path: Path to private key file.
            password: Optional password for encrypted key.

        Raises:
            If loading fails.
        """
        self.load_own_certificate(cert_path)
        self.load_own_key(key_path, password)
