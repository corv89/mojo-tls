"""FFI bindings to mbedTLS SSL/TLS functions.

These bindings wrap the core SSL/TLS functions from mbedtls/ssl.h.
mbedTLS 4.0.0 uses PSA Crypto internally for RNG, so no explicit
entropy/ctr_drbg setup is needed.

With static linking, all calls use external_call.
"""

from sys.ffi import external_call, c_int, c_size_t, c_char
from memory import UnsafePointer

from .constants import *


# ============================================================================
# FFI Pointer type - stores raw address as Int for struct fields
# ============================================================================


@register_passable("trivial")
struct FFIPtr(Stringable, Writable):
    """A pointer type for FFI that stores raw memory address.

    This is needed because UnsafePointer can't be used in struct fields
    in Mojo 0.26 due to origin inference issues.
    """
    var addr: Int

    @always_inline
    fn __init__(out self):
        """Create a null pointer."""
        self.addr = 0

    @always_inline
    fn __init__(out self, addr: Int):
        """Create from address."""
        self.addr = addr

    @always_inline
    fn __bool__(self) -> Bool:
        """Check if pointer is non-null."""
        return self.addr != 0

    fn __str__(self) -> String:
        return "FFIPtr(" + String(self.addr) + ")"

    fn write_to[W: Writer](self, mut writer: W):
        writer.write("FFIPtr(", self.addr, ")")


fn alloc_ffi(size: Int) -> FFIPtr:
    """Allocate memory using shim library and return as FFIPtr.

    Args:
        size: Number of bytes to allocate.

    Returns:
        FFIPtr containing the address of allocated memory.
    """
    return FFIPtr(external_call["mojo_tls_alloc", Int](size))


fn free_ffi(ptr: FFIPtr):
    """Free memory allocated with alloc_ffi.

    Args:
        ptr: FFIPtr to free.
    """
    if ptr:
        external_call["mojo_tls_free", NoneType](ptr.addr)


fn strlen_ffi(ptr: FFIPtr) -> Int:
    """Get the length of a null-terminated C string.

    Args:
        ptr: FFIPtr pointing to the string.

    Returns:
        Length of the string (not including null terminator).
    """
    return external_call["mojo_tls_strlen", Int](ptr.addr)


fn strcpy_ffi(
    dest: UnsafePointer[UInt8],
    dest_size: Int,
    src: FFIPtr,
) -> Int:
    """Copy a C string to a buffer.

    Args:
        dest: Destination buffer.
        dest_size: Size of destination buffer.
        src: Source C string (FFIPtr).

    Returns:
        Number of bytes copied (not including null terminator).
    """
    return external_call["mojo_tls_strcpy", Int](dest, dest_size, src.addr)


fn get_null_ptr() -> FFIPtr:
    """Get a null pointer."""
    return FFIPtr()


# For backwards compatibility
alias OpaquePtr = FFIPtr


# ============================================================================
# SSL Context Functions
# ============================================================================


fn ssl_init(ssl: FFIPtr):
    """Initialize an SSL context.

    Args:
        ssl: SSL context to initialize.
    """
    external_call["mojo_tls_ssl_init", NoneType](ssl.addr)


fn ssl_free(ssl: FFIPtr):
    """Free an SSL context.

    Args:
        ssl: SSL context to free.
    """
    external_call["mojo_tls_ssl_free", NoneType](ssl.addr)


fn ssl_setup(ssl: FFIPtr, conf: FFIPtr) -> c_int:
    """Set up an SSL context for use.

    Args:
        ssl: SSL context.
        conf: SSL configuration to use.

    Returns:
        0 on success, or MBEDTLS_ERR_SSL_ALLOC_FAILED.
    """
    return external_call["mojo_tls_ssl_setup", c_int](ssl.addr, conf.addr)


fn ssl_set_hostname(ssl: FFIPtr, hostname: UnsafePointer[c_char]) -> c_int:
    """Set the hostname for server certificate verification (SNI).

    Args:
        ssl: SSL context.
        hostname: Expected hostname (null-terminated).

    Returns:
        0 on success, or MBEDTLS_ERR_SSL_ALLOC_FAILED.
    """
    return external_call["mojo_tls_ssl_set_hostname", c_int](ssl.addr, hostname)


fn ssl_set_bio(
    ssl: FFIPtr,
    p_bio: FFIPtr,
    f_send: FFIPtr,
    f_recv: FFIPtr,
    f_recv_timeout: FFIPtr,
):
    """Set the underlying BIO callbacks for sending and receiving data.

    Args:
        ssl: SSL context.
        p_bio: Context passed to callbacks (e.g., network socket context).
        f_send: Send callback function pointer.
        f_recv: Receive callback function pointer.
        f_recv_timeout: Receive with timeout callback (can be null).
    """
    external_call["mojo_tls_ssl_set_bio", NoneType](
        ssl.addr, p_bio.addr, f_send.addr, f_recv.addr, f_recv_timeout.addr
    )


# ============================================================================
# SSL Handshake and I/O
# ============================================================================


fn ssl_handshake(ssl: FFIPtr) -> c_int:
    """Perform the SSL/TLS handshake."""
    return external_call["mojo_tls_ssl_handshake", c_int](ssl.addr)


fn ssl_read(ssl: FFIPtr, buf: UnsafePointer[UInt8], length: c_size_t) -> c_int:
    """Read at most 'len' application data bytes."""
    return external_call["mojo_tls_ssl_read", c_int](ssl.addr, buf, length)


fn ssl_write(ssl: FFIPtr, buf: UnsafePointer[UInt8], length: c_size_t) -> c_int:
    """Write exactly 'len' application data bytes."""
    return external_call["mojo_tls_ssl_write", c_int](ssl.addr, buf, length)


fn ssl_close_notify(ssl: FFIPtr) -> c_int:
    """Notify the peer that the connection is being closed."""
    return external_call["mojo_tls_ssl_close_notify", c_int](ssl.addr)


# ============================================================================
# SSL Configuration Functions
# ============================================================================


fn ssl_config_init(conf: FFIPtr):
    """Initialize an SSL configuration context."""
    external_call["mojo_tls_ssl_config_init", NoneType](conf.addr)


fn ssl_config_free(conf: FFIPtr):
    """Free an SSL configuration context."""
    external_call["mojo_tls_ssl_config_free", NoneType](conf.addr)


fn ssl_config_defaults(
    conf: FFIPtr, endpoint: c_int, transport: c_int, preset: c_int
) -> c_int:
    """Load reasonable default SSL configuration values."""
    return external_call["mojo_tls_ssl_config_defaults", c_int](
        conf.addr, endpoint, transport, preset
    )


fn ssl_conf_authmode(conf: FFIPtr, authmode: c_int):
    """Set the certificate verification mode."""
    external_call["mojo_tls_ssl_conf_authmode", NoneType](conf.addr, authmode)


fn ssl_conf_ca_chain(conf: FFIPtr, ca_chain: FFIPtr, ca_crl: FFIPtr):
    """Set the trusted CA chain for certificate verification."""
    external_call["mojo_tls_ssl_conf_ca_chain", NoneType](conf.addr, ca_chain.addr, ca_crl.addr)


fn ssl_conf_own_cert(conf: FFIPtr, own_cert: FFIPtr, pk_ctx: FFIPtr) -> c_int:
    """Set own certificate chain and private key (for servers or mutual TLS).

    Args:
        conf: SSL configuration.
        own_cert: Own certificate chain.
        pk_ctx: Private key context.

    Returns:
        0 on success, or MBEDTLS_ERR_SSL_ALLOC_FAILED.
    """
    return external_call["mojo_tls_ssl_conf_own_cert", c_int](
        conf.addr, own_cert.addr, pk_ctx.addr
    )


# ============================================================================
# TLS Version Configuration (via C shim - static inline in mbedTLS)
# ============================================================================


fn ssl_conf_min_version(conf: FFIPtr, version: c_int):
    """Set minimum supported TLS version (via shim)."""
    external_call["mojo_tls_conf_min_version", NoneType](conf.addr, version)


fn ssl_conf_max_version(conf: FFIPtr, version: c_int):
    """Set maximum supported TLS version (via shim)."""
    external_call["mojo_tls_conf_max_version", NoneType](conf.addr, version)


# ============================================================================
# SSL Session Functions
# ============================================================================


fn ssl_session_init(session: FFIPtr):
    """Initialize an SSL session structure."""
    external_call["mojo_tls_ssl_session_init", NoneType](session.addr)


fn ssl_session_free(session: FFIPtr):
    """Free an SSL session structure."""
    external_call["mojo_tls_ssl_session_free", NoneType](session.addr)


# ============================================================================
# Query Functions
# ============================================================================


fn ssl_get_version(ssl: FFIPtr) -> FFIPtr:
    """Get the negotiated protocol version as a string."""
    return FFIPtr(external_call["mojo_tls_ssl_get_version", Int](ssl.addr))


fn ssl_get_ciphersuite(ssl: FFIPtr) -> FFIPtr:
    """Get the negotiated ciphersuite name."""
    return FFIPtr(external_call["mojo_tls_ssl_get_ciphersuite", Int](ssl.addr))


fn ssl_get_verify_result(ssl: FFIPtr) -> UInt32:
    """Get the result of certificate verification."""
    return external_call["mojo_tls_ssl_get_verify_result", UInt32](ssl.addr)


fn ssl_get_peer_cert(ssl: FFIPtr) -> FFIPtr:
    """Get the peer's X.509 certificate from the SSL context.

    Returns:
        FFIPtr to the peer certificate, or null pointer if no certificate.
        The returned pointer is owned by the SSL context - do not free it.
    """
    return FFIPtr(external_call["mojo_tls_ssl_get_peer_cert", Int](ssl.addr))


# ============================================================================
# Private Key Functions
# ============================================================================


fn pk_init(pk: FFIPtr):
    """Initialize a private key context."""
    external_call["mojo_tls_pk_init", NoneType](pk.addr)


fn pk_free(pk: FFIPtr):
    """Free a private key context."""
    external_call["mojo_tls_pk_free", NoneType](pk.addr)


fn pk_parse_key(
    pk: FFIPtr,
    key: UnsafePointer[UInt8],
    keylen: c_size_t,
    pwd: UnsafePointer[UInt8],
    pwdlen: c_size_t,
) -> c_int:
    """Parse a private key in PEM or DER format.

    Args:
        pk: Private key context to populate.
        key: Buffer containing the key.
        keylen: Length of the key buffer (include null terminator for PEM).
        pwd: Optional password for encrypted keys (or null).
        pwdlen: Length of password (0 if no password).

    Returns:
        0 on success, or a negative error code.
    """
    return external_call["mojo_tls_pk_parse_key", c_int](
        pk.addr, key, keylen, pwd, pwdlen
    )


fn pk_parse_keyfile(
    pk: FFIPtr,
    path: UnsafePointer[c_char],
    password: UnsafePointer[c_char],
) -> c_int:
    """Load and parse a private key from a file.

    Args:
        pk: Private key context to populate.
        path: Path to the key file (null-terminated).
        password: Optional password for encrypted keys (or null).

    Returns:
        0 on success, or a negative error code.
    """
    return external_call["mojo_tls_pk_parse_keyfile", c_int](pk.addr, path, password)
