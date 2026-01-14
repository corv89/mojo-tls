"""FFI bindings to mbedTLS X.509 certificate functions.

These bindings wrap certificate handling functions from mbedtls/x509_crt.h.
With static linking, all calls use external_call.
"""

from sys.ffi import external_call, c_int, c_size_t, c_char
from memory import UnsafePointer

from .ssl import FFIPtr, OpaquePtr


# ============================================================================
# Certificate Chain Functions
# ============================================================================


fn x509_crt_init(crt: FFIPtr):
    """Initialize a certificate chain.

    Args:
        crt: Certificate chain to initialize.
    """
    external_call["mojo_tls_x509_crt_init", NoneType](crt.addr)


fn x509_crt_free(crt: FFIPtr):
    """Free a certificate chain and all associated data.

    Args:
        crt: Certificate chain to free.
    """
    external_call["mojo_tls_x509_crt_free", NoneType](crt.addr)


fn x509_crt_parse(
    chain: FFIPtr, buf: UnsafePointer[UInt8], buflen: Int
) -> c_int:
    """Parse one or more PEM or DER certificates and add them to the chain.

    Args:
        chain: Certificate chain to add to.
        buf: Buffer holding the certificate data.
        buflen: Size of the buffer (including null terminator for PEM).

    Returns:
        0 if all certificates were parsed successfully, or a negative
        error code. If some certificates were parsed successfully
        before an error, the chain will contain those certificates.
    """
    return external_call["mojo_tls_x509_crt_parse", c_int](chain.addr, buf, buflen)


fn x509_crt_parse_file(chain: FFIPtr, path: UnsafePointer[c_char]) -> c_int:
    """Parse one or more certificates from a file and add them to the chain.

    Args:
        chain: Certificate chain to add to.
        path: Path to the certificate file (null-terminated).

    Returns:
        0 if successful, or a negative error code.
    """
    return external_call["mojo_tls_x509_crt_parse_file", c_int](chain.addr, path)


fn x509_crt_parse_path(chain: FFIPtr, path: UnsafePointer[c_char]) -> c_int:
    """Parse all certificate files in a directory and add them to the chain.

    Args:
        chain: Certificate chain to add to.
        path: Path to the directory (null-terminated).

    Returns:
        0 if successful, or a negative error code.
    """
    return external_call["mbedtls_x509_crt_parse_path", c_int](chain.addr, path)


# ============================================================================
# Certificate Information Functions
# ============================================================================


fn x509_crt_info(
    buf: UnsafePointer[c_char],
    size: c_size_t,
    prefix: UnsafePointer[c_char],
    crt: FFIPtr,
) -> c_int:
    """Return an informational string about the certificate.

    Args:
        buf: Buffer to write the string to.
        size: Maximum size of the buffer.
        prefix: Prefix to add before each line.
        crt: Certificate to describe.

    Returns:
        Length of the string written (excluding null terminator),
        or a negative error code.
    """
    return external_call["mbedtls_x509_crt_info", c_int](buf, size, prefix, crt.addr)


fn x509_crt_verify_info(
    buf: UnsafePointer[c_char],
    size: c_size_t,
    prefix: UnsafePointer[c_char],
    flags: UInt32,
) -> c_int:
    """Return an informational string about verification results.

    Args:
        buf: Buffer to write the string to.
        size: Maximum size of the buffer.
        prefix: Prefix to add before each line.
        flags: Verification flags from mbedtls_x509_crt_verify().

    Returns:
        Length of the string written (excluding null terminator),
        or a negative error code.
    """
    return external_call["mbedtls_x509_crt_verify_info", c_int](buf, size, prefix, flags)


# ============================================================================
# Certificate Raw Data Access
# ============================================================================


fn x509_crt_get_raw_data(crt: FFIPtr) -> FFIPtr:
    """Get pointer to the raw DER-encoded certificate data.

    Args:
        crt: Certificate context.

    Returns:
        FFIPtr to the raw data (owned by the certificate - do not free).
    """
    return FFIPtr(external_call["mojo_tls_x509_crt_get_raw_data", Int](crt.addr))


fn x509_crt_get_raw_len(crt: FFIPtr) -> Int:
    """Get length of the raw DER-encoded certificate data.

    Args:
        crt: Certificate context.

    Returns:
        Length in bytes of the raw certificate data.
    """
    return external_call["mojo_tls_x509_crt_get_raw_len", Int](crt.addr)


# ============================================================================
# Cryptographic Hash Functions
# ============================================================================


fn sha256(
    input: UnsafePointer[UInt8], input_len: Int, output: UnsafePointer[UInt8]
) -> c_int:
    """Compute SHA-256 hash of input data using PSA Crypto.

    Args:
        input: Input data buffer.
        input_len: Length of input data.
        output: Output buffer (must be at least 32 bytes).

    Returns:
        0 on success, non-zero on error.
    """
    return external_call["mojo_tls_sha256", c_int](input, input_len, output)
