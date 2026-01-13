"""TLS error handling for mbedTLS bindings.

Provides a TLSError struct that wraps mbedTLS error codes and converts
them to human-readable messages.
"""

from sys.ffi import c_int

from ._ffi.constants import (
    MBEDTLS_ERR_SSL_WANT_READ,
    MBEDTLS_ERR_SSL_WANT_WRITE,
    MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
    MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE,
    MBEDTLS_ERR_SSL_BAD_CERTIFICATE,
    MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
    MBEDTLS_ERR_SSL_CONN_EOF,
    MBEDTLS_ERR_SSL_TIMEOUT,
    MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
    MBEDTLS_ERR_SSL_ALLOC_FAILED,
    MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE,
    MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION,
    MBEDTLS_ERR_SSL_INTERNAL_ERROR,
    MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE,
    MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE,
    MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED,
    MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME,
    MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
    MBEDTLS_ERR_X509_BAD_INPUT_DATA,
    MBEDTLS_ERR_X509_FILE_IO_ERROR,
    MBEDTLS_ERR_PK_FILE_IO_ERROR,
    MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
    MBEDTLS_ERR_PK_PASSWORD_REQUIRED,
    MBEDTLS_ERR_NET_SOCKET_FAILED,
    MBEDTLS_ERR_NET_CONNECT_FAILED,
    MBEDTLS_ERR_NET_UNKNOWN_HOST,
    MBEDTLS_ERR_NET_RECV_FAILED,
    MBEDTLS_ERR_NET_SEND_FAILED,
    MBEDTLS_ERR_NET_CONN_RESET,
)


struct TLSError(Stringable, Writable, Copyable, Movable):
    """Represents an error from mbedTLS operations.

    Attributes:
        code: The mbedTLS error code (negative for errors).
        message: Human-readable error description.
    """

    var code: c_int
    var message: String

    fn __init__(out self, code: c_int):
        """Create a TLSError from an error code.

        Args:
            code: The mbedTLS error code.
        """
        self.code = code
        self.message = _error_code_to_string(code)

    fn __init__(out self, code: c_int, context: String):
        """Create a TLSError with additional context.

        Args:
            code: The mbedTLS error code.
            context: Additional context about where the error occurred.
        """
        self.code = code
        self.message = context + ": " + _error_code_to_string(code)

    fn __copyinit__(out self, other: Self):
        """Copy constructor."""
        self.code = other.code
        self.message = other.message

    fn __moveinit__(out self, owned other: Self):
        """Move constructor."""
        self.code = other.code
        self.message = other.message^

    fn __str__(self) -> String:
        """Return string representation of the error."""
        return "TLSError(" + String(Int(self.code)) + "): " + self.message

    fn write_to[W: Writer](self, mut writer: W):
        """Write the error to a writer."""
        writer.write("TLSError(", Int(self.code), "): ", self.message)

    fn is_want_read(self) -> Bool:
        """Check if error indicates non-blocking read would block."""
        return self.code == MBEDTLS_ERR_SSL_WANT_READ

    fn is_want_write(self) -> Bool:
        """Check if error indicates non-blocking write would block."""
        return self.code == MBEDTLS_ERR_SSL_WANT_WRITE

    fn is_would_block(self) -> Bool:
        """Check if error indicates operation would block (non-blocking I/O)."""
        return self.is_want_read() or self.is_want_write()

    fn is_peer_close_notify(self) -> Bool:
        """Check if peer sent close_notify (graceful shutdown)."""
        return self.code == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY

    fn is_timeout(self) -> Bool:
        """Check if operation timed out."""
        return self.code == MBEDTLS_ERR_SSL_TIMEOUT

    fn is_fatal(self) -> Bool:
        """Check if error is fatal (not recoverable via retry)."""
        return self.code < 0 and not self.is_would_block()


fn _error_code_to_string(code: c_int) -> String:
    """Convert an mbedTLS error code to a human-readable string.

    Args:
        code: The mbedTLS error code.

    Returns:
        A string describing the error.
    """
    if code == 0:
        return "Success"

    # SSL errors
    if code == MBEDTLS_ERR_SSL_WANT_READ:
        return "SSL - Connection requires read call"
    if code == MBEDTLS_ERR_SSL_WANT_WRITE:
        return "SSL - Connection requires write call"
    if code == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        return "SSL - Peer sent close_notify"
    if code == MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE:
        return "SSL - Handshake negotiation failed"
    if code == MBEDTLS_ERR_SSL_BAD_CERTIFICATE:
        return "SSL - Bad certificate"
    if code == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
        return "SSL - Fatal alert message received"
    if code == MBEDTLS_ERR_SSL_CONN_EOF:
        return "SSL - Connection EOF"
    if code == MBEDTLS_ERR_SSL_TIMEOUT:
        return "SSL - Operation timed out"
    if code == MBEDTLS_ERR_SSL_BAD_INPUT_DATA:
        return "SSL - Bad input parameters"
    if code == MBEDTLS_ERR_SSL_ALLOC_FAILED:
        return "SSL - Memory allocation failed"
    if code == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE:
        return "SSL - Feature not available"
    if code == MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION:
        return "SSL - Unsupported protocol version"
    if code == MBEDTLS_ERR_SSL_INTERNAL_ERROR:
        return "SSL - Internal error"
    if code == MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
        return "SSL - Unexpected message received"
    if code == MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
        return "SSL - No client certificate received"
    if code == MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED:
        return "SSL - CA chain required but not set"
    if code == MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME:
        return "SSL - Certificate verification without hostname"

    # X.509 errors
    if code == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
        return "X509 - Certificate verification failed"
    if code == MBEDTLS_ERR_X509_BAD_INPUT_DATA:
        return "X509 - Bad input data"
    if code == MBEDTLS_ERR_X509_FILE_IO_ERROR:
        return "X509 - File I/O error"

    # PK errors
    if code == MBEDTLS_ERR_PK_FILE_IO_ERROR:
        return "PK - File I/O error"
    if code == MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
        return "PK - Invalid key format"
    if code == MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
        return "PK - Password required for key"

    # Network errors
    if code == MBEDTLS_ERR_NET_SOCKET_FAILED:
        return "NET - Socket creation failed"
    if code == MBEDTLS_ERR_NET_CONNECT_FAILED:
        return "NET - Connection failed"
    if code == MBEDTLS_ERR_NET_UNKNOWN_HOST:
        return "NET - Unknown host"
    if code == MBEDTLS_ERR_NET_RECV_FAILED:
        return "NET - Receive failed"
    if code == MBEDTLS_ERR_NET_SEND_FAILED:
        return "NET - Send failed"
    if code == MBEDTLS_ERR_NET_CONN_RESET:
        return "NET - Connection reset by peer"

    # Generic fallback
    return "Unknown error code: " + String(Int(code))


fn check_error(code: c_int) raises:
    """Check an mbedTLS return code and raise if it indicates an error.

    Args:
        code: The mbedTLS return code.

    Raises:
        If code is negative (indicates an error).
    """
    if code < 0:
        raise Error(String(TLSError(code)))


fn check_error(code: c_int, context: String) raises:
    """Check an mbedTLS return code and raise with context if it indicates an error.

    Args:
        code: The mbedTLS return code.
        context: Additional context for the error message.

    Raises:
        If code is negative (indicates an error).
    """
    if code < 0:
        raise Error(String(TLSError(code, context)))
