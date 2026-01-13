"""High-level TLS context for mbedTLS.

Provides a TLSContext struct that wraps an SSL connection with proper
initialization, handshake, I/O, and cleanup.
"""

from sys.ffi import external_call, c_int, c_char, c_size_t
from memory import UnsafePointer

from ._lib import SSL_CONTEXT_SIZE
from ._ffi.constants import (
    MBEDTLS_ERR_SSL_WANT_READ,
    MBEDTLS_ERR_SSL_WANT_WRITE,
    MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
)
from ._ffi.ssl import (
    ssl_init,
    ssl_free,
    ssl_setup,
    ssl_set_hostname,
    ssl_set_bio,
    ssl_handshake,
    ssl_read,
    ssl_write,
    ssl_close_notify,
    ssl_get_version,
    ssl_get_ciphersuite,
    ssl_get_verify_result,
    FFIPtr,
    alloc_ffi,
    free_ffi,
    strlen_ffi,
    strcpy_ffi,
)
from .error import check_error, TLSError
from .tls_config import TLSConfig


struct TLSContext(Movable):
    """High-level TLS context for a single connection.

    Wraps mbedTLS SSL context with proper initialization and cleanup.
    Takes ownership of a TLSConfig.

    Example:
        var config = TLSConfig()
        config.set_client_mode()
        config.load_system_ca_chain()

        var ctx = TLSContext(config^)
        ctx.set_hostname("example.com")
        # Set BIO callbacks...
        ctx.handshake()
    """

    var _config: TLSConfig
    var _ssl: FFIPtr
    var _handshake_done: Bool

    fn __init__(out self, var config: TLSConfig) raises:
        """Initialize a new TLS context with the given configuration.

        Takes ownership of the config.

        Args:
            config: TLS configuration to use for this context.

        Raises:
            If initialization or setup fails.
        """
        self._config = config^
        self._handshake_done = False

        # Allocate SSL context
        self._ssl = alloc_ffi(SSL_CONTEXT_SIZE)

        # Initialize SSL context
        ssl_init(self._ssl)

        # Set up with config
        var ret = ssl_setup(self._ssl, self._config.get_config_ptr())
        if ret < 0:
            ssl_free(self._ssl)
            free_ffi(self._ssl)
            check_error(ret, "ssl_setup")

    fn __moveinit__(out self, owned existing: Self):
        """Move constructor for TLSContext."""
        self._config = existing._config^
        self._ssl = existing._ssl
        self._handshake_done = existing._handshake_done
        # Invalidate source to prevent double-free
        existing._ssl = FFIPtr(0)

    fn __del__(owned self):
        """Clean up TLS context and free resources."""
        # Skip cleanup if this object was moved-from
        if not self._ssl:
            return
        ssl_free(self._ssl)
        free_ffi(self._ssl)

    fn set_hostname(mut self, hostname: String) raises:
        """Set the expected hostname for server certificate verification (SNI).

        Args:
            hostname: The expected server hostname.

        Raises:
            If setting hostname fails.
        """
        # Create null-terminated hostname buffer
        var hostname_bytes = hostname.as_bytes()
        var hostname_buf = List[UInt8](capacity=len(hostname_bytes) + 1)
        for i in range(len(hostname_bytes)):
            hostname_buf.append(hostname_bytes[i])
        hostname_buf.append(0)  # Null terminator
        var hostname_ptr = hostname_buf.unsafe_ptr().bitcast[c_char]()

        var ret = ssl_set_hostname(self._ssl, hostname_ptr)
        check_error(ret, "ssl_set_hostname")

    fn set_bio(
        mut self,
        bio_ctx: FFIPtr,
        f_send: FFIPtr,
        f_recv: FFIPtr,
        f_recv_timeout: FFIPtr,
    ):
        """Set the underlying I/O callbacks.

        Args:
            bio_ctx: Context passed to callbacks (e.g., socket context).
            f_send: Send callback function pointer.
            f_recv: Receive callback function pointer.
            f_recv_timeout: Receive with timeout callback (can be null).
        """
        ssl_set_bio(self._ssl, bio_ctx, f_send, f_recv, f_recv_timeout)

    fn handshake(mut self) raises:
        """Perform the TLS handshake.

        For non-blocking I/O, may need to be called multiple times until
        it succeeds or fails with a non-WANT_READ/WANT_WRITE error.

        Raises:
            If handshake fails with a fatal error.
        """
        while True:
            var ret = ssl_handshake(self._ssl)
            if ret == 0:
                self._handshake_done = True
                return
            if ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE:
                check_error(ret, "ssl_handshake")

    fn handshake_step(mut self) -> c_int:
        """Perform a single step of the TLS handshake.

        Useful for non-blocking I/O where you need to poll between steps.

        Returns:
            0 if handshake is complete, MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE
            if more I/O is needed, or negative error code.
        """
        var ret = ssl_handshake(self._ssl)
        if ret == 0:
            self._handshake_done = True
        return ret

    fn read(mut self, buf: UnsafePointer[UInt8], max_len: Int) raises -> Int:
        """Read decrypted application data.

        Args:
            buf: Buffer to store received data.
            max_len: Maximum number of bytes to read.

        Returns:
            Number of bytes read.

        Raises:
            If read fails with a fatal error.
        """
        while True:
            var ret = ssl_read(self._ssl, buf, c_size_t(max_len))
            if ret >= 0:
                return Int(ret)
            # Retry on non-fatal errors (TLS 1.3 post-handshake messages)
            if (
                ret == MBEDTLS_ERR_SSL_WANT_READ
                or ret == MBEDTLS_ERR_SSL_WANT_WRITE
                or ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
            ):
                continue
            check_error(ret, "ssl_read")

    fn read_nonblocking(mut self, buf: UnsafePointer[UInt8], max_len: Int) -> c_int:
        """Read decrypted application data (non-blocking).

        Args:
            buf: Buffer to store received data.
            max_len: Maximum number of bytes to read.

        Returns:
            Number of bytes read, MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE if
            would block, 0 for EOF, or negative error code.
        """
        return ssl_read(self._ssl, buf, c_size_t(max_len))

    fn write(mut self, buf: UnsafePointer[UInt8], length: Int) raises -> Int:
        """Write application data to be encrypted and sent.

        Args:
            buf: Buffer containing data to write.
            length: Number of bytes to write.

        Returns:
            Number of bytes written.

        Raises:
            If write fails with a fatal error.
        """
        while True:
            var ret = ssl_write(self._ssl, buf, c_size_t(length))
            if ret >= 0:
                return Int(ret)
            if ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE:
                check_error(ret, "ssl_write")
            # For WANT_READ/WANT_WRITE, loop and retry

    fn write_nonblocking(mut self, buf: UnsafePointer[UInt8], length: Int) -> c_int:
        """Write application data (non-blocking).

        Args:
            buf: Buffer containing data to write.
            length: Number of bytes to write.

        Returns:
            Number of bytes written, MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE if
            would block, or negative error code.
        """
        return ssl_write(self._ssl, buf, c_size_t(length))

    fn close_notify(mut self) raises:
        """Send close_notify alert to peer.

        Raises:
            If sending close_notify fails.
        """
        while True:
            var ret = ssl_close_notify(self._ssl)
            if ret == 0:
                return
            if ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE:
                check_error(ret, "ssl_close_notify")

    fn get_version(self) -> String:
        """Get the negotiated TLS version as a string.

        Returns:
            String like "TLSv1.3" or "TLSv1.2".
        """
        var ptr = ssl_get_version(self._ssl)
        if not ptr:
            return "Unknown"
        # Get string length via shim and copy to Mojo String
        var length = strlen_ffi(ptr)
        if length == 0:
            return "Unknown"
        # Create a buffer and copy the string data
        var buf = List[UInt8](capacity=length + 1)
        buf.resize(length + 1, 0)
        _ = strcpy_ffi(buf.unsafe_ptr(), length + 1, ptr)
        # Build string character by character
        var result = String()
        for i in range(Int(length)):
            result += chr(Int(buf[i]))
        return result

    fn get_ciphersuite(self) -> String:
        """Get the negotiated ciphersuite name.

        Returns:
            Ciphersuite name string.
        """
        var ptr = ssl_get_ciphersuite(self._ssl)
        if not ptr:
            return "Unknown"
        # Get string length via shim
        var length = strlen_ffi(ptr)
        if length == 0:
            return "Unknown"
        # Create a buffer and copy the string data
        var buf = List[UInt8](capacity=length + 1)
        buf.resize(length + 1, 0)
        _ = strcpy_ffi(buf.unsafe_ptr(), length + 1, ptr)
        # Build string character by character
        var result = String()
        for i in range(Int(length)):
            result += chr(Int(buf[i]))
        return result

    fn get_verify_result(self) -> UInt32:
        """Get certificate verification result flags.

        Returns:
            0 if verification succeeded, or bitwise OR of MBEDTLS_X509_BADCERT_*
            and MBEDTLS_X509_BADCRL_* flags.
        """
        return ssl_get_verify_result(self._ssl)

    fn is_handshake_done(self) -> Bool:
        """Check if handshake has completed successfully.

        Returns:
            True if handshake is complete.
        """
        return self._handshake_done

    fn get_ssl_ptr(self) -> FFIPtr:
        """Get the underlying SSL context pointer.

        Returns:
            Pointer to mbedtls_ssl_context.
        """
        return self._ssl


struct ServerTLSContext(Movable):
    """TLS context for server-accepted connections.

    Unlike TLSContext, this does not own a TLSConfig - it borrows a config
    pointer from the TLSListener that created it. The config must outlive
    this context.

    This is used internally by TLSListener.accept() to create per-connection
    TLS contexts that share a common configuration.
    """

    var _ssl: FFIPtr
    var _handshake_done: Bool

    fn __init__(out self, config_ptr: FFIPtr) raises:
        """Initialize a server TLS context with a borrowed config.

        Args:
            config_ptr: Pointer to mbedtls_ssl_config (borrowed, must outlive this context).

        Raises:
            If initialization or setup fails.
        """
        self._handshake_done = False

        # Allocate SSL context
        self._ssl = alloc_ffi(SSL_CONTEXT_SIZE)

        # Initialize SSL context
        ssl_init(self._ssl)

        # Set up with borrowed config pointer
        var ret = ssl_setup(self._ssl, config_ptr)
        if ret < 0:
            ssl_free(self._ssl)
            free_ffi(self._ssl)
            check_error(ret, "ssl_setup")

    fn __moveinit__(out self, owned existing: Self):
        """Move constructor for ServerTLSContext."""
        self._ssl = existing._ssl
        self._handshake_done = existing._handshake_done
        # Invalidate source to prevent double-free when it's destroyed
        existing._ssl = FFIPtr(0)

    fn __del__(owned self):
        """Clean up TLS context and free resources."""
        # Skip cleanup if this object was moved-from (pointer is null)
        if not self._ssl:
            return
        ssl_free(self._ssl)
        free_ffi(self._ssl)

    fn set_bio(
        mut self,
        bio_ctx: FFIPtr,
        f_send: FFIPtr,
        f_recv: FFIPtr,
        f_recv_timeout: FFIPtr,
    ):
        """Set the underlying I/O callbacks."""
        ssl_set_bio(self._ssl, bio_ctx, f_send, f_recv, f_recv_timeout)

    fn handshake(mut self) raises:
        """Perform the TLS handshake."""
        while True:
            var ret = ssl_handshake(self._ssl)
            if ret == 0:
                self._handshake_done = True
                return
            if ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE:
                check_error(ret, "ssl_handshake")

    fn read(mut self, buf: UnsafePointer[UInt8], max_len: Int) raises -> Int:
        """Read decrypted application data."""
        while True:
            var ret = ssl_read(self._ssl, buf, c_size_t(max_len))
            if ret >= 0:
                return Int(ret)
            if (
                ret == MBEDTLS_ERR_SSL_WANT_READ
                or ret == MBEDTLS_ERR_SSL_WANT_WRITE
                or ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
            ):
                continue
            check_error(ret, "ssl_read")

    fn write(mut self, buf: UnsafePointer[UInt8], length: Int) raises -> Int:
        """Write application data to be encrypted and sent."""
        while True:
            var ret = ssl_write(self._ssl, buf, c_size_t(length))
            if ret >= 0:
                return Int(ret)
            if ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE:
                check_error(ret, "ssl_write")

    fn close_notify(mut self) raises:
        """Send close_notify alert to peer."""
        while True:
            var ret = ssl_close_notify(self._ssl)
            if ret == 0:
                return
            if ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE:
                check_error(ret, "ssl_close_notify")

    fn get_version(self) -> String:
        """Get the negotiated TLS version as a string."""
        var ptr = ssl_get_version(self._ssl)
        if not ptr:
            return "Unknown"
        var length = strlen_ffi(ptr)
        if length == 0:
            return "Unknown"
        var buf = List[UInt8](capacity=length + 1)
        buf.resize(length + 1, 0)
        _ = strcpy_ffi(buf.unsafe_ptr(), length + 1, ptr)
        var result = String()
        for i in range(Int(length)):
            result += chr(Int(buf[i]))
        return result

    fn get_ciphersuite(self) -> String:
        """Get the negotiated ciphersuite name."""
        var ptr = ssl_get_ciphersuite(self._ssl)
        if not ptr:
            return "Unknown"
        var length = strlen_ffi(ptr)
        if length == 0:
            return "Unknown"
        var buf = List[UInt8](capacity=length + 1)
        buf.resize(length + 1, 0)
        _ = strcpy_ffi(buf.unsafe_ptr(), length + 1, ptr)
        var result = String()
        for i in range(Int(length)):
            result += chr(Int(buf[i]))
        return result

    fn is_handshake_done(self) -> Bool:
        """Check if handshake has completed successfully."""
        return self._handshake_done
