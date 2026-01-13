"""High-level TLS stream for easy client connections.

Provides a TLSStream struct that combines socket and TLS operations
into a simple, easy-to-use interface for TLS client connections.
"""

from sys.ffi import external_call, c_int, c_char, c_size_t
from memory import UnsafePointer

from ._lib import init_mojo_tls, NET_CONTEXT_SIZE
from ._ffi.constants import MBEDTLS_NET_PROTO_TCP
from ._ffi.net_sockets import (
    net_init,
    net_free,
    net_connect,
    net_set_block,
    get_net_send_ptr,
    get_net_recv_ptr,
    get_net_recv_timeout_ptr,
)
from ._ffi.ssl import FFIPtr, alloc_ffi, free_ffi, get_null_ptr
from .error import check_error
from .tls_config import TLSConfig
from .tls_context import TLSContext


struct TLSStream(Movable):
    """High-level TLS stream combining socket and TLS.

    Provides a simple interface for TLS client connections that manages
    both the underlying socket and TLS context.

    Example:
        var stream = TLSStream.connect("example.com", "443")
        var data = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        _ = stream.write_all(data)

        var buf = List[UInt8](capacity=4096)
        buf.resize(4096, 0)
        var n = stream.read(buf.unsafe_ptr(), 4096)
        print(String(buf.unsafe_ptr(), n))

        stream.close()
    """

    var _net_ctx: FFIPtr
    var _tls_ctx: TLSContext
    var _connected: Bool

    fn __init__(out self, var config: TLSConfig) raises:
        """Initialize a new TLS stream with the given configuration.

        The stream is not connected until connect() is called.

        Args:
            config: TLS configuration to use.

        Raises:
            If initialization fails.
        """
        # Allocate and init network context
        self._net_ctx = alloc_ffi(NET_CONTEXT_SIZE)
        net_init(self._net_ctx)

        # Create TLS context (takes ownership of config)
        self._tls_ctx = TLSContext(config^)
        self._connected = False

    fn __moveinit__(out self, owned existing: Self):
        """Move constructor for TLSStream."""
        self._net_ctx = existing._net_ctx
        self._tls_ctx = existing._tls_ctx^
        self._connected = existing._connected

    fn __del__(owned self):
        """Clean up TLS stream and free resources."""
        if self._connected:
            try:
                self._tls_ctx.close_notify()
            except:
                pass  # Ignore errors during cleanup

        net_free(self._net_ctx)
        free_ffi(self._net_ctx)

    @staticmethod
    fn connect(hostname: String, port: String) raises -> TLSStream:
        """Create a TLS stream and connect to a server.

        Uses system CA certificates and default TLS settings (TLS 1.2+).

        Args:
            hostname: Server hostname to connect to.
            port: Server port (e.g., "443").

        Returns:
            Connected TLSStream ready for I/O.

        Raises:
            If connection or handshake fails.
        """
        var config = TLSConfig()
        config.set_client_mode()
        config.load_system_ca_chain()

        var stream = TLSStream(config^)
        stream._connect(hostname, port)
        return stream^

    @staticmethod
    fn connect_tls13(hostname: String, port: String) raises -> TLSStream:
        """Create a TLS 1.3-only stream and connect to a server.

        Uses system CA certificates and enforces TLS 1.3.

        Args:
            hostname: Server hostname to connect to.
            port: Server port (e.g., "443").

        Returns:
            Connected TLSStream ready for I/O.

        Raises:
            If connection or handshake fails.
        """
        var config = TLSConfig()
        config.set_client_mode()
        config.set_tls13_only()
        config.load_system_ca_chain()

        var stream = TLSStream(config^)
        stream._connect(hostname, port)
        return stream^

    @staticmethod
    fn connect_insecure(hostname: String, port: String) raises -> TLSStream:
        """Create a TLS stream with disabled certificate verification.

        WARNING: This is insecure and should only be used for testing.

        Args:
            hostname: Server hostname to connect to.
            port: Server port (e.g., "443").

        Returns:
            Connected TLSStream ready for I/O.

        Raises:
            If connection or handshake fails.
        """
        var config = TLSConfig()
        config.set_client_mode()
        config.set_verify_none()

        var stream = TLSStream(config^)
        stream._connect(hostname, port)
        return stream^

    fn _connect(mut self, hostname: String, port: String) raises:
        """Internal method to connect to a server.

        Args:
            hostname: Server hostname.
            port: Server port.

        Raises:
            If connection or handshake fails.
        """
        # Connect socket - create null-terminated buffers
        var hostname_bytes = hostname.as_bytes()
        var hostname_buf = List[UInt8](capacity=len(hostname_bytes) + 1)
        for i in range(len(hostname_bytes)):
            hostname_buf.append(hostname_bytes[i])
        hostname_buf.append(0)  # Null terminator
        var hostname_ptr = hostname_buf.unsafe_ptr().bitcast[c_char]()

        var port_bytes = port.as_bytes()
        var port_buf = List[UInt8](capacity=len(port_bytes) + 1)
        for i in range(len(port_bytes)):
            port_buf.append(port_bytes[i])
        port_buf.append(0)  # Null terminator
        var port_ptr = port_buf.unsafe_ptr().bitcast[c_char]()

        var ret = net_connect(self._net_ctx, hostname_ptr, port_ptr, MBEDTLS_NET_PROTO_TCP)
        check_error(ret, "net_connect")

        # Set socket to blocking mode
        ret = net_set_block(self._net_ctx)
        check_error(ret, "net_set_block")

        # Set hostname for SNI
        self._tls_ctx.set_hostname(hostname)

        # Set up BIO callbacks to use mbedtls_net_send/recv
        var send_ptr = get_net_send_ptr()
        var recv_ptr = get_net_recv_ptr()

        self._tls_ctx.set_bio(
            self._net_ctx,
            send_ptr,
            recv_ptr,
            get_null_ptr(),  # No timeout callback
        )

        # Perform handshake
        self._tls_ctx.handshake()
        self._connected = True

    fn read(mut self, buf: UnsafePointer[UInt8], max_len: Int) raises -> Int:
        """Read decrypted data from the TLS stream.

        Args:
            buf: Buffer to store received data.
            max_len: Maximum number of bytes to read.

        Returns:
            Number of bytes read.

        Raises:
            If read fails.
        """
        return self._tls_ctx.read(buf, max_len)

    fn write(mut self, buf: UnsafePointer[UInt8], length: Int) raises -> Int:
        """Write data to be encrypted and sent over the TLS stream.

        Args:
            buf: Buffer containing data to write.
            length: Number of bytes to write.

        Returns:
            Number of bytes written.

        Raises:
            If write fails.
        """
        return self._tls_ctx.write(buf, length)

    fn write_all(mut self, data: String) raises -> Int:
        """Write a string to the TLS stream.

        Args:
            data: String data to write.

        Returns:
            Number of bytes written.

        Raises:
            If write fails.
        """
        var bytes = data.as_bytes()
        return self.write(bytes.unsafe_ptr(), len(bytes))

    fn close(mut self) raises:
        """Close the TLS stream gracefully.

        Sends close_notify alert and closes the socket.

        Raises:
            If close_notify fails.
        """
        if self._connected:
            self._tls_ctx.close_notify()
            self._connected = False

    fn get_version(self) -> String:
        """Get the negotiated TLS version.

        Returns:
            String like "TLSv1.3".
        """
        return self._tls_ctx.get_version()

    fn get_ciphersuite(self) -> String:
        """Get the negotiated ciphersuite.

        Returns:
            Ciphersuite name string.
        """
        return self._tls_ctx.get_ciphersuite()

    fn is_connected(self) -> Bool:
        """Check if the stream is connected.

        Returns:
            True if connected and handshake complete.
        """
        return self._connected
