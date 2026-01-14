"""TLS server listener for accepting TLS connections.

Provides TLSListener for binding to a port and accepting TLS connections,
and TLSClientConnection for handling individual client connections.
"""

from sys.ffi import c_int, c_char, c_size_t
from memory import UnsafePointer

from ._lib import init_mojo_tls, NET_CONTEXT_SIZE
from ._ffi.constants import MBEDTLS_NET_PROTO_TCP
from ._ffi.net_sockets import (
    net_init,
    net_free,
    net_bind,
    net_bind_reuseport,
    net_accept_alloc,
    net_free_context,
    net_set_block,
    get_net_send_ptr,
    get_net_recv_ptr,
)
from ._ffi.ssl import FFIPtr, alloc_ffi, free_ffi, get_null_ptr
from .error import check_error
from .tls_config import TLSConfig
from .tls_context import ServerTLSContext


struct TLSClientConnection(Movable):
    """Represents an accepted TLS client connection.

    This struct owns both the client socket and the TLS context for a
    single client connection. It provides read/write/close methods for
    application data transfer.

    The connection is ready for the TLS handshake after creation.
    Call handshake() before read/write.
    """

    var _net_ctx: FFIPtr
    var _tls_ctx: ServerTLSContext
    var _connected: Bool

    fn __init__(
        out self, var net_ctx: FFIPtr, var tls_ctx: ServerTLSContext
    ):
        """Initialize from pre-created network and TLS contexts.

        Args:
            net_ctx: Client socket context (takes ownership).
            tls_ctx: Server TLS context (takes ownership).
        """
        self._net_ctx = net_ctx
        self._tls_ctx = tls_ctx^
        self._connected = False

    fn __moveinit__(out self, deinit existing: Self):
        """Move constructor."""
        self._net_ctx = existing._net_ctx
        self._tls_ctx = existing._tls_ctx^
        self._connected = existing._connected

    fn __del__(deinit self):
        """Clean up connection resources."""
        # Skip cleanup if moved-from
        if not self._net_ctx:
            return
        if self._connected:
            try:
                self._tls_ctx.close_notify()
            except:
                pass

        # Free the client socket (allocated by net_accept_alloc)
        net_free_context(self._net_ctx)

    fn handshake(mut self) raises:
        """Perform the TLS handshake with the client.

        Must be called before read/write operations.

        Raises:
            If handshake fails.
        """
        self._tls_ctx.handshake()
        self._connected = True

    fn read(mut self, buf: UnsafePointer[UInt8], max_len: Int) raises -> Int:
        """Read decrypted data from the client.

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
        """Write data to be encrypted and sent to the client.

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
        """Write a string to the client.

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
        """Close the connection gracefully.

        Sends close_notify alert to the client.

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
        """Check if the connection is established.

        Returns:
            True if handshake complete and connection active.
        """
        return self._connected

    fn has_peer_cert(self) -> Bool:
        """Check if the client presented a certificate.

        Useful for optional client certificate authentication.

        Returns:
            True if client certificate is available.
        """
        return self._tls_ctx.has_peer_cert()

    fn get_peer_cert_fingerprint(self) raises -> List[UInt8]:
        """Get SHA-256 fingerprint of the client's certificate.

        Returns:
            32-byte SHA-256 fingerprint as List[UInt8].

        Raises:
            If no client certificate or hashing fails.
        """
        return self._tls_ctx.get_peer_cert_fingerprint()

    fn get_peer_cert_fingerprint_hex(self) raises -> String:
        """Get SHA-256 fingerprint of the client's certificate as hex string.

        Returns:
            64-character lowercase hex string.

        Raises:
            If no client certificate or hashing fails.
        """
        return self._tls_ctx.get_peer_cert_fingerprint_hex()

    fn verify_peer_cert_fingerprint(self, expected_hex: String) raises -> Bool:
        """Verify client certificate fingerprint matches expected SHA-256 hex.

        Args:
            expected_hex: Expected fingerprint as hex string (case-insensitive).

        Returns:
            True if fingerprint matches.

        Raises:
            If no client certificate or hashing fails.
        """
        return self._tls_ctx.verify_peer_cert_fingerprint(expected_hex)


struct TLSListener(Movable):
    """TLS server listener for accepting incoming TLS connections.

    TLSListener binds to a port and listens for incoming connections.
    Call accept() to wait for and accept client connections.

    IMPORTANT: The listener owns the TLSConfig, which is borrowed by all
    accepted connections. The listener MUST be kept alive while any
    accepted connection is in use. If the listener is destroyed before
    its connections complete their handshakes, the handshakes will fail.

    To keep the listener alive, either:
    - Use it again after accept() (e.g., call is_bound())
    - Assign to _ at the end of scope: `_ = listener`

    Example:
        var listener = TLSListener.bind(
            "server.crt", "server.key",
            "0.0.0.0", "8443"
        )

        while True:
            var client = listener.accept()
            client.handshake()
            # ... handle client ...
            client.close()

        _ = listener  # Keep alive until done
    """

    var _listen_ctx: FFIPtr
    var _config: TLSConfig
    var _bound: Bool

    fn __init__(out self, var config: TLSConfig) raises:
        """Initialize a listener with the given server configuration.

        Args:
            config: TLS configuration with server cert/key loaded.

        Raises:
            If initialization fails.
        """
        init_mojo_tls()

        self._listen_ctx = alloc_ffi(NET_CONTEXT_SIZE)
        net_init(self._listen_ctx)

        self._config = config^
        self._bound = False

    fn __moveinit__(out self, deinit existing: Self):
        """Move constructor."""
        self._listen_ctx = existing._listen_ctx
        self._config = existing._config^
        self._bound = existing._bound

    fn __del__(deinit self):
        """Clean up listener resources."""
        # Skip cleanup if moved-from
        if not self._listen_ctx:
            return
        net_free(self._listen_ctx)
        free_ffi(self._listen_ctx)

    @staticmethod
    fn bind(
        cert_path: String,
        key_path: String,
        address: String,
        port: String,
    ) raises -> TLSListener:
        """Create a TLS server listener bound to the given address.

        Args:
            cert_path: Path to server certificate file (PEM).
            key_path: Path to server private key file (PEM).
            address: Address to bind to (e.g., "0.0.0.0" or "127.0.0.1").
            port: Port to listen on (e.g., "8443").

        Returns:
            A TLSListener ready to accept connections.

        Raises:
            If binding or configuration fails.
        """
        # Create and configure for server mode
        var config = TLSConfig()
        config.set_server_mode()
        config.load_own_cert_and_key(cert_path, key_path)

        var listener = TLSListener(config^)
        listener._bind(address, port)
        return listener^

    fn _bind(mut self, address: String, port: String) raises:
        """Internal method to bind the listening socket.

        Args:
            address: Address to bind to.
            port: Port to listen on.

        Raises:
            If binding fails.
        """
        # Create null-terminated address string
        var addr_bytes = address.as_bytes()
        var addr_buf = List[UInt8](capacity=len(addr_bytes) + 1)
        for i in range(len(addr_bytes)):
            addr_buf.append(addr_bytes[i])
        addr_buf.append(0)
        var addr_ptr = addr_buf.unsafe_ptr().bitcast[c_char]()

        # Create null-terminated port string
        var port_bytes = port.as_bytes()
        var port_buf = List[UInt8](capacity=len(port_bytes) + 1)
        for i in range(len(port_bytes)):
            port_buf.append(port_bytes[i])
        port_buf.append(0)
        var port_ptr = port_buf.unsafe_ptr().bitcast[c_char]()

        var ret = net_bind(
            self._listen_ctx, addr_ptr, port_ptr, MBEDTLS_NET_PROTO_TCP
        )
        check_error(ret, "net_bind")

        self._bound = True

    fn _bind_reuseport(mut self, address: String, port: String) raises:
        """Bind with SO_REUSEPORT for prefork servers.

        Uses SO_REUSEPORT to allow multiple processes to bind to the same port.
        Each process gets its own accept queue - kernel distributes connections.

        Args:
            address: Address to bind to.
            port: Port to listen on.

        Raises:
            If binding fails.
        """
        # Create null-terminated address string
        var addr_bytes = address.as_bytes()
        var addr_buf = List[UInt8](capacity=len(addr_bytes) + 1)
        for i in range(len(addr_bytes)):
            addr_buf.append(addr_bytes[i])
        addr_buf.append(0)
        var addr_ptr = addr_buf.unsafe_ptr().bitcast[c_char]()

        # Create null-terminated port string
        var port_bytes = port.as_bytes()
        var port_buf = List[UInt8](capacity=len(port_bytes) + 1)
        for i in range(len(port_bytes)):
            port_buf.append(port_bytes[i])
        port_buf.append(0)
        var port_ptr = port_buf.unsafe_ptr().bitcast[c_char]()

        var ret = net_bind_reuseport(
            self._listen_ctx, addr_ptr, port_ptr, MBEDTLS_NET_PROTO_TCP
        )
        check_error(ret, "net_bind_reuseport")

        self._bound = True

    fn accept(mut self) raises -> TLSClientConnection:
        """Accept an incoming client connection.

        Blocks until a client connects. Returns a TLSClientConnection
        ready for handshake.

        Returns:
            A TLSClientConnection for the accepted client.

        Raises:
            If accept fails.
        """
        if not self._bound:
            raise Error("Listener not bound")

        # Accept connection - shim allocates client context
        # Use a List to hold the return code and get a pointer to it
        var ret_code_buf = List[c_int](capacity=1)
        ret_code_buf.append(c_int(0))

        var client_net_ctx = net_accept_alloc(
            self._listen_ctx,
            get_null_ptr(),  # Don't need client IP
            0,
            get_null_ptr(),  # Don't need IP length
            ret_code_buf.unsafe_ptr(),
        )

        if not client_net_ctx:
            check_error(ret_code_buf[0], "net_accept")
            raise Error("Accept failed")

        # Set client socket to blocking mode
        var ret = net_set_block(client_net_ctx)
        if ret != 0:
            net_free_context(client_net_ctx)
            check_error(ret, "net_set_block")

        # Create TLS context for this connection (borrows config)
        var tls_ctx: ServerTLSContext
        try:
            tls_ctx = ServerTLSContext(self._config.get_config_ptr())
        except e:
            net_free_context(client_net_ctx)
            raise e^

        # Set up BIO callbacks
        tls_ctx.set_bio(
            client_net_ctx,
            get_net_send_ptr(),
            get_net_recv_ptr(),
            get_null_ptr(),
        )

        return TLSClientConnection(client_net_ctx, tls_ctx^)

    fn is_bound(self) -> Bool:
        """Check if the listener is bound.

        Returns:
            True if bound to a port.
        """
        return self._bound
