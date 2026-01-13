"""FFI bindings to mbedTLS network socket functions.

These bindings wrap the BSD-style socket abstraction from mbedtls/net_sockets.h.
The mbedtls_net_context is a simple struct containing just a file descriptor.
With static linking, all calls use external_call.
"""

from sys.ffi import external_call, c_int, c_size_t, c_char
from memory import UnsafePointer

from .ssl import FFIPtr, OpaquePtr


# ============================================================================
# Poll flags
# ============================================================================

comptime MBEDTLS_NET_POLL_READ: c_int = 1
comptime MBEDTLS_NET_POLL_WRITE: c_int = 2


# ============================================================================
# Network Context Functions
# ============================================================================


fn net_init(ctx: FFIPtr):
    """Initialize a network context."""
    external_call["mojo_tls_net_init", NoneType](ctx.addr)


fn net_free(ctx: FFIPtr):
    """Gracefully shutdown and free a network context."""
    external_call["mojo_tls_net_free", NoneType](ctx.addr)


fn net_close(ctx: FFIPtr):
    """Close down the connection without graceful shutdown."""
    external_call["mbedtls_net_close", NoneType](ctx.addr)


# ============================================================================
# Client Connection
# ============================================================================


fn net_connect(
    ctx: FFIPtr,
    host: UnsafePointer[c_char],
    port: UnsafePointer[c_char],
    proto: c_int,
) -> c_int:
    """Initiate a connection with host:port in the given protocol."""
    return external_call["mojo_tls_net_connect", c_int](ctx.addr, host, port, proto)


# ============================================================================
# Server Bind/Accept
# ============================================================================


fn net_bind(
    ctx: FFIPtr,
    bind_ip: UnsafePointer[c_char],
    port: UnsafePointer[c_char],
    proto: c_int,
) -> c_int:
    """Create a listening socket on bind_ip:port."""
    return external_call["mojo_tls_net_bind", c_int](ctx.addr, bind_ip, port, proto)


fn net_accept(
    bind_ctx: FFIPtr,
    client_ctx: FFIPtr,
    client_ip: FFIPtr,
    buf_size: c_size_t,
    cip_len: UnsafePointer[c_size_t],
) -> c_int:
    """Accept a connection from a remote client."""
    return external_call["mojo_tls_net_accept", c_int](
        bind_ctx.addr, client_ctx.addr, client_ip.addr, buf_size, cip_len
    )


# ============================================================================
# Socket Configuration
# ============================================================================


fn net_set_block(ctx: FFIPtr) -> c_int:
    """Set the socket to blocking mode."""
    return external_call["mojo_tls_net_set_block", c_int](ctx.addr)


fn net_set_nonblock(ctx: FFIPtr) -> c_int:
    """Set the socket to non-blocking mode."""
    return external_call["mojo_tls_net_set_nonblock", c_int](ctx.addr)


fn net_poll(ctx: FFIPtr, rw: UInt32, timeout: UInt32) -> c_int:
    """Check and wait for the context to be ready for read/write."""
    return external_call["mbedtls_net_poll", c_int](ctx.addr, rw, timeout)


# ============================================================================
# I/O Functions (used as BIO callbacks)
# ============================================================================


fn net_send(ctx: FFIPtr, buf: UnsafePointer[UInt8], length: c_size_t) -> c_int:
    """Write at most 'len' bytes to the socket."""
    return external_call["mbedtls_net_send", c_int](ctx.addr, buf, length)


fn net_recv(ctx: FFIPtr, buf: UnsafePointer[UInt8], length: c_size_t) -> c_int:
    """Read at most 'len' bytes from the socket."""
    return external_call["mbedtls_net_recv", c_int](ctx.addr, buf, length)


fn net_recv_timeout(
    ctx: FFIPtr,
    buf: UnsafePointer[UInt8],
    length: c_size_t,
    timeout: UInt32,
) -> c_int:
    """Read at most 'len' bytes, blocking for at most 'timeout' ms."""
    return external_call["mbedtls_net_recv_timeout", c_int](ctx.addr, buf, length, timeout)


# ============================================================================
# Function Pointer Getters (for ssl_set_bio)
# ============================================================================


fn get_net_send_ptr() -> FFIPtr:
    """Get function pointer to mbedtls_net_send for use with ssl_set_bio."""
    return FFIPtr(external_call["mojo_tls_get_net_send_ptr", Int]())


fn get_net_recv_ptr() -> FFIPtr:
    """Get function pointer to mbedtls_net_recv for use with ssl_set_bio."""
    return FFIPtr(external_call["mojo_tls_get_net_recv_ptr", Int]())


fn get_net_recv_timeout_ptr() -> FFIPtr:
    """Get function pointer to mbedtls_net_recv_timeout for use with ssl_set_bio."""
    return FFIPtr(external_call["mojo_tls_get_net_recv_timeout_ptr", Int]())
