"""Test using TLSConfig but manual accept/handshake."""

from sys.ffi import external_call, c_int, c_char, c_size_t

from mojo_tls.tls_config import TLSConfig
from mojo_tls._ffi.ssl import (
    ssl_init,
    ssl_setup,
    ssl_set_bio,
    ssl_handshake,
    ssl_close_notify,
    ssl_free,
    alloc_ffi,
    free_ffi,
    FFIPtr,
)
from mojo_tls._ffi.net_sockets import (
    net_init,
    net_bind,
    net_accept_alloc,
    net_set_block,
    net_free,
    net_free_context,
    get_net_send_ptr,
    get_net_recv_ptr,
)
from mojo_tls._ffi.constants import MBEDTLS_NET_PROTO_TCP
from mojo_tls._lib import NET_CONTEXT_SIZE, SSL_CONTEXT_SIZE, init_mojo_tls
from mojo_tls.error import check_error


fn main() raises:
    print("=== Partial Wrapper Test ===")
    print()

    # Use TLSConfig wrapper
    print("Creating TLSConfig...")
    var config = TLSConfig()
    config.set_server_mode()
    config.load_own_cert_and_key("tests/server.crt", "tests/server.key")
    print("  TLSConfig: OK")
    print("  config_ptr:", config.get_config_ptr().addr)

    # Manual listen setup
    print("Setting up listener...")
    init_mojo_tls()
    var listen_ctx = alloc_ffi(NET_CONTEXT_SIZE)
    net_init(listen_ctx)

    # Create null-terminated address string
    var addr = "127.0.0.1"
    var addr_bytes = addr.as_bytes()
    var addr_buf = List[UInt8](capacity=len(addr_bytes) + 1)
    for i in range(len(addr_bytes)):
        addr_buf.append(addr_bytes[i])
    addr_buf.append(0)
    var addr_ptr = addr_buf.unsafe_ptr().bitcast[c_char]()

    # Create null-terminated port string
    var port = "8443"
    var port_bytes = port.as_bytes()
    var port_buf = List[UInt8](capacity=len(port_bytes) + 1)
    for i in range(len(port_bytes)):
        port_buf.append(port_bytes[i])
    port_buf.append(0)
    var port_ptr = port_buf.unsafe_ptr().bitcast[c_char]()

    var ret = net_bind(listen_ctx, addr_ptr, port_ptr, MBEDTLS_NET_PROTO_TCP)
    check_error(ret, "net_bind")
    print("  net_bind: OK")

    print()
    print("Server listening on 127.0.0.1:8443")
    print("Waiting for connection...")

    # Accept connection
    var ret_code_buf = List[c_int](capacity=1)
    ret_code_buf.append(c_int(0))
    var client_ctx = net_accept_alloc(
        listen_ctx,
        FFIPtr(0),  # Don't need client IP
        0,
        FFIPtr(0),  # Don't need IP length
        ret_code_buf.unsafe_ptr(),
    )
    if not client_ctx:
        check_error(ret_code_buf[0], "net_accept")
        raise Error("Accept failed")
    print("  net_accept: OK, client_ctx:", client_ctx.addr)

    # Set blocking mode
    ret = net_set_block(client_ctx)
    check_error(ret, "net_set_block")
    print("  net_set_block: OK")

    # Allocate and init SSL context
    print("Setting up SSL context...")
    var ssl = alloc_ffi(SSL_CONTEXT_SIZE)
    print("  ssl:", ssl.addr)
    ssl_init(ssl)

    # Get config pointer and pass to ssl_setup
    var cfg_ptr = config.get_config_ptr()
    print("  Using config_ptr:", cfg_ptr.addr)
    ret = ssl_setup(ssl, cfg_ptr)
    check_error(ret, "ssl_setup")
    print("  ssl_setup: OK")

    # Set BIO
    print("Setting BIO...")
    ssl_set_bio(ssl, client_ctx, get_net_send_ptr(), get_net_recv_ptr(), FFIPtr(0))
    print("  ssl_set_bio: OK")

    # Perform handshake
    print("Performing handshake...")
    while True:
        ret = ssl_handshake(ssl)
        if ret == 0:
            break
        # Don't handle WANT_READ/WANT_WRITE for simplicity
        check_error(ret, "ssl_handshake")

    print()
    print("=== SUCCESS! ===")

    # Cleanup
    _ = ssl_close_notify(ssl)
    ssl_free(ssl)
    free_ffi(ssl)
    net_free_context(client_ctx)
    net_free(listen_ctx)
    free_ffi(listen_ctx)
