"""Raw TLS server test 2 - mimics wrapper allocation pattern."""

from sys.ffi import external_call, c_int, c_char, c_size_t

fn main() raises:
    print("=== Raw TLS Server Test 2 (mimics wrapper pattern) ===")
    print()

    # Initialize PSA Crypto
    print("Initializing PSA...")
    var ret = external_call["mojo_tls_init", c_int]()
    if ret != 0:
        raise Error("mojo_tls_init failed: " + String(ret))
    print("  mojo_tls_init: OK")

    # Get struct sizes
    var conf_size = Int(external_call["mojo_tls_sizeof_ssl_config", c_size_t]())
    var cert_size = Int(external_call["mojo_tls_sizeof_x509_crt", c_size_t]())
    var pk_size = Int(external_call["mojo_tls_sizeof_pk_context", c_size_t]())
    var net_size = Int(external_call["mojo_tls_sizeof_net_context", c_size_t]())
    var ssl_size = Int(external_call["mojo_tls_sizeof_ssl_context", c_size_t]())

    # Allocate and init like wrapper does (interleaved, with ca_chain)
    print("Allocating and initializing like wrapper...")

    # Config
    var conf = external_call["mojo_tls_alloc", Int](conf_size)
    external_call["mojo_tls_ssl_config_init", NoneType](conf)
    print("  conf:", conf)

    # CA chain (unused, but allocated like wrapper)
    var ca_chain = external_call["mojo_tls_alloc", Int](cert_size)
    external_call["mojo_tls_x509_crt_init", NoneType](ca_chain)
    print("  ca_chain:", ca_chain)

    # Own cert
    var cert = external_call["mojo_tls_alloc", Int](cert_size)
    external_call["mojo_tls_x509_crt_init", NoneType](cert)
    print("  cert:", cert)

    # PK context
    var pkey = external_call["mojo_tls_alloc", Int](pk_size)
    external_call["mojo_tls_pk_init", NoneType](pkey)
    print("  pkey:", pkey)

    # Set config defaults (endpoint=1 for server)
    print("Setting config defaults...")
    ret = external_call["mojo_tls_ssl_config_defaults", c_int](conf, c_int(1), c_int(0), c_int(0))
    if ret != 0:
        raise Error("ssl_config_defaults failed: " + String(ret))
    print("  ssl_config_defaults: OK")

    # Load certificate
    print("Loading certificate...")
    var cert_path = "tests/server-rsa.crt"
    var cert_path_bytes = cert_path.as_bytes()
    var cert_path_buf = List[UInt8](capacity=len(cert_path_bytes) + 1)
    for i in range(len(cert_path_bytes)):
        cert_path_buf.append(cert_path_bytes[i])
    cert_path_buf.append(0)
    var cert_path_ptr = cert_path_buf.unsafe_ptr().bitcast[c_char]()

    ret = external_call["mojo_tls_x509_crt_parse_file", c_int](cert, cert_path_ptr)
    if ret != 0:
        raise Error("x509_crt_parse_file failed: " + String(ret))
    print("  x509_crt_parse_file: OK")

    # Load private key
    print("Loading private key...")
    var key_path = "tests/server-rsa.key"
    var key_path_bytes = key_path.as_bytes()
    var key_path_buf = List[UInt8](capacity=len(key_path_bytes) + 1)
    for i in range(len(key_path_bytes)):
        key_path_buf.append(key_path_bytes[i])
    key_path_buf.append(0)
    var key_path_ptr = key_path_buf.unsafe_ptr().bitcast[c_char]()

    var empty_pwd_buf = List[UInt8](capacity=1)
    empty_pwd_buf.append(0)
    var pwd_ptr = empty_pwd_buf.unsafe_ptr().bitcast[c_char]()

    ret = external_call["mojo_tls_pk_parse_keyfile", c_int](pkey, key_path_ptr, pwd_ptr)
    if ret != 0:
        raise Error("pk_parse_keyfile failed: " + String(ret))
    print("  pk_parse_keyfile: OK")

    # Set own cert on config
    print("Setting own cert...")
    ret = external_call["mojo_tls_ssl_conf_own_cert", c_int](conf, cert, pkey)
    if ret != 0:
        raise Error("ssl_conf_own_cert failed: " + String(ret))
    print("  ssl_conf_own_cert: OK")

    # Now init mojo_tls again (like wrapper does when creating TLSListener)
    ret = external_call["mojo_tls_init", c_int]()
    print("  mojo_tls_init again:", ret)

    # Allocate listen_ctx
    var listen_ctx = external_call["mojo_tls_alloc", Int](net_size)
    external_call["mojo_tls_net_init", NoneType](listen_ctx)
    print("  listen_ctx:", listen_ctx)

    # Bind to port
    print("Binding to port...")
    var addr = "127.0.0.1"
    var addr_bytes = addr.as_bytes()
    var addr_buf = List[UInt8](capacity=len(addr_bytes) + 1)
    for i in range(len(addr_bytes)):
        addr_buf.append(addr_bytes[i])
    addr_buf.append(0)
    var addr_ptr = addr_buf.unsafe_ptr().bitcast[c_char]()

    var port = "8443"
    var port_bytes = port.as_bytes()
    var port_buf = List[UInt8](capacity=len(port_bytes) + 1)
    for i in range(len(port_bytes)):
        port_buf.append(port_bytes[i])
    port_buf.append(0)
    var port_ptr = port_buf.unsafe_ptr().bitcast[c_char]()

    ret = external_call["mojo_tls_net_bind", c_int](listen_ctx, addr_ptr, port_ptr, c_int(0))
    if ret != 0:
        raise Error("net_bind failed: " + String(ret))
    print("  net_bind: OK")

    print()
    print("Server listening on 127.0.0.1:8443")
    print("Waiting for connection...")

    # Accept connection
    var ret_code_buf = List[c_int](capacity=1)
    ret_code_buf.append(c_int(0))
    var client_ctx = external_call["mojo_tls_net_accept_alloc", Int](
        listen_ctx, Int(0), c_size_t(0), Int(0), ret_code_buf.unsafe_ptr()
    )
    if client_ctx == 0:
        raise Error("net_accept_alloc failed: " + String(ret_code_buf[0]))
    print("  net_accept_alloc: OK, client_ctx:", client_ctx)

    # Set blocking mode
    ret = external_call["mojo_tls_net_set_block", c_int](client_ctx)
    if ret != 0:
        raise Error("net_set_block failed: " + String(ret))
    print("  net_set_block: OK")

    # Allocate and init SSL context
    print("Setting up SSL context...")
    var ssl = external_call["mojo_tls_alloc", Int](ssl_size)
    print("  ssl:", ssl)
    external_call["mojo_tls_ssl_init", NoneType](ssl)

    # Setup SSL with config
    print("  calling ssl_setup with ssl=", ssl, ", conf=", conf)
    ret = external_call["mojo_tls_ssl_setup", c_int](ssl, conf)
    if ret != 0:
        raise Error("ssl_setup failed: " + String(ret))
    print("  ssl_setup: OK")

    # Set BIO callbacks
    print("Setting BIO...")
    var f_send = external_call["mojo_tls_get_net_send_ptr", Int]()
    var f_recv = external_call["mojo_tls_get_net_recv_ptr", Int]()
    external_call["mojo_tls_ssl_set_bio", NoneType](ssl, client_ctx, f_send, f_recv, Int(0))
    print("  ssl_set_bio: OK")

    # Perform handshake
    print("Performing handshake...")
    ret = external_call["mojo_tls_ssl_handshake", c_int](ssl)
    if ret != 0:
        raise Error("ssl_handshake failed: " + String(ret))

    print()
    print("=== SUCCESS! ===")
    print("  Handshake complete!")

    # Cleanup
    _ = external_call["mojo_tls_ssl_close_notify", c_int](ssl)
    external_call["mojo_tls_ssl_free", NoneType](ssl)
    external_call["mojo_tls_free", NoneType](ssl)
    external_call["mojo_tls_net_free_context", NoneType](client_ctx)
    external_call["mojo_tls_net_free", NoneType](listen_ctx)
    external_call["mojo_tls_free", NoneType](listen_ctx)
    external_call["mojo_tls_pk_free", NoneType](pkey)
    external_call["mojo_tls_free", NoneType](pkey)
    external_call["mojo_tls_x509_crt_free", NoneType](cert)
    external_call["mojo_tls_free", NoneType](cert)
    external_call["mojo_tls_x509_crt_free", NoneType](ca_chain)
    external_call["mojo_tls_free", NoneType](ca_chain)
    external_call["mojo_tls_ssl_config_free", NoneType](conf)
    external_call["mojo_tls_free", NoneType](conf)
