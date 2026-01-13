"""mbedTLS static linking support.

With static linking, all mbedTLS functions are called via external_call
to the statically linked shim library. No dynamic library loading needed.
"""

from sys.ffi import external_call, c_int, c_size_t


fn init_mojo_tls() raises:
    """Initialize mbedTLS and PSA Crypto.

    Must be called before any other TLS operations.
    Safe to call multiple times - PSA Crypto initialization is idempotent
    (tracked in C shim), and struct size validation is cheap.

    Raises:
        If PSA Crypto initialization or struct size validation fails.
    """
    var ret = external_call["mojo_tls_init", c_int]()
    if ret != 0:
        raise Error("Failed to initialize mojo_tls (PSA Crypto): " + String(ret))

    # Validate struct sizes on every call (cheap operation)
    # This catches mbedTLS version mismatches early
    _validate_struct_sizes()


fn _validate_struct_sizes() raises:
    """Validate that compiled struct sizes match expected values.

    This catches mbedTLS version mismatches that would cause memory corruption.

    Raises:
        If any struct size doesn't match the expected value.
    """
    var actual = query_struct_sizes()

    if actual[0] != SSL_CONTEXT_SIZE:
        raise Error(
            "mbedTLS struct size mismatch: ssl_context is "
            + String(actual[0])
            + " bytes, expected "
            + String(SSL_CONTEXT_SIZE)
        )
    if actual[1] != SSL_CONFIG_SIZE:
        raise Error(
            "mbedTLS struct size mismatch: ssl_config is "
            + String(actual[1])
            + " bytes, expected "
            + String(SSL_CONFIG_SIZE)
        )
    if actual[3] != X509_CRT_SIZE:
        raise Error(
            "mbedTLS struct size mismatch: x509_crt is "
            + String(actual[3])
            + " bytes, expected "
            + String(X509_CRT_SIZE)
        )
    if actual[4] != PK_CONTEXT_SIZE:
        raise Error(
            "mbedTLS struct size mismatch: pk_context is "
            + String(actual[4])
            + " bytes, expected "
            + String(PK_CONTEXT_SIZE)
        )
    if actual[5] != NET_CONTEXT_SIZE:
        raise Error(
            "mbedTLS struct size mismatch: net_context is "
            + String(actual[5])
            + " bytes, expected "
            + String(NET_CONTEXT_SIZE)
        )


# Struct sizes from mbedTLS 4.0.0 Homebrew build
# These are queried via the shim at build time
comptime SSL_CONTEXT_SIZE = 840
comptime SSL_CONFIG_SIZE = 352
comptime SSL_SESSION_SIZE = 496
comptime X509_CRT_SIZE = 1304
comptime PK_CONTEXT_SIZE = 584
comptime NET_CONTEXT_SIZE = 4


fn query_struct_sizes() raises -> Tuple[Int, Int, Int, Int, Int, Int]:
    """Query struct sizes from the shim library.

    Returns:
        Tuple of (ssl_context, ssl_config, ssl_session, x509_crt, pk_context, net_context) sizes.
    """
    var ssl_ctx = Int(external_call["mojo_tls_sizeof_ssl_context", c_size_t]())
    var ssl_cfg = Int(external_call["mojo_tls_sizeof_ssl_config", c_size_t]())
    var ssl_sess = Int(external_call["mojo_tls_sizeof_ssl_session", c_size_t]())
    var x509 = Int(external_call["mojo_tls_sizeof_x509_crt", c_size_t]())
    var pk = Int(external_call["mojo_tls_sizeof_pk_context", c_size_t]())
    var net = Int(external_call["mojo_tls_sizeof_net_context", c_size_t]())

    return (ssl_ctx, ssl_cfg, ssl_sess, x509, pk, net)
