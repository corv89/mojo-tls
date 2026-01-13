"""Test static linking with external_call."""
from sys.ffi import external_call, c_int, c_char
from memory import UnsafePointer
from pathlib import Path


fn main() raises:
    print("Testing static linking with external_call...")
    print()

    # Initialize PSA via statically linked shim
    print("Initializing PSA Crypto...")
    var init_ret = external_call["mojo_tls_init", c_int]()
    print("mojo_tls_init:", init_ret)
    if init_ret != 0:
        print("PSA init failed!")
        return

    # Query struct sizes to verify linking works
    var ssl_ctx_size = external_call["mojo_tls_sizeof_ssl_context", Int]()
    var ssl_cfg_size = external_call["mojo_tls_sizeof_ssl_config", Int]()
    var x509_size = external_call["mojo_tls_sizeof_x509_crt", Int]()
    print("Struct sizes:")
    print("  ssl_context:", ssl_ctx_size)
    print("  ssl_config:", ssl_cfg_size)
    print("  x509_crt:", x509_size)
    print()

    # Allocate and init ssl_config
    print("Allocating SSL config...")
    var config = external_call["mojo_tls_alloc", Int](352)
    print("  config at:", hex(config))
    external_call["mojo_tls_ssl_config_init", NoneType](config)

    # Allocate and init x509_crt chain
    print("Allocating x509_crt...")
    var ca_chain = external_call["mojo_tls_alloc", Int](1304)
    print("  ca_chain at:", hex(ca_chain))
    external_call["mojo_tls_x509_crt_init", NoneType](ca_chain)

    # Set config defaults
    print("Setting config defaults...")
    var defaults_ret = external_call["mojo_tls_ssl_config_defaults", c_int](config, 0, 0, 0)
    print("  ssl_config_defaults:", defaults_ret)

    # Parse CA certificate
    print()
    print("Loading CA certificates...")
    var path = Path("/opt/homebrew/etc/ca-certificates/cert.pem")
    var content = path.read_text()
    var data = content.as_bytes()
    var buf = List[UInt8](capacity=len(data) + 1)
    for i in range(len(data)):
        buf.append(data[i])
    buf.append(0)
    print("  Read", len(buf), "bytes")

    var parse_ret = external_call["mojo_tls_x509_crt_parse", c_int](ca_chain, buf.unsafe_ptr(), len(buf))
    print("  x509_crt_parse:", parse_ret)

    if parse_ret == 0:
        print()
        print("=" * 50)
        print("SUCCESS! Static linking works!")
        print("=" * 50)
    else:
        print()
        print("FAILED with error:", parse_ret)

    # Cleanup
    external_call["mojo_tls_x509_crt_free", NoneType](ca_chain)
    external_call["mojo_tls_free", NoneType](ca_chain)
    external_call["mojo_tls_ssl_config_free", NoneType](config)
    external_call["mojo_tls_free", NoneType](config)
