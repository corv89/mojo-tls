"""Test mbedTLS library loading and basic FFI calls."""

from sys.ffi import c_size_t
from memory import alloc

from mojo_tls._lib import MbedTLSLibs, query_struct_sizes


fn main() raises:
    print("Testing mbedTLS library loading...")

    # Test loading libraries in dependency order
    print("\n1. Loading libraries...")
    var libs = MbedTLSLibs()
    print("   libmbedcrypto loaded: OK")
    print("   libmbedx509 loaded: OK")
    print("   libmbedtls loaded: OK")
    print("   libmojo_tls_shim loaded: OK")

    # Test struct size queries via shim
    print("\n2. Querying struct sizes via shim...")
    var sizes = query_struct_sizes(libs.shim)
    print("   ssl_context size:", sizes[0], "bytes")
    print("   ssl_config size:", sizes[1], "bytes")
    print("   ssl_session size:", sizes[2], "bytes")
    print("   x509_crt size:", sizes[3], "bytes")
    print("   pk_context size:", sizes[4], "bytes")
    print("   net_context size:", sizes[5], "bytes")

    # Verify sizes are reasonable
    var ssl_ctx_size = sizes[0]
    var ssl_cfg_size = sizes[1]
    if ssl_ctx_size < 100 or ssl_ctx_size > 20000:
        raise Error("ssl_context size seems wrong: " + String(ssl_ctx_size))
    if ssl_cfg_size < 100 or ssl_cfg_size > 10000:
        raise Error("ssl_config size seems wrong: " + String(ssl_cfg_size))

    print("\n3. Testing mbedtls_ssl_config_init...")
    # Allocate config and call init
    var config_ptr = alloc[UInt8](ssl_cfg_size).bitcast[NoneType]()
    libs.tls.call["mbedtls_ssl_config_init", NoneType](config_ptr)
    print("   mbedtls_ssl_config_init: OK")

    # Clean up
    libs.tls.call["mbedtls_ssl_config_free", NoneType](config_ptr)
    config_ptr.free()
    print("   mbedtls_ssl_config_free: OK")

    print("\n4. Testing shim version functions...")
    # Test that shim functions are callable
    # (We don't call them without a proper config, just verify symbols)
    var has_min_ver = libs.shim.check_symbol("mojo_tls_conf_min_version")
    var has_max_ver = libs.shim.check_symbol("mojo_tls_conf_max_version")
    if has_min_ver:
        print("   mojo_tls_conf_min_version: symbol found")
    if has_max_ver:
        print("   mojo_tls_conf_max_version: symbol found")

    print("\n" + "=" * 50)
    print("All library loading tests passed!")
    print("=" * 50)
