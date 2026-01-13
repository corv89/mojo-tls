"""Test using pure C connection function."""
from sys.ffi import external_call, c_int


fn main() raises:
    print("Testing pure C TLS connection...")
    print()

    # Initialize PSA
    var init_ret = external_call["mojo_tls_init", c_int]()
    print("mojo_tls_init:", init_ret)
    if init_ret != 0:
        print("PSA init failed!")
        return

    # Test pure C connection
    print()
    print("Calling mojo_tls_test_connection (pure C)...")
    var ret = external_call["mojo_tls_test_connection", c_int](
        "example.com".unsafe_cstr_ptr(),
        "443".unsafe_cstr_ptr()
    )
    print("Test result:", ret)

    if ret == 0:
        print()
        print("=" * 50)
        print("SUCCESS! Pure C TLS connection works!")
        print("=" * 50)
    else:
        print()
        print("FAILED with error:", ret)
