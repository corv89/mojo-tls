"""Test calling the shim's test_connection function directly."""

from sys.ffi import OwnedDLHandle, c_int, c_char


fn main() raises:
    print("Testing direct shim connection...")

    # Load shim library
    var shim = OwnedDLHandle("/Users/corv/Src/mojo-tls/shim/libmojo_tls_shim.dylib")
    print("Shim loaded")

    # Initialize PSA
    var init_ret = shim.call["mojo_tls_init", c_int]()
    print("mojo_tls_init returned:", init_ret)

    # Call test connection
    var host = "example.com"
    var port = "443"

    var host_bytes = host.as_bytes()
    var host_buf = List[UInt8](capacity=len(host_bytes) + 1)
    for i in range(len(host_bytes)):
        host_buf.append(host_bytes[i])
    host_buf.append(0)

    var port_bytes = port.as_bytes()
    var port_buf = List[UInt8](capacity=len(port_bytes) + 1)
    for i in range(len(port_bytes)):
        port_buf.append(port_bytes[i])
    port_buf.append(0)

    print("Calling mojo_tls_test_connection...")
    var ret = shim.call["mojo_tls_test_connection", c_int](
        host_buf.unsafe_ptr().bitcast[c_char](),
        port_buf.unsafe_ptr().bitcast[c_char]()
    )
    print("mojo_tls_test_connection returned:", ret)

    if ret == 0:
        print("SUCCESS!")
    else:
        print("FAILED with error:", ret)
