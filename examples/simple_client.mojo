"""Simple HTTPS client example using mojo_tls.

This example connects to a server over TLS 1.3 and performs a GET request.
"""

from mojo_tls import TLSStream


fn main() raises:
    print("Connecting to httpbin.org:443...")

    # Connect with TLS 1.3 only
    var stream = TLSStream.connect_tls13("httpbin.org", "443")

    print("Connected!")
    print("TLS Version:", stream.get_version())
    print("Ciphersuite:", stream.get_ciphersuite())

    # Send HTTP request
    var request = "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
    print("\nSending request...")
    _ = stream.write_all(request)

    # Read response
    print("\nResponse:")
    print("-" * 60)

    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)

    var total = 0
    while True:
        try:
            var n = stream.read(buf.unsafe_ptr(), 4096)
            if n == 0:
                break
            total += n
            # Print the response
            print(String(buf.unsafe_ptr(), n), end="")
        except e:
            # Check if it's just a close_notify
            if "close_notify" in str(e) or "EOF" in str(e):
                break
            raise e

    print("-" * 60)
    print("\nReceived", total, "bytes")

    # Close connection
    try:
        stream.close()
    except:
        pass  # Ignore close errors

    print("Done!")
