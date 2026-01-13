"""Test TLS client connection without cert verification."""

from mojo_tls import TLSStream


fn main() raises:
    print("Testing TLS connection (insecure mode)...")
    print()

    # Connect using insecure mode (no certificate verification)
    print("Connecting to example.com:443 (insecure)...")
    var stream = TLSStream.connect_insecure("example.com", "443")

    print("Connected!")
    print("  TLS Version:", stream.get_version())
    print("  Ciphersuite:", stream.get_ciphersuite())
    print()

    # Send HTTP request
    var request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    print("Sending HTTP request...")
    _ = stream.write_all(request)

    # Read response
    print("Reading response...")
    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = stream.read(buf.unsafe_ptr(), 4096)

    print()
    print("Response (" + String(n) + " bytes):")
    print("-" * 50)
    # Print first 500 chars of response
    var response_len = n if n < 500 else 500
    var response = String(buf.unsafe_ptr(), response_len)
    print(response)
    if n > 500:
        print("... (truncated)")
    print("-" * 50)
    print()

    # Close connection
    print("Closing connection...")
    stream.close()

    print()
    print("=" * 50)
    print("TLS insecure test passed!")
    print("=" * 50)
