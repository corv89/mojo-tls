"""Test TLS server - simple echo server for testing."""

from mojo_tls import TLSListener


fn main() raises:
    print("=== TLS 1.3 Server Test ===")
    print()

    # Bind to localhost:8443 with test certificate (EC)
    print("Binding to 127.0.0.1:8443...")
    var listener = TLSListener.bind(
        "tests/server.crt",
        "tests/server.key",
        "127.0.0.1",
        "8443",
    )
    print("Server listening on 127.0.0.1:8443")
    print()
    print("Test with: openssl s_client -connect 127.0.0.1:8443")
    print("Press Ctrl+C to stop")
    print()

    # Accept one connection for testing
    print("Waiting for connection...")
    var client = listener.accept()
    print("Client connected!")

    # Perform TLS handshake
    print("Performing TLS handshake...")
    client.handshake()

    print("Handshake complete!")
    print("  TLS Version:", client.get_version())
    print("  Ciphersuite:", client.get_ciphersuite())
    print()

    # Read data from client
    print("Waiting for data...")
    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = client.read(buf.unsafe_ptr(), 4096)

    print("Received", n, "bytes:")
    print("-" * 40)
    var data = String()
    for i in range(n if n < 200 else 200):
        data += chr(Int(buf[i]))
    print(data)
    if n > 200:
        print("... (truncated)")
    print("-" * 40)
    print()

    # Send response
    var response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello from Mojo TLS Server!\r\n"
    print("Sending response...")
    _ = client.write_all(response)

    # Close connection
    print("Closing connection...")
    client.close()

    print()
    print("=== Server test complete ===")
    # Explicitly keep listener alive until the end
    _ = listener
