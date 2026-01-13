"""Test PSA crypto initialization."""

from sys.ffi import OwnedDLHandle, c_int


fn main() raises:
    print("Loading mbedTLS libraries...")

    var base = "/opt/homebrew/opt/mbedtls/lib/"
    var crypto = OwnedDLHandle(base + "libmbedcrypto.dylib")
    print("  Loaded libmbedcrypto.dylib")

    var x509 = OwnedDLHandle(base + "libmbedx509.dylib")
    print("  Loaded libmbedx509.dylib")

    var tls = OwnedDLHandle(base + "libmbedtls.dylib")
    print("  Loaded libmbedtls.dylib")

    print()
    print("Initializing PSA Crypto...")
    var ret = crypto.call["psa_crypto_init", c_int]()
    print("  psa_crypto_init returned:", ret)

    if ret != 0:
        print("  ERROR: PSA Crypto init failed!")
    else:
        print("  SUCCESS: PSA Crypto initialized!")

    print()
    print("Test complete!")
