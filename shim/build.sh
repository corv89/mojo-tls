#!/bin/bash
# Build script for mojo_tls_shim
#
# This builds a shared library that wraps mbedTLS functions for use
# with Mojo's FFI. The library is linked against the mbedTLS libraries.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# mbedTLS paths (Homebrew on macOS)
MBEDTLS_INCLUDE="/opt/homebrew/opt/mbedtls/include"
MBEDTLS_LIB="/opt/homebrew/opt/mbedtls/lib"

# Check if mbedTLS is installed
if [ ! -d "$MBEDTLS_INCLUDE" ]; then
    echo "Error: mbedTLS not found at $MBEDTLS_INCLUDE"
    echo "Install with: brew install mbedtls"
    exit 1
fi

# Compile the shim, linking against mbedTLS
echo "Compiling mojo_tls_shim.c..."
cc -shared -fPIC \
    -I"$MBEDTLS_INCLUDE" \
    -L"$MBEDTLS_LIB" \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    -Wl,-rpath,"$MBEDTLS_LIB" \
    -o libmojo_tls_shim.dylib \
    mojo_tls_shim.c

echo "Built: $SCRIPT_DIR/libmojo_tls_shim.dylib"

# Verify the library links correctly
echo ""
echo "Verifying library dependencies..."
otool -L libmojo_tls_shim.dylib

# Print struct sizes for verification
echo ""
echo "Verifying struct sizes..."
cat > /tmp/check_sizes.c << 'EOF'
#include <stdio.h>
#include <mbedtls/ssl.h>
#include <mbedtls/private/entropy.h>
#include <mbedtls/private/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>

int main() {
    printf("mbedtls_ssl_context:     %zu bytes\n", sizeof(mbedtls_ssl_context));
    printf("mbedtls_ssl_config:      %zu bytes\n", sizeof(mbedtls_ssl_config));
    printf("mbedtls_ssl_session:     %zu bytes\n", sizeof(mbedtls_ssl_session));
    printf("mbedtls_entropy_context: %zu bytes\n", sizeof(mbedtls_entropy_context));
    printf("mbedtls_ctr_drbg_context:%zu bytes\n", sizeof(mbedtls_ctr_drbg_context));
    printf("mbedtls_x509_crt:        %zu bytes\n", sizeof(mbedtls_x509_crt));
    printf("mbedtls_pk_context:      %zu bytes\n", sizeof(mbedtls_pk_context));
    printf("mbedtls_net_context:     %zu bytes\n", sizeof(mbedtls_net_context));
    return 0;
}
EOF

cc -I"$MBEDTLS_INCLUDE" -o /tmp/check_sizes /tmp/check_sizes.c 2>/dev/null && /tmp/check_sizes
rm -f /tmp/check_sizes /tmp/check_sizes.c

# List exported symbols
echo ""
echo "Exported symbols (mojo_tls_*):"
nm -gU libmojo_tls_shim.dylib | grep "mojo_tls_" | head -20
echo "... ($(nm -gU libmojo_tls_shim.dylib | grep -c 'mojo_tls_') total)"

echo ""
echo "Done!"
