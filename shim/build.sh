#!/bin/bash
# Build script for mojo_tls_shim shared library
#
# This builds a shared library that wraps mbedTLS functions for use
# with Mojo's FFI. The library is linked against the mbedTLS libraries.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Detect mbedTLS paths
if [ "$(uname)" = "Darwin" ]; then
    # macOS - check Homebrew locations
    if [ -d "/opt/homebrew/opt/mbedtls" ]; then
        MBEDTLS_INCLUDE="/opt/homebrew/opt/mbedtls/include"
        MBEDTLS_LIB="/opt/homebrew/opt/mbedtls/lib"
    elif [ -d "/usr/local/opt/mbedtls" ]; then
        MBEDTLS_INCLUDE="/usr/local/opt/mbedtls/include"
        MBEDTLS_LIB="/usr/local/opt/mbedtls/lib"
    else
        echo "Error: mbedTLS not found at Homebrew locations"
        echo "Install with: brew install mbedtls"
        exit 1
    fi
    SHARED_EXT="dylib"
    RPATH_FLAG="-Wl,-rpath,$MBEDTLS_LIB"
else
    # Linux - check common paths
    if [ -d "/usr/include/mbedtls" ]; then
        MBEDTLS_INCLUDE="/usr/include"
        MBEDTLS_LIB="/usr/lib"
    elif [ -d "/usr/local/include/mbedtls" ]; then
        MBEDTLS_INCLUDE="/usr/local/include"
        MBEDTLS_LIB="/usr/local/lib"
    else
        echo "Error: mbedTLS not found"
        echo "Install with your package manager (e.g., apt install libmbedtls-dev)"
        exit 1
    fi
    SHARED_EXT="so"
    RPATH_FLAG="-Wl,-rpath,$MBEDTLS_LIB"
fi

# Compile the shim, linking against mbedTLS
# Add -DMOJO_TLS_DEBUG for debug output
DEBUG_FLAGS=""
if [ "$1" = "debug" ]; then
    DEBUG_FLAGS="-DMOJO_TLS_DEBUG"
    echo "Compiling mojo_tls_shim.c with DEBUG enabled..."
else
    echo "Compiling mojo_tls_shim.c..."
fi

cc -shared -fPIC \
    $DEBUG_FLAGS \
    -I"$MBEDTLS_INCLUDE" \
    -L"$MBEDTLS_LIB" \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    $RPATH_FLAG \
    -o libmojo_tls_shim.$SHARED_EXT \
    mojo_tls_shim.c

echo "Built: $SCRIPT_DIR/libmojo_tls_shim.$SHARED_EXT"

# Verify the library links correctly
echo ""
echo "Verifying library dependencies..."
if [ "$(uname)" = "Darwin" ]; then
    otool -L libmojo_tls_shim.$SHARED_EXT
else
    ldd libmojo_tls_shim.$SHARED_EXT
fi

# Print struct sizes for verification
echo ""
echo "Verifying struct sizes..."
cat > /tmp/check_sizes.c << 'EOF'
#include <stdio.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>

#ifdef MBEDTLS_PRIVATE_ACCESS
#include <mbedtls/private/entropy.h>
#include <mbedtls/private/ctr_drbg.h>
#endif

int main() {
    printf("mbedtls_ssl_context:     %zu bytes\n", sizeof(mbedtls_ssl_context));
    printf("mbedtls_ssl_config:      %zu bytes\n", sizeof(mbedtls_ssl_config));
    printf("mbedtls_ssl_session:     %zu bytes\n", sizeof(mbedtls_ssl_session));
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
if [ "$(uname)" = "Darwin" ]; then
    nm -gU libmojo_tls_shim.$SHARED_EXT | grep "mojo_tls_" | head -20
    echo "... ($(nm -gU libmojo_tls_shim.$SHARED_EXT | grep -c 'mojo_tls_') total)"
else
    nm -D libmojo_tls_shim.$SHARED_EXT | grep "mojo_tls_" | head -20
    echo "... ($(nm -D libmojo_tls_shim.$SHARED_EXT | grep -c 'mojo_tls_') total)"
fi

echo ""
echo "Done!"
