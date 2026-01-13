#!/bin/bash
set -e

MBEDTLS_INC="/opt/homebrew/opt/mbedtls/include"

echo "Building static shim library..."
clang -c mojo_tls_shim.c -o mojo_tls_shim.o -I${MBEDTLS_INC} -O2
ar rcs libmojo_tls_shim.a mojo_tls_shim.o

echo "Created libmojo_tls_shim.a"
ls -la libmojo_tls_shim.a

echo ""
echo "Symbols in archive:"
nm libmojo_tls_shim.a | grep " T " | head -20
