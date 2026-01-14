#!/bin/bash
# Build script for mojo-tls with static linking
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect mbedTLS paths
if [ "$(uname)" = "Darwin" ]; then
    # macOS - check Homebrew locations
    if [ -d "/opt/homebrew/opt/mbedtls" ]; then
        MBEDTLS_INC="/opt/homebrew/opt/mbedtls/include"
        MBEDTLS_LIB="/opt/homebrew/opt/mbedtls/lib"
    elif [ -d "/usr/local/opt/mbedtls" ]; then
        MBEDTLS_INC="/usr/local/opt/mbedtls/include"
        MBEDTLS_LIB="/usr/local/opt/mbedtls/lib"
    else
        echo "Error: mbedTLS not found. Install with: brew install mbedtls"
        exit 1
    fi
else
    # Linux - check common paths
    if [ -d "/usr/include/mbedtls" ]; then
        MBEDTLS_INC="/usr/include"
        MBEDTLS_LIB="/usr/lib"
    elif [ -d "/usr/local/include/mbedtls" ]; then
        MBEDTLS_INC="/usr/local/include"
        MBEDTLS_LIB="/usr/local/lib"
    else
        echo "Error: mbedTLS not found. Install with your package manager."
        exit 1
    fi
fi

# Detect Mojo runtime library path
if [ -n "$MOJO_RUNTIME_LIB" ]; then
    # Use environment variable if set
    :
elif [ -n "$VIRTUAL_ENV" ]; then
    # Check virtual environment
    MOJO_RUNTIME_LIB="$VIRTUAL_ENV/lib/python3.*/site-packages/modular/lib"
    MOJO_RUNTIME_LIB=$(echo $MOJO_RUNTIME_LIB)  # Expand glob
elif command -v mojo &> /dev/null; then
    # Find from mojo command location
    MOJO_BIN=$(dirname "$(command -v mojo)")
    MOJO_RUNTIME_LIB=$(dirname "$MOJO_BIN")/lib
fi

if [ ! -d "$MOJO_RUNTIME_LIB" ]; then
    echo "Error: Mojo runtime library not found."
    echo "Set MOJO_RUNTIME_LIB environment variable or activate a venv with Mojo installed."
    exit 1
fi

# Parse arguments
DEBUG_FLAG=""
BUNDLE_MODE=""
POSITIONAL_ARGS=()

for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_FLAG="-DMOJO_TLS_DEBUG"
            ;;
        --bundle)
            BUNDLE_MODE="1"
            ;;
        *)
            POSITIONAL_ARGS+=("$arg")
            ;;
    esac
done

# Restore positional args
set -- "${POSITIONAL_ARGS[@]}"

# Default input/output
INPUT_FILE="${1:-tests/test_static.mojo}"
OUTPUT_FILE="${2:-$(basename "${INPUT_FILE%.mojo}")}"

echo "=== Building mojo-tls with static linking ==="
echo "Input:  $INPUT_FILE"
echo "Output: $OUTPUT_FILE"
echo

# Step 1: Build the static shim library
echo "[1/3] Building static shim library..."
cd shim
clang -c mojo_tls_shim.c -o mojo_tls_shim.o -I${MBEDTLS_INC} -O2 $DEBUG_FLAG

if [ -n "$BUNDLE_MODE" ]; then
    # Create combined archive with all mbedTLS deps
    echo "      Bundling mbedTLS static libs..."
    if [ "$(uname)" = "Darwin" ]; then
        libtool -static -o libmojo_tls_full.a \
            mojo_tls_shim.o \
            ${MBEDTLS_LIB}/libmbedtls.a \
            ${MBEDTLS_LIB}/libmbedx509.a \
            ${MBEDTLS_LIB}/libmbedcrypto.a \
            ${MBEDTLS_LIB}/libtfpsacrypto.a
    else
        ar rcs libmojo_tls_full.a \
            mojo_tls_shim.o \
            ${MBEDTLS_LIB}/libmbedtls.a \
            ${MBEDTLS_LIB}/libmbedx509.a \
            ${MBEDTLS_LIB}/libmbedcrypto.a
    fi
    SHIM_LIB="$SCRIPT_DIR/shim/libmojo_tls_full.a"
    echo "      Created shim/libmojo_tls_full.a (bundled)"
else
    ar rcs libmojo_tls_shim.a mojo_tls_shim.o
    SHIM_LIB="$SCRIPT_DIR/shim/libmojo_tls_shim.a"
    echo "      Created shim/libmojo_tls_shim.a"
fi
cd ..

# Step 2: Compile Mojo to object file
echo "[2/3] Compiling Mojo to object file..."
OBJ_FILE="${OUTPUT_FILE}.o"
mojo build --emit object "$INPUT_FILE" -o "$OBJ_FILE" -I "$SCRIPT_DIR"
echo "      Created $OBJ_FILE"

# Step 3: Link everything together
echo "[3/3] Linking..."

# Build mbedTLS lib list (Linux may not have tfpsacrypto)
MBEDTLS_LIBS="${MBEDTLS_LIB}/libmbedtls.a ${MBEDTLS_LIB}/libmbedx509.a ${MBEDTLS_LIB}/libmbedcrypto.a"
if [ -f "${MBEDTLS_LIB}/libtfpsacrypto.a" ]; then
    MBEDTLS_LIBS="$MBEDTLS_LIBS ${MBEDTLS_LIB}/libtfpsacrypto.a"
fi

if [ -n "$BUNDLE_MODE" ]; then
    # Bundled mode - all mbedTLS in the archive
    clang "$OBJ_FILE" \
        "$SHIM_LIB" \
        -L${MOJO_RUNTIME_LIB} \
        -lKGENCompilerRTShared -lAsyncRTMojoBindings -lAsyncRTRuntimeGlobals \
        -o "$OUTPUT_FILE"
else
    # Normal mode - link mbedTLS static libs directly
    clang "$OBJ_FILE" \
        "$SHIM_LIB" \
        $MBEDTLS_LIBS \
        -L${MOJO_RUNTIME_LIB} \
        -lKGENCompilerRTShared -lAsyncRTMojoBindings -lAsyncRTRuntimeGlobals \
        -o "$OUTPUT_FILE"
fi

# Cleanup object file
rm -f "$OBJ_FILE"

echo
echo "=== Build complete ==="
echo "Binary: $OUTPUT_FILE"
echo
if [ "$(uname)" = "Darwin" ]; then
    echo "Run with:"
    echo "  DYLD_LIBRARY_PATH=${MOJO_RUNTIME_LIB} ./$OUTPUT_FILE"
else
    echo "Run with:"
    echo "  LD_LIBRARY_PATH=${MOJO_RUNTIME_LIB} ./$OUTPUT_FILE"
fi
