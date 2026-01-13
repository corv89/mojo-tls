"""mbedTLS constants and error codes for TLS 1.3.

These constants are from mbedTLS 4.0.0 ssl.h header.
"""

from sys.ffi import c_int

# ============================================================================
# TLS Protocol Versions
# ============================================================================

comptime MBEDTLS_SSL_VERSION_UNKNOWN: c_int = 0
comptime MBEDTLS_SSL_VERSION_TLS1_2: c_int = 0x0303
comptime MBEDTLS_SSL_VERSION_TLS1_3: c_int = 0x0304

# ============================================================================
# Endpoint Types
# ============================================================================

comptime MBEDTLS_SSL_IS_CLIENT: c_int = 0
comptime MBEDTLS_SSL_IS_SERVER: c_int = 1

# ============================================================================
# Transport Types
# ============================================================================

comptime MBEDTLS_SSL_TRANSPORT_STREAM: c_int = 0   # TLS
comptime MBEDTLS_SSL_TRANSPORT_DATAGRAM: c_int = 1  # DTLS

# ============================================================================
# Configuration Presets
# ============================================================================

comptime MBEDTLS_SSL_PRESET_DEFAULT: c_int = 0
comptime MBEDTLS_SSL_PRESET_SUITEB: c_int = 2

# ============================================================================
# Certificate Verification Modes
# ============================================================================

comptime MBEDTLS_SSL_VERIFY_NONE: c_int = 0
comptime MBEDTLS_SSL_VERIFY_OPTIONAL: c_int = 1
comptime MBEDTLS_SSL_VERIFY_REQUIRED: c_int = 2
comptime MBEDTLS_SSL_VERIFY_UNSET: c_int = 3

# ============================================================================
# TLS 1.3 Key Exchange Modes
# ============================================================================

comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK: c_int = 1
comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL: c_int = 2
comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL: c_int = 4

comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL: c_int = (
    MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK
    | MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL
    | MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL
)

comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL: c_int = (
    MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK
    | MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL
)

comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL: c_int = (
    MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL
    | MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL
)

comptime MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_NONE: c_int = 0

# ============================================================================
# Session Tickets
# ============================================================================

comptime MBEDTLS_SSL_SESSION_TICKETS_DISABLED: c_int = 0
comptime MBEDTLS_SSL_SESSION_TICKETS_ENABLED: c_int = 1

# ============================================================================
# Network Protocol
# ============================================================================

comptime MBEDTLS_NET_PROTO_TCP: c_int = 0
comptime MBEDTLS_NET_PROTO_UDP: c_int = 1

# ============================================================================
# SSL Error Codes (from ssl.h)
# ============================================================================

comptime MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS: c_int = -0x7000
comptime MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE: c_int = -0x7080
# Note: MBEDTLS_ERR_SSL_BAD_INPUT_DATA is PSA_ERROR_INVALID_ARGUMENT in 4.0.0
comptime MBEDTLS_ERR_SSL_BAD_INPUT_DATA: c_int = -0x7100  # Simplified
comptime MBEDTLS_ERR_SSL_INVALID_MAC: c_int = -0x7180
comptime MBEDTLS_ERR_SSL_INVALID_RECORD: c_int = -0x7200
comptime MBEDTLS_ERR_SSL_CONN_EOF: c_int = -0x7280
comptime MBEDTLS_ERR_SSL_DECODE_ERROR: c_int = -0x7300
comptime MBEDTLS_ERR_SSL_NO_RNG: c_int = -0x7400
comptime MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE: c_int = -0x7480
comptime MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION: c_int = -0x7500
comptime MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL: c_int = -0x7580
comptime MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED: c_int = -0x7600
comptime MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED: c_int = -0x7680
comptime MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE: c_int = -0x7700
comptime MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE: c_int = -0x7780
comptime MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME: c_int = -0x7800
comptime MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY: c_int = -0x7880
comptime MBEDTLS_ERR_SSL_BAD_CERTIFICATE: c_int = -0x7A00
comptime MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET: c_int = -0x7B00
comptime MBEDTLS_ERR_SSL_CANNOT_READ_EARLY_DATA: c_int = -0x7B80
comptime MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA: c_int = -0x7C00
comptime MBEDTLS_ERR_SSL_CANNOT_WRITE_EARLY_DATA: c_int = -0x7C80
comptime MBEDTLS_ERR_SSL_CACHE_ENTRY_NOT_FOUND: c_int = -0x7E80
# Note: MBEDTLS_ERR_SSL_ALLOC_FAILED is PSA_ERROR_INSUFFICIENT_MEMORY in 4.0.0
comptime MBEDTLS_ERR_SSL_ALLOC_FAILED: c_int = -0x7F00  # Simplified
comptime MBEDTLS_ERR_SSL_HW_ACCEL_FAILED: c_int = -0x7F80
comptime MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH: c_int = -0x6F80
comptime MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION: c_int = -0x6E80
comptime MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE: c_int = -0x6E00
comptime MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED: c_int = -0x6D80
comptime MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH: c_int = -0x6D00
comptime MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY: c_int = -0x6C80
comptime MBEDTLS_ERR_SSL_INTERNAL_ERROR: c_int = -0x6C00
comptime MBEDTLS_ERR_SSL_COUNTER_WRAPPING: c_int = -0x6B80
comptime MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO: c_int = -0x6B00
comptime MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED: c_int = -0x6A80
# Note: MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL is PSA_ERROR_BUFFER_TOO_SMALL in 4.0.0
comptime MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL: c_int = -0x6A00  # Simplified
comptime MBEDTLS_ERR_SSL_WANT_READ: c_int = -0x6900
comptime MBEDTLS_ERR_SSL_WANT_WRITE: c_int = -0x6880
comptime MBEDTLS_ERR_SSL_TIMEOUT: c_int = -0x6800
comptime MBEDTLS_ERR_SSL_CLIENT_RECONNECT: c_int = -0x6780
comptime MBEDTLS_ERR_SSL_UNEXPECTED_RECORD: c_int = -0x6700
comptime MBEDTLS_ERR_SSL_NON_FATAL: c_int = -0x6680
comptime MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER: c_int = -0x6600
comptime MBEDTLS_ERR_SSL_CONTINUE_PROCESSING: c_int = -0x6580
comptime MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS: c_int = -0x6500
comptime MBEDTLS_ERR_SSL_EARLY_MESSAGE: c_int = -0x6480
comptime MBEDTLS_ERR_SSL_UNEXPECTED_CID: c_int = -0x6000
comptime MBEDTLS_ERR_SSL_VERSION_MISMATCH: c_int = -0x5F00
comptime MBEDTLS_ERR_SSL_BAD_CONFIG: c_int = -0x5E80
comptime MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME: c_int = -0x5D80

# ============================================================================
# X.509 Error Codes
# ============================================================================

comptime MBEDTLS_ERR_X509_CERT_VERIFY_FAILED: c_int = -0x2700
comptime MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT: c_int = -0x2780
comptime MBEDTLS_ERR_X509_BAD_INPUT_DATA: c_int = -0x2800
comptime MBEDTLS_ERR_X509_FILE_IO_ERROR: c_int = -0x2880
comptime MBEDTLS_ERR_X509_BUFFER_TOO_SMALL: c_int = -0x2980

# ============================================================================
# PK Error Codes
# ============================================================================

comptime MBEDTLS_ERR_PK_BAD_INPUT_DATA: c_int = -0x3E80
comptime MBEDTLS_ERR_PK_FILE_IO_ERROR: c_int = -0x3E00
comptime MBEDTLS_ERR_PK_KEY_INVALID_FORMAT: c_int = -0x3D80
comptime MBEDTLS_ERR_PK_PASSWORD_REQUIRED: c_int = -0x3D00
comptime MBEDTLS_ERR_PK_PASSWORD_MISMATCH: c_int = -0x3C80

# ============================================================================
# NET Error Codes
# ============================================================================

comptime MBEDTLS_ERR_NET_SOCKET_FAILED: c_int = -0x0042
comptime MBEDTLS_ERR_NET_CONNECT_FAILED: c_int = -0x0044
comptime MBEDTLS_ERR_NET_BIND_FAILED: c_int = -0x0046
comptime MBEDTLS_ERR_NET_LISTEN_FAILED: c_int = -0x0048
comptime MBEDTLS_ERR_NET_ACCEPT_FAILED: c_int = -0x004A
comptime MBEDTLS_ERR_NET_RECV_FAILED: c_int = -0x004C
comptime MBEDTLS_ERR_NET_SEND_FAILED: c_int = -0x004E
comptime MBEDTLS_ERR_NET_CONN_RESET: c_int = -0x0050
comptime MBEDTLS_ERR_NET_UNKNOWN_HOST: c_int = -0x0052
comptime MBEDTLS_ERR_NET_BUFFER_TOO_SMALL: c_int = -0x0043
comptime MBEDTLS_ERR_NET_INVALID_CONTEXT: c_int = -0x0045
comptime MBEDTLS_ERR_NET_POLL_FAILED: c_int = -0x0047
comptime MBEDTLS_ERR_NET_BAD_INPUT_DATA: c_int = -0x0049

# ============================================================================
# Helper Functions
# ============================================================================

fn is_want_read(err: c_int) -> Bool:
    """Check if error indicates non-blocking read would block."""
    return err == MBEDTLS_ERR_SSL_WANT_READ


fn is_want_write(err: c_int) -> Bool:
    """Check if error indicates non-blocking write would block."""
    return err == MBEDTLS_ERR_SSL_WANT_WRITE


fn is_peer_close_notify(err: c_int) -> Bool:
    """Check if error indicates peer sent close_notify."""
    return err == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY


fn is_fatal_error(err: c_int) -> Bool:
    """Check if error is fatal (not WANT_READ/WANT_WRITE)."""
    return err < 0 and not is_want_read(err) and not is_want_write(err)
