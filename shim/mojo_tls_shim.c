/*
 * mojo_tls_shim.c - C shim for Mojo mbedTLS bindings
 *
 * Provides wrappers for mbedTLS functions to work with Mojo's FFI.
 * Each wrapper function simply calls the corresponding mbedTLS function.
 */

#include "mojo_tls_shim.h"

#include <stdlib.h>
#include <string.h>

/* Debug output control - compile with -DMOJO_TLS_DEBUG to enable */
#ifdef MOJO_TLS_DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINT(...) ((void)0)
#endif
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#ifdef MOJO_TLS_DEBUG
static void mojo_tls_debug_callback(void *ctx, int level, const char *file, int line, const char *str) {
    (void)ctx;
    fprintf(stderr, "[mbedTLS %d] %s:%04d: %s", level, file, line, str);
}
#endif
#include <mbedtls/private/entropy.h>    /* Moved to private in 4.0.0 */
#include <mbedtls/private/ctr_drbg.h>   /* Moved to private in 4.0.0 */
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <psa/crypto.h>  /* Required for PSA Crypto init in mbedTLS 4.0.0 */

/* ============================================================================
 * Library Initialization
 * ============================================================================ */

static int psa_initialized = 0;

int mojo_tls_init(void) {
    DEBUG_PRINT("[C DEBUG] mojo_tls_init called, psa_initialized=%d\n", psa_initialized);
    if (psa_initialized) {
        DEBUG_PRINT("[C DEBUG] Already initialized, returning 0\n");
        return 0;  /* Already initialized */
    }
    psa_status_t status = psa_crypto_init();
    DEBUG_PRINT("[C DEBUG] psa_crypto_init returned %d\n", (int)status);
    if (status == PSA_SUCCESS) {
        psa_initialized = 1;
        DEBUG_PRINT("[C DEBUG] PSA initialized successfully\n");
        return 0;
    }
    DEBUG_PRINT("[C DEBUG] PSA init failed with %d\n", (int)status);
    return (int)status;
}

/* ============================================================================
 * Struct size queries
 * ============================================================================ */

size_t mojo_tls_sizeof_ssl_context(void) {
    return sizeof(mbedtls_ssl_context);
}

size_t mojo_tls_sizeof_ssl_config(void) {
    return sizeof(mbedtls_ssl_config);
}

size_t mojo_tls_sizeof_ssl_session(void) {
    return sizeof(mbedtls_ssl_session);
}

size_t mojo_tls_sizeof_entropy_context(void) {
    return sizeof(mbedtls_entropy_context);
}

size_t mojo_tls_sizeof_ctr_drbg_context(void) {
    return sizeof(mbedtls_ctr_drbg_context);
}

size_t mojo_tls_sizeof_x509_crt(void) {
    return sizeof(mbedtls_x509_crt);
}

size_t mojo_tls_sizeof_pk_context(void) {
    return sizeof(mbedtls_pk_context);
}

size_t mojo_tls_sizeof_net_context(void) {
    return sizeof(mbedtls_net_context);
}

/* ============================================================================
 * TLS version configuration wrappers (for static inline functions)
 * ============================================================================ */

void mojo_tls_conf_min_version(void *conf, int version) {
    mbedtls_ssl_conf_min_tls_version(
        (mbedtls_ssl_config *)conf,
        (mbedtls_ssl_protocol_version)version
    );
}

void mojo_tls_conf_max_version(void *conf, int version) {
    mbedtls_ssl_conf_max_tls_version(
        (mbedtls_ssl_config *)conf,
        (mbedtls_ssl_protocol_version)version
    );
}

/* ============================================================================
 * SSL Context Functions
 * ============================================================================ */

void mojo_tls_ssl_init(void *ssl) {
    DEBUG_PRINT("[C DEBUG] ssl_init called: ssl=%p\n", ssl);
    mbedtls_ssl_init((mbedtls_ssl_context *)ssl);
    DEBUG_PRINT("[C DEBUG] ssl_init done\n");
}

void mojo_tls_ssl_free(void *ssl) {
    mbedtls_ssl_free((mbedtls_ssl_context *)ssl);
}

int mojo_tls_ssl_setup(void *ssl, const void *conf) {
    DEBUG_PRINT("[C DEBUG] ssl_setup called: ssl=%p conf=%p\n", ssl, conf);
    int ret = mbedtls_ssl_setup(
        (mbedtls_ssl_context *)ssl,
        (const mbedtls_ssl_config *)conf
    );
    DEBUG_PRINT("[C DEBUG] ssl_setup returned: %d\n", ret);
    return ret;
}

int mojo_tls_ssl_set_hostname(void *ssl, const char *hostname) {
    return mbedtls_ssl_set_hostname((mbedtls_ssl_context *)ssl, hostname);
}

void mojo_tls_ssl_set_bio(void *ssl, void *p_bio,
                          void *f_send, void *f_recv, void *f_recv_timeout) {
    DEBUG_PRINT("[C DEBUG] ssl_set_bio called: ssl=%p p_bio=%p f_send=%p f_recv=%p\n",
            ssl, p_bio, f_send, f_recv);
    if (p_bio) {
        mbedtls_net_context *net = (mbedtls_net_context *)p_bio;
        DEBUG_PRINT("[C DEBUG] ssl_set_bio: p_bio->fd = %d\n", net->fd);
    }
    mbedtls_ssl_set_bio(
        (mbedtls_ssl_context *)ssl,
        p_bio,
        (mbedtls_ssl_send_t *)f_send,
        (mbedtls_ssl_recv_t *)f_recv,
        (mbedtls_ssl_recv_timeout_t *)f_recv_timeout
    );
}

/* ============================================================================
 * SSL Handshake and I/O
 * ============================================================================ */

int mojo_tls_ssl_handshake(void *ssl) {
    DEBUG_PRINT("[C DEBUG] mojo_tls_ssl_handshake called, ssl=%p, psa_initialized=%d\n", ssl, psa_initialized);
    int ret = mbedtls_ssl_handshake((mbedtls_ssl_context *)ssl);
    if (ret != 0) {
        char error_buf[200];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C DEBUG] mbedtls_ssl_handshake FAILED: %d (0x%x): %s\n", ret, -ret, error_buf);
    } else {
        DEBUG_PRINT("[C DEBUG] mbedtls_ssl_handshake SUCCESS\n");
    }
    return ret;
}

int mojo_tls_ssl_read(void *ssl, unsigned char *buf, size_t len) {
    int ret = mbedtls_ssl_read((mbedtls_ssl_context *)ssl, buf, len);
    DEBUG_PRINT("[C DEBUG] ssl_read: ret=%d\n", ret);
    return ret;
}

int mojo_tls_ssl_write(void *ssl, const unsigned char *buf, size_t len) {
    DEBUG_PRINT("[C DEBUG] ssl_write: len=%zu\n", len);
    int ret = mbedtls_ssl_write((mbedtls_ssl_context *)ssl, buf, len);
    DEBUG_PRINT("[C DEBUG] ssl_write returned: %d\n", ret);
    return ret;
}

int mojo_tls_ssl_close_notify(void *ssl) {
    return mbedtls_ssl_close_notify((mbedtls_ssl_context *)ssl);
}

/* ============================================================================
 * SSL Configuration Functions
 * ============================================================================ */

void mojo_tls_ssl_config_init(void *conf) {
    DEBUG_PRINT("[C DEBUG] ssl_config_init called with conf: %p\n", conf);
    mbedtls_ssl_config_init((mbedtls_ssl_config *)conf);
    DEBUG_PRINT("[C DEBUG] ssl_config_init done\n");
}

void mojo_tls_ssl_config_free(void *conf) {
    mbedtls_ssl_config_free((mbedtls_ssl_config *)conf);
}

int mojo_tls_ssl_config_defaults(void *conf, int endpoint, int transport, int preset) {
    DEBUG_PRINT("[C DEBUG] ssl_config_defaults called (endpoint=%d, transport=%d, preset=%d)\n",
            endpoint, transport, preset);
    int ret = mbedtls_ssl_config_defaults(
        (mbedtls_ssl_config *)conf,
        endpoint,
        transport,
        preset
    );
    DEBUG_PRINT("[C DEBUG] ssl_config_defaults returned: %d\n", ret);
#ifdef MOJO_TLS_DEBUG
    /* Set debug callback for detailed TLS debugging */
    mbedtls_ssl_conf_dbg((mbedtls_ssl_config *)conf, mojo_tls_debug_callback, NULL);
    mbedtls_debug_set_threshold(4);  /* 0=none, 1=error, 2=state change, 3=info, 4=verbose */
#endif
    /* mbedTLS 4.0: PSA Crypto handles RNG internally via psa_crypto_init() */
    return ret;
}

void mojo_tls_ssl_conf_authmode(void *conf, int authmode) {
    mbedtls_ssl_conf_authmode((mbedtls_ssl_config *)conf, authmode);
}

void mojo_tls_ssl_conf_ca_chain(void *conf, void *ca_chain, void *ca_crl) {
    mbedtls_ssl_conf_ca_chain(
        (mbedtls_ssl_config *)conf,
        (mbedtls_x509_crt *)ca_chain,
        (mbedtls_x509_crl *)ca_crl
    );
}

/* ============================================================================
 * SSL Session Functions
 * ============================================================================ */

void mojo_tls_ssl_session_init(void *session) {
    mbedtls_ssl_session_init((mbedtls_ssl_session *)session);
}

void mojo_tls_ssl_session_free(void *session) {
    mbedtls_ssl_session_free((mbedtls_ssl_session *)session);
}

/* ============================================================================
 * SSL Query Functions
 * ============================================================================ */

const char* mojo_tls_ssl_get_version(const void *ssl) {
    const char* ver = mbedtls_ssl_get_version((const mbedtls_ssl_context *)ssl);
    DEBUG_PRINT("[C DEBUG] ssl_get_version: %s (ptr=%p)\n", ver ? ver : "(null)", (void*)ver);
    return ver;
}

const char* mojo_tls_ssl_get_ciphersuite(const void *ssl) {
    const char* cs = mbedtls_ssl_get_ciphersuite((const mbedtls_ssl_context *)ssl);
    DEBUG_PRINT("[C DEBUG] ssl_get_ciphersuite: %s (ptr=%p)\n", cs ? cs : "(null)", (void*)cs);
    return cs;
}

unsigned int mojo_tls_ssl_get_verify_result(const void *ssl) {
    return mbedtls_ssl_get_verify_result((const mbedtls_ssl_context *)ssl);
}

/* ============================================================================
 * X.509 Certificate Functions
 * ============================================================================ */

void mojo_tls_x509_crt_init(void *crt) {
    DEBUG_PRINT("[C DEBUG] x509_crt_init called with crt: %p (as int64: %lld)\n", crt, (long long)(uintptr_t)crt);
    mbedtls_x509_crt_init((mbedtls_x509_crt *)crt);
    DEBUG_PRINT("[C DEBUG] x509_crt_init done\n");
}

void mojo_tls_x509_crt_free(void *crt) {
    mbedtls_x509_crt_free((mbedtls_x509_crt *)crt);
}

int mojo_tls_x509_crt_parse(void *chain, const unsigned char *buf, size_t buflen) {
    char error_buf[200];
    DEBUG_PRINT("[C DEBUG] x509_crt_parse called\n");
    DEBUG_PRINT("[C DEBUG]   chain: %p\n", chain);
    DEBUG_PRINT("[C DEBUG]   buf: %p\n", (void*)buf);
    DEBUG_PRINT("[C DEBUG]   buflen: %zu\n", buflen);

#ifdef MOJO_TLS_DEBUG
    /* Dump first 64 bytes of chain struct to check if properly initialized */
    unsigned char *chain_bytes = (unsigned char *)chain;
    DEBUG_PRINT("[C DEBUG]   chain bytes: ");
    for (int i = 0; i < 64; i++) {
        fprintf(stderr, "%02x", chain_bytes[i]);
        if (i % 8 == 7) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
#endif

    if (buf && buflen > 0) {
        DEBUG_PRINT("[C DEBUG]   first buf bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    }
    int ret = mbedtls_x509_crt_parse((mbedtls_x509_crt *)chain, buf, buflen);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C DEBUG] x509_crt_parse ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C DEBUG] x509_crt_parse SUCCESS\n");
    }
    return ret;
}

int mojo_tls_x509_crt_parse_file(void *chain, const char *path) {
    char error_buf[200];
    DEBUG_PRINT("[C DEBUG] x509_crt_parse_file called\n");
    DEBUG_PRINT("[C DEBUG]   chain ptr: %p\n", chain);
    DEBUG_PRINT("[C DEBUG]   path ptr: %p\n", (void*)path);
    DEBUG_PRINT("[C DEBUG]   path: '%s'\n", path ? path : "(null)");
    int ret = mbedtls_x509_crt_parse_file((mbedtls_x509_crt *)chain, path);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C DEBUG] x509_crt_parse_file ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C DEBUG] x509_crt_parse_file SUCCESS\n");
    }
    return ret;
}

/* ============================================================================
 * Private Key Functions
 * ============================================================================ */

void mojo_tls_pk_init(void *pk) {
    DEBUG_PRINT("[C DEBUG] pk_init called with pk: %p\n", pk);
    mbedtls_pk_init((mbedtls_pk_context *)pk);
    DEBUG_PRINT("[C DEBUG] pk_init done\n");
}

void mojo_tls_pk_free(void *pk) {
    mbedtls_pk_free((mbedtls_pk_context *)pk);
}

int mojo_tls_pk_parse_key(void *pk, const unsigned char *key, size_t keylen,
                          const unsigned char *pwd, size_t pwdlen) {
    char error_buf[200];
    DEBUG_PRINT("[C DEBUG] pk_parse_key called\n");
    DEBUG_PRINT("[C DEBUG]   pk: %p\n", pk);
    DEBUG_PRINT("[C DEBUG]   keylen: %zu, pwdlen: %zu\n", keylen, pwdlen);

    /* mbedTLS 4.0: RNG parameters removed - PSA Crypto handles RNG internally */
    int ret = mbedtls_pk_parse_key(
        (mbedtls_pk_context *)pk,
        key, keylen,
        pwd, pwdlen
    );

    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C DEBUG] pk_parse_key ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C DEBUG] pk_parse_key SUCCESS\n");
    }
    return ret;
}

int mojo_tls_pk_parse_keyfile(void *pk, const char *path, const char *password) {
    char error_buf[200];
    DEBUG_PRINT("[C DEBUG] pk_parse_keyfile called\n");
    DEBUG_PRINT("[C DEBUG]   pk: %p\n", pk);
    DEBUG_PRINT("[C DEBUG]   path: %s\n", path ? path : "(null)");

    /* mbedTLS 4.0: RNG parameters removed - PSA Crypto handles RNG internally */
    int ret = mbedtls_pk_parse_keyfile(
        (mbedtls_pk_context *)pk,
        path,
        password
    );

    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C DEBUG] pk_parse_keyfile ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C DEBUG] pk_parse_keyfile SUCCESS\n");
    }
    return ret;
}

/* ============================================================================
 * SSL Certificate Configuration (for servers)
 * ============================================================================ */

int mojo_tls_ssl_conf_own_cert(void *conf, void *own_cert, void *pk_ctx) {
    DEBUG_PRINT("[C DEBUG] ssl_conf_own_cert called\n");
    DEBUG_PRINT("[C DEBUG]   conf: %p, own_cert: %p, pk_ctx: %p\n", conf, own_cert, pk_ctx);

    int ret = mbedtls_ssl_conf_own_cert(
        (mbedtls_ssl_config *)conf,
        (mbedtls_x509_crt *)own_cert,
        (mbedtls_pk_context *)pk_ctx
    );

    if (ret != 0) {
        char error_buf[200];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C DEBUG] ssl_conf_own_cert ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C DEBUG] ssl_conf_own_cert SUCCESS\n");
    }
    return ret;
}

/* ============================================================================
 * Network Socket Functions
 * ============================================================================ */

void mojo_tls_net_init(void *ctx) {
    mbedtls_net_init((mbedtls_net_context *)ctx);
}

void mojo_tls_net_free(void *ctx) {
    mbedtls_net_free((mbedtls_net_context *)ctx);
}

int mojo_tls_net_connect(void *ctx, const char *host, const char *port, int proto) {
    DEBUG_PRINT("[C DEBUG] net_connect called: host=%s port=%s proto=%d\n", host, port, proto);
    int ret = mbedtls_net_connect((mbedtls_net_context *)ctx, host, port, proto);
    DEBUG_PRINT("[C DEBUG] net_connect returned: %d\n", ret);
    if (ret == 0) {
        mbedtls_net_context *net = (mbedtls_net_context *)ctx;
        DEBUG_PRINT("[C DEBUG] net_connect fd: %d\n", net->fd);
    }
    return ret;
}

int mojo_tls_net_bind(void *ctx, const char *bind_ip, const char *port, int proto) {
    return mbedtls_net_bind((mbedtls_net_context *)ctx, bind_ip, port, proto);
}

int mojo_tls_net_accept(void *bind_ctx, void *client_ctx,
                        void *client_ip, size_t buf_size, size_t *cip_len) {
    return mbedtls_net_accept(
        (mbedtls_net_context *)bind_ctx,
        (mbedtls_net_context *)client_ctx,
        client_ip,
        buf_size,
        cip_len
    );
}

void* mojo_tls_net_accept_alloc(void *bind_ctx, void *client_ip,
                                 size_t buf_size, size_t *cip_len, int *ret_code) {
    DEBUG_PRINT("[C DEBUG] net_accept_alloc called: bind_ctx=%p\n", bind_ctx);

    /* Allocate new client context */
    mbedtls_net_context *client_ctx = (mbedtls_net_context *)calloc(1, sizeof(mbedtls_net_context));
    if (!client_ctx) {
        DEBUG_PRINT("[C DEBUG] net_accept_alloc: allocation failed\n");
        if (ret_code) *ret_code = -1;
        return NULL;
    }

    mbedtls_net_init(client_ctx);

    int ret = mbedtls_net_accept(
        (mbedtls_net_context *)bind_ctx,
        client_ctx,
        client_ip,
        buf_size,
        cip_len
    );

    if (ret_code) *ret_code = ret;

    if (ret != 0) {
        DEBUG_PRINT("[C DEBUG] net_accept_alloc: accept failed with %d\n", ret);
        mbedtls_net_free(client_ctx);
        free(client_ctx);
        return NULL;
    }

    DEBUG_PRINT("[C DEBUG] net_accept_alloc: success, client_ctx=%p fd=%d\n",
            (void*)client_ctx, client_ctx->fd);
    return client_ctx;
}

void mojo_tls_net_free_context(void *ctx) {
    DEBUG_PRINT("[C DEBUG] net_free_context: ctx=%p\n", ctx);
    if (ctx) {
        mbedtls_net_free((mbedtls_net_context *)ctx);
        free(ctx);
    }
}

int mojo_tls_net_set_block(void *ctx) {
    DEBUG_PRINT("[C DEBUG] net_set_block called: ctx=%p\n", ctx);
    int ret = mbedtls_net_set_block((mbedtls_net_context *)ctx);
    DEBUG_PRINT("[C DEBUG] net_set_block returned: %d\n", ret);
    return ret;
}

int mojo_tls_net_set_nonblock(void *ctx) {
    return mbedtls_net_set_nonblock((mbedtls_net_context *)ctx);
}

/* Get function pointers for BIO callbacks */
void* mojo_tls_get_net_send_ptr(void) {
    return (void *)mbedtls_net_send;
}

void* mojo_tls_get_net_recv_ptr(void) {
    return (void *)mbedtls_net_recv;
}

void* mojo_tls_get_net_recv_timeout_ptr(void) {
    return (void *)mbedtls_net_recv_timeout;
}

/* ============================================================================
 * Debug/Test Functions
 * ============================================================================ */

/* Test CA parsing directly from C */
int mojo_tls_test_ca_parse(const char *path) {
    char error_buf[200];
    mbedtls_x509_crt ca_chain;

    DEBUG_PRINT("[C TEST] Testing CA parse with path: %s\n", path);

    mbedtls_x509_crt_init(&ca_chain);
    DEBUG_PRINT("[C TEST] Initialized chain on stack: %p\n", (void*)&ca_chain);

    int ret = mbedtls_x509_crt_parse_file(&ca_chain, path);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C TEST] parse_file ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C TEST] parse_file SUCCESS\n");
    }

    mbedtls_x509_crt_free(&ca_chain);
    return ret;
}

/* Test CA parsing with heap allocation in C */
int mojo_tls_test_ca_parse_heap(const char *path) {
    char error_buf[200];

    DEBUG_PRINT("[C TEST] Testing CA parse HEAP with path: %s\n", path);

    /* Allocate on heap like Mojo does */
    mbedtls_x509_crt *ca_chain = (mbedtls_x509_crt *)calloc(1, sizeof(mbedtls_x509_crt));
    DEBUG_PRINT("[C TEST] Allocated chain on heap: %p (size=%zu)\n", (void*)ca_chain, sizeof(mbedtls_x509_crt));

    mbedtls_x509_crt_init(ca_chain);
    DEBUG_PRINT("[C TEST] Initialized heap chain\n");

    int ret = mbedtls_x509_crt_parse_file(ca_chain, path);
    if (ret != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        DEBUG_PRINT("[C TEST] parse_file HEAP ERROR: %d (0x%x): %s\n", ret, ret, error_buf);
    } else {
        DEBUG_PRINT("[C TEST] parse_file HEAP SUCCESS\n");
    }

    mbedtls_x509_crt_free(ca_chain);
    free(ca_chain);
    return ret;
}

int mojo_tls_test_connection(const char *host, const char *port) {
    DEBUG_PRINT("[C TEST] Starting test connection to %s:%s\n", host, port);

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int ret;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    DEBUG_PRINT("[C TEST] Connecting...\n");
    ret = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        DEBUG_PRINT("[C TEST] net_connect failed: %d\n", ret);
        goto cleanup;
    }

    /* Set socket to blocking mode */
    mbedtls_net_set_block(&server_fd);

    DEBUG_PRINT("[C TEST] Setting config defaults...\n");
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        DEBUG_PRINT("[C TEST] config_defaults failed: %d\n", ret);
        goto cleanup;
    }

    /* mbedTLS 4.0: PSA Crypto handles RNG internally via psa_crypto_init() */

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    DEBUG_PRINT("[C TEST] SSL setup...\n");
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        DEBUG_PRINT("[C TEST] ssl_setup failed: %d\n", ret);
        goto cleanup;
    }

    mbedtls_ssl_set_hostname(&ssl, host);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    DEBUG_PRINT("[C TEST] Handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char error_buf[200];
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            DEBUG_PRINT("[C TEST] handshake failed: %d (%s)\n", ret, error_buf);
            goto cleanup;
        }
    }

    DEBUG_PRINT("[C TEST] SUCCESS! Protocol: %s, Cipher: %s\n",
            mbedtls_ssl_get_version(&ssl),
            mbedtls_ssl_get_ciphersuite(&ssl));
    ret = 0;

cleanup:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_net_free(&server_fd);
    return ret;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

void* mojo_tls_get_null_ptr(void) {
    return NULL;
}

/* ============================================================================
 * Memory Management (for consistent alloc/free across FFI boundary)
 * ============================================================================ */

void* mojo_tls_alloc(size_t size) {
    void* ptr = calloc(1, size);
    DEBUG_PRINT("[C DEBUG] mojo_tls_alloc(%zu) = %p (as int64: %lld)\n", size, ptr, (long long)(uintptr_t)ptr);
    return ptr;
}

void mojo_tls_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

/* ============================================================================
 * String Helpers
 * ============================================================================ */

size_t mojo_tls_strlen(const char* str) {
    if (!str) return 0;
    size_t len = strlen(str);
    DEBUG_PRINT("[C DEBUG] strlen: str=%p len=%zu\n", (void*)str, len);
    return len;
}

/* Copy a C string to a buffer. Returns number of bytes copied (excluding null terminator). */
size_t mojo_tls_strcpy(char* dest, size_t dest_size, const char* src) {
    if (!src || !dest || dest_size == 0) return 0;
    size_t len = strlen(src);
    if (len >= dest_size) {
        len = dest_size - 1;
    }
    memcpy(dest, src, len);
    dest[len] = '\0';
    return len;
}
