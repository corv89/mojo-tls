/**
 * Test server using heap allocation like Mojo does.
 * This tests if heap vs stack allocation matters.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include "../shim/mojo_tls_shim.h"

#define CHECK(ret, msg) do { \
    if (ret != 0) { \
        char buf[256]; \
        mbedtls_strerror(ret, buf, sizeof(buf)); \
        fprintf(stderr, "Error %s: %d (0x%x): %s\n", msg, ret, -ret, buf); \
        exit(1); \
    } \
    printf("  %s: %d\n", msg, ret); \
} while(0)

// Forward declarations for functions not in header
extern void* mojo_tls_alloc(size_t size);
extern void mojo_tls_free(void* ptr);

int main(void) {
    int ret;

    printf("Initializing PSA Crypto...\n");
    ret = mojo_tls_init();
    CHECK(ret, "mojo_tls_init");

    // Allocate on heap like Mojo does
    printf("Allocating structures on heap...\n");
    void* conf = mojo_tls_alloc(mojo_tls_sizeof_ssl_config());
    void* srvcert = mojo_tls_alloc(mojo_tls_sizeof_x509_crt());
    void* pkey = mojo_tls_alloc(mojo_tls_sizeof_pk_context());
    void* listen_ctx = mojo_tls_alloc(mojo_tls_sizeof_net_context());

    printf("  conf: %p\n", conf);
    printf("  srvcert: %p\n", srvcert);
    printf("  pkey: %p\n", pkey);
    printf("  listen_ctx: %p\n", listen_ctx);

    // Initialize structures
    printf("Initializing structures...\n");
    mojo_tls_ssl_config_init(conf);
    mojo_tls_x509_crt_init(srvcert);
    mojo_tls_pk_init(pkey);
    mojo_tls_net_init(listen_ctx);

    printf("Setting config defaults...\n");
    ret = mojo_tls_ssl_config_defaults(conf, 1, 0, 0);  // SERVER, STREAM, DEFAULT
    CHECK(ret, "ssl_config_defaults");

    printf("Loading certificate...\n");
    ret = mojo_tls_x509_crt_parse_file(srvcert, "tests/server.crt");
    CHECK(ret, "x509_crt_parse_file");

    printf("Loading private key...\n");
    ret = mojo_tls_pk_parse_keyfile(pkey, "tests/server.key", "");
    CHECK(ret, "pk_parse_keyfile");

    printf("Setting own cert on config...\n");
    ret = mojo_tls_ssl_conf_own_cert(conf, srvcert, pkey);
    CHECK(ret, "ssl_conf_own_cert");

    printf("Binding to port 8443...\n");
    ret = mojo_tls_net_bind(listen_ctx, "127.0.0.1", "8443", 0);  // TCP
    CHECK(ret, "net_bind");

    printf("Waiting for connection...\n");
    int accept_ret = 0;
    void* client_ctx = mojo_tls_net_accept_alloc(listen_ctx, NULL, 0, NULL, &accept_ret);
    printf("  net_accept: %d, client_ctx: %p\n", accept_ret, client_ctx);
    if (accept_ret != 0 || client_ctx == NULL) {
        fprintf(stderr, "Accept failed\n");
        exit(1);
    }

    // Set blocking mode
    ret = mojo_tls_net_set_block(client_ctx);
    CHECK(ret, "net_set_block");

    // Allocate SSL context on heap
    void* ssl = mojo_tls_alloc(mojo_tls_sizeof_ssl_context());
    printf("  ssl: %p\n", ssl);

    printf("Setting up SSL context...\n");
    mojo_tls_ssl_init(ssl);
    ret = mojo_tls_ssl_setup(ssl, conf);
    CHECK(ret, "ssl_setup");

    printf("Setting BIO...\n");
    mojo_tls_ssl_set_bio(ssl, client_ctx,
                         mojo_tls_get_net_send_ptr(),
                         mojo_tls_get_net_recv_ptr(),
                         NULL);

    printf("Performing handshake...\n");
    ret = mojo_tls_ssl_handshake(ssl);
    CHECK(ret, "ssl_handshake");

    printf("\nSUCCESS!\n");
    printf("  Version: %s\n", mojo_tls_ssl_get_version(ssl));
    printf("  Ciphersuite: %s\n", mojo_tls_ssl_get_ciphersuite(ssl));

    // Cleanup
    mojo_tls_ssl_close_notify(ssl);
    mojo_tls_ssl_free(ssl);
    mojo_tls_free(ssl);
    mojo_tls_net_free_context(client_ctx);
    mojo_tls_net_free(listen_ctx);
    mojo_tls_free(listen_ctx);
    mojo_tls_pk_free(pkey);
    mojo_tls_free(pkey);
    mojo_tls_x509_crt_free(srvcert);
    mojo_tls_free(srvcert);
    mojo_tls_ssl_config_free(conf);
    mojo_tls_free(conf);

    return 0;
}
