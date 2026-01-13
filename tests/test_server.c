/* Minimal TLS server test to debug PSA error */
#include <stdio.h>
#include <string.h>
#include "../shim/mojo_tls_shim.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <psa/crypto.h>

int main(void) {
    int ret;

    /* Initialize PSA */
    printf("Initializing PSA Crypto...\n");
    ret = mojo_tls_init();
    printf("  mojo_tls_init: %d\n", ret);
    if (ret != 0) return 1;

    /* Allocate structures */
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;

    /* Initialize */
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);

    /* Set server config defaults */
    printf("Setting config defaults...\n");
    ret = mbedtls_ssl_config_defaults(&conf,
                                       MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    printf("  ssl_config_defaults: %d\n", ret);
    if (ret != 0) return 1;

    /* Load certificate */
    printf("Loading certificate...\n");
    ret = mbedtls_x509_crt_parse_file(&srvcert, "tests/server-rsa.crt");
    printf("  x509_crt_parse_file: %d\n", ret);
    if (ret != 0) return 1;

    /* Load private key */
    printf("Loading private key...\n");
    ret = mbedtls_pk_parse_keyfile(&pkey, "tests/server-rsa.key", NULL);
    printf("  pk_parse_keyfile: %d\n", ret);
    if (ret != 0) return 1;

    /* Set own cert on config */
    printf("Setting own cert on config...\n");
    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    printf("  ssl_conf_own_cert: %d\n", ret);
    if (ret != 0) return 1;

    /* Bind socket */
    printf("Binding to port 8443...\n");
    ret = mbedtls_net_bind(&listen_fd, "127.0.0.1", "8443", MBEDTLS_NET_PROTO_TCP);
    printf("  net_bind: %d\n", ret);
    if (ret != 0) return 1;

    printf("Waiting for connection...\n");
    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    printf("  net_accept: %d\n", ret);
    if (ret != 0) return 1;

    /* Set up SSL context */
    printf("Setting up SSL context...\n");
    ret = mbedtls_ssl_setup(&ssl, &conf);
    printf("  ssl_setup: %d\n", ret);
    if (ret != 0) return 1;

    /* Set BIO */
    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Handshake */
    printf("Performing handshake...\n");
    ret = mbedtls_ssl_handshake(&ssl);
    printf("  ssl_handshake: %d\n", ret);

    if (ret == 0) {
        printf("SUCCESS!\n");
        printf("  Version: %s\n", mbedtls_ssl_get_version(&ssl));
        printf("  Ciphersuite: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));
    } else {
        char errbuf[200];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        printf("FAILED: %s\n", errbuf);
    }

    /* Cleanup */
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);

    return (ret != 0);
}
