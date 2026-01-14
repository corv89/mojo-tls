/*
 * mojo_tls_shim.h - C shim for Mojo mbedTLS bindings
 *
 * Provides wrappers for mbedTLS functions to work with Mojo's FFI.
 * This is necessary because Mojo's external_call needs symbols that are
 * available at runtime, and mbedTLS functions need to be wrapped to
 * provide a stable ABI.
 */

#ifndef MOJO_TLS_SHIM_H
#define MOJO_TLS_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Library Initialization (MUST be called before any other function!)
 * ============================================================================ */
int mojo_tls_init(void);

/* ============================================================================
 * Struct size queries - needed because mbedTLS struct sizes vary by build config
 * ============================================================================ */
size_t mojo_tls_sizeof_ssl_context(void);
size_t mojo_tls_sizeof_ssl_config(void);
size_t mojo_tls_sizeof_ssl_session(void);
size_t mojo_tls_sizeof_entropy_context(void);
size_t mojo_tls_sizeof_ctr_drbg_context(void);
size_t mojo_tls_sizeof_x509_crt(void);
size_t mojo_tls_sizeof_pk_context(void);
size_t mojo_tls_sizeof_net_context(void);

/* ============================================================================
 * TLS version configuration - wraps static inline functions
 * ============================================================================ */
void mojo_tls_conf_min_version(void *conf, int version);
void mojo_tls_conf_max_version(void *conf, int version);

/* ============================================================================
 * SSL Context Functions
 * ============================================================================ */
void mojo_tls_ssl_init(void *ssl);
void mojo_tls_ssl_free(void *ssl);
int mojo_tls_ssl_setup(void *ssl, const void *conf);
int mojo_tls_ssl_set_hostname(void *ssl, const char *hostname);
void mojo_tls_ssl_set_bio(void *ssl, void *p_bio,
                          void *f_send, void *f_recv, void *f_recv_timeout);

/* ============================================================================
 * SSL Handshake and I/O
 * ============================================================================ */
int mojo_tls_ssl_handshake(void *ssl);
int mojo_tls_ssl_read(void *ssl, unsigned char *buf, size_t len);
int mojo_tls_ssl_write(void *ssl, const unsigned char *buf, size_t len);
int mojo_tls_ssl_close_notify(void *ssl);

/* ============================================================================
 * SSL Configuration Functions
 * ============================================================================ */
void mojo_tls_ssl_config_init(void *conf);
void mojo_tls_ssl_config_free(void *conf);
int mojo_tls_ssl_config_defaults(void *conf, int endpoint, int transport, int preset);
void mojo_tls_ssl_conf_authmode(void *conf, int authmode);
void mojo_tls_ssl_conf_ca_chain(void *conf, void *ca_chain, void *ca_crl);

/* ============================================================================
 * SSL Query Functions
 * ============================================================================ */
const char* mojo_tls_ssl_get_version(const void *ssl);
const char* mojo_tls_ssl_get_ciphersuite(const void *ssl);
unsigned int mojo_tls_ssl_get_verify_result(const void *ssl);

/* ============================================================================
 * Peer Certificate Access
 * ============================================================================ */
const void* mojo_tls_ssl_get_peer_cert(const void *ssl);
const unsigned char* mojo_tls_x509_crt_get_raw_data(const void *crt);
size_t mojo_tls_x509_crt_get_raw_len(const void *crt);
int mojo_tls_sha256(const unsigned char *input, size_t input_len,
                    unsigned char *output);

/* ============================================================================
 * X.509 Certificate Functions
 * ============================================================================ */
void mojo_tls_x509_crt_init(void *crt);
void mojo_tls_x509_crt_free(void *crt);
int mojo_tls_x509_crt_parse(void *chain, const unsigned char *buf, size_t buflen);
int mojo_tls_x509_crt_parse_file(void *chain, const char *path);

/* ============================================================================
 * Private Key Functions
 * ============================================================================ */
void mojo_tls_pk_init(void *pk);
void mojo_tls_pk_free(void *pk);
int mojo_tls_pk_parse_key(void *pk, const unsigned char *key, size_t keylen,
                          const unsigned char *pwd, size_t pwdlen);
int mojo_tls_pk_parse_keyfile(void *pk, const char *path, const char *password);

/* ============================================================================
 * SSL Certificate Configuration (for servers)
 * ============================================================================ */
int mojo_tls_ssl_conf_own_cert(void *conf, void *own_cert, void *pk_ctx);

/* ============================================================================
 * Network Socket Functions
 * ============================================================================ */
void mojo_tls_net_init(void *ctx);
void mojo_tls_net_free(void *ctx);
int mojo_tls_net_connect(void *ctx, const char *host, const char *port, int proto);
int mojo_tls_net_bind(void *ctx, const char *bind_ip, const char *port, int proto);
int mojo_tls_net_bind_reuseport(void *ctx, const char *bind_ip, const char *port, int proto);
int mojo_tls_net_accept(void *bind_ctx, void *client_ctx,
                        void *client_ip, size_t buf_size, size_t *cip_len);

/* Server accept with allocation - returns newly allocated client context */
void* mojo_tls_net_accept_alloc(void *bind_ctx, void *client_ip,
                                 size_t buf_size, size_t *cip_len, int *ret_code);
void mojo_tls_net_free_context(void *ctx);

int mojo_tls_net_set_block(void *ctx);
int mojo_tls_net_set_nonblock(void *ctx);

/* Get function pointers for BIO callbacks */
void* mojo_tls_get_net_send_ptr(void);
void* mojo_tls_get_net_recv_ptr(void);
void* mojo_tls_get_net_recv_timeout_ptr(void);

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Protocol version enum values */
#define MOJO_TLS_VERSION_UNKNOWN 0
#define MOJO_TLS_VERSION_TLS1_2  0x0303
#define MOJO_TLS_VERSION_TLS1_3  0x0304

/* Endpoint types */
#define MOJO_TLS_IS_CLIENT 0
#define MOJO_TLS_IS_SERVER 1

/* Transport types */
#define MOJO_TLS_TRANSPORT_STREAM   0
#define MOJO_TLS_TRANSPORT_DATAGRAM 1

/* Presets */
#define MOJO_TLS_PRESET_DEFAULT 0
#define MOJO_TLS_PRESET_SUITEB  2

/* Verify modes */
#define MOJO_TLS_VERIFY_NONE     0
#define MOJO_TLS_VERIFY_OPTIONAL 1
#define MOJO_TLS_VERIFY_REQUIRED 2

/* Network protocol */
#define MOJO_TLS_NET_PROTO_TCP 0
#define MOJO_TLS_NET_PROTO_UDP 1

#ifdef __cplusplus
}
#endif

#endif /* MOJO_TLS_SHIM_H */
