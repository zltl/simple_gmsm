#ifndef GMSM_TLCP_H_
#define GMSM_TLCP_H_

/// @file simple_gmsm/tlcp.h
/// @brief TLCP protocol implementation (GB/T 38636-2020)

#include "common.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "hmac_sm3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol version */
#define TLCP_VERSION_MAJOR 0x01
#define TLCP_VERSION_MINOR 0x01
#define TLCP_VERSION ((TLCP_VERSION_MAJOR << 8) | TLCP_VERSION_MINOR)

/* Content types */
#define TLCP_CONTENT_CHANGE_CIPHER_SPEC 20
#define TLCP_CONTENT_ALERT              21
#define TLCP_CONTENT_HANDSHAKE          22
#define TLCP_CONTENT_APPLICATION_DATA   23

/* Handshake types */
#define TLCP_HS_CLIENT_HELLO          1
#define TLCP_HS_SERVER_HELLO          2
#define TLCP_HS_CERTIFICATE           11
#define TLCP_HS_SERVER_KEY_EXCHANGE   12
#define TLCP_HS_CERTIFICATE_REQUEST   13
#define TLCP_HS_SERVER_HELLO_DONE     14
#define TLCP_HS_CERTIFICATE_VERIFY    15
#define TLCP_HS_CLIENT_KEY_EXCHANGE   16
#define TLCP_HS_FINISHED              20

/* Cipher suites */
#define TLCP_ECC_SM4_CBC_SM3    0xE013
#define TLCP_ECC_SM4_GCM_SM3   0xE053
#define TLCP_ECDHE_SM4_CBC_SM3 0xE011
#define TLCP_ECDHE_SM4_GCM_SM3 0xE051

/* Alert levels */
#define TLCP_ALERT_WARNING  1
#define TLCP_ALERT_FATAL    2

/* Alert descriptions */
#define TLCP_ALERT_CLOSE_NOTIFY             0
#define TLCP_ALERT_UNEXPECTED_MESSAGE        10
#define TLCP_ALERT_BAD_RECORD_MAC           20
#define TLCP_ALERT_DECRYPTION_FAILED        21
#define TLCP_ALERT_RECORD_OVERFLOW          22
#define TLCP_ALERT_HANDSHAKE_FAILURE        40
#define TLCP_ALERT_BAD_CERTIFICATE          42
#define TLCP_ALERT_UNSUPPORTED_CERTIFICATE  43
#define TLCP_ALERT_CERTIFICATE_REVOKED      44
#define TLCP_ALERT_CERTIFICATE_EXPIRED      45
#define TLCP_ALERT_CERTIFICATE_UNKNOWN      46
#define TLCP_ALERT_ILLEGAL_PARAMETER        47
#define TLCP_ALERT_UNKNOWN_CA               48
#define TLCP_ALERT_ACCESS_DENIED            49
#define TLCP_ALERT_DECODE_ERROR             50
#define TLCP_ALERT_DECRYPT_ERROR            51
#define TLCP_ALERT_PROTOCOL_VERSION         70
#define TLCP_ALERT_INSUFFICIENT_SECURITY    71
#define TLCP_ALERT_INTERNAL_ERROR           80
#define TLCP_ALERT_USER_CANCELED            90
#define TLCP_ALERT_UNSUPPORTED_SITE2SITE    200

/* Max sizes */
#define TLCP_MAX_RECORD_LEN      16384
#define TLCP_MAX_FRAGMENT_LEN    16384
#define TLCP_RANDOM_LEN          32
#define TLCP_SESSION_ID_MAX_LEN  32
#define TLCP_MASTER_SECRET_LEN   48
#define TLCP_VERIFY_DATA_LEN     12
#define TLCP_MAX_CERT_SIZE       4096
#define TLCP_MAX_HANDSHAKE_SIZE  8192

/* Connection states */
#define TLCP_STATE_INIT              0
#define TLCP_STATE_CLIENT_HELLO      1
#define TLCP_STATE_SERVER_HELLO      2
#define TLCP_STATE_SERVER_CERT       3
#define TLCP_STATE_SERVER_KEY_EX     4
#define TLCP_STATE_CERT_REQUEST      5
#define TLCP_STATE_SERVER_DONE       6
#define TLCP_STATE_CLIENT_CERT       7
#define TLCP_STATE_CLIENT_KEY_EX     8
#define TLCP_STATE_CERT_VERIFY       9
#define TLCP_STATE_CHANGE_CIPHER     10
#define TLCP_STATE_FINISHED          11
#define TLCP_STATE_ESTABLISHED       12
#define TLCP_STATE_ERROR             255

/* Record header size */
#define TLCP_RECORD_HEADER_SIZE  5

/* I/O callback types */
typedef int (*tlcp_read_fn)(void* ctx, unsigned char* buf, unsigned long len);
typedef int (*tlcp_write_fn)(void* ctx, const unsigned char* buf, unsigned long len);

/// TLS record header (5 bytes)
typedef struct {
    unsigned char content_type;
    unsigned char version[2];
    unsigned char length[2];
} tlcp_record_header_t;

/// Certificate (simplified - just raw DER + SM2 public key extracted)
typedef struct {
    unsigned char der[TLCP_MAX_CERT_SIZE];
    unsigned long der_len;
    big_t pubkey_x;
    big_t pubkey_y;
    int has_pubkey;
} tlcp_cert_t;

/// Security parameters derived from handshake
typedef struct {
    unsigned char master_secret[TLCP_MASTER_SECRET_LEN];
    unsigned char client_random[TLCP_RANDOM_LEN];
    unsigned char server_random[TLCP_RANDOM_LEN];
    unsigned char client_write_key[16];
    unsigned char server_write_key[16];
    unsigned char client_write_iv[16];
    unsigned char server_write_iv[16];
    unsigned char client_write_mac_key[32];
    unsigned char server_write_mac_key[32];
    unsigned short cipher_suite;
    int is_gcm;
} tlcp_security_params_t;

/// Handshake hash context (for Finished message)
typedef struct {
    sm3_context_t hash;
    int active;
} tlcp_handshake_hash_t;

/// TLCP context (configuration)
typedef struct {
    /* Our certificates (signing + encryption) */
    tlcp_cert_t sign_cert;
    tlcp_cert_t enc_cert;
    /* Our private keys */
    big_t sign_private_key;
    big_t enc_private_key;
    int has_sign_cert;
    int has_enc_cert;
    /* Trusted CA certificates */
    tlcp_cert_t ca_certs[8];
    int ca_cert_count;
    /* Supported cipher suites (in preference order) */
    unsigned short cipher_suites[4];
    int cipher_suite_count;
    /* Is server? */
    int is_server;
    /* Request client cert? */
    int verify_client;
} tlcp_context_t;

/// TLCP connection state
typedef struct {
    tlcp_context_t* ctx;
    /* I/O */
    tlcp_read_fn read_fn;
    tlcp_write_fn write_fn;
    void* io_ctx;
    /* State */
    int state;
    int is_server;
    /* Security params */
    tlcp_security_params_t params;
    /* Peer certificates */
    tlcp_cert_t peer_sign_cert;
    tlcp_cert_t peer_enc_cert;
    int peer_cert_count;
    /* Sequence numbers */
    unsigned long long client_seq;
    unsigned long long server_seq;
    /* Handshake hash */
    tlcp_handshake_hash_t hs_hash;
    /* Cipher active flags */
    int client_cipher_active;
    int server_cipher_active;
    /* Read/write buffers */
    unsigned char read_buf[TLCP_MAX_RECORD_LEN + 256];
    unsigned long read_buf_len;
    /* Session ID */
    unsigned char session_id[TLCP_SESSION_ID_MAX_LEN];
    unsigned long session_id_len;
    /* Error info */
    int last_error;
    unsigned char last_alert_level;
    unsigned char last_alert_desc;
} tlcp_conn_t;

/* ---- Context management ---- */

/// @brief Initialize TLCP context
void tlcp_ctx_init(tlcp_context_t* ctx);

/// @brief Set as server or client
void tlcp_ctx_set_server(tlcp_context_t* ctx, int is_server);

/// @brief Load signing certificate (DER format)
int tlcp_ctx_set_sign_cert(tlcp_context_t* ctx, const unsigned char* der,
                           unsigned long len);

/// @brief Load encryption certificate (DER format)
int tlcp_ctx_set_enc_cert(tlcp_context_t* ctx, const unsigned char* der,
                          unsigned long len);

/// @brief Set signing private key
void tlcp_ctx_set_sign_key(tlcp_context_t* ctx, const big_t* key);

/// @brief Set encryption private key
void tlcp_ctx_set_enc_key(tlcp_context_t* ctx, const big_t* key);

/// @brief Add trusted CA certificate
int tlcp_ctx_add_ca_cert(tlcp_context_t* ctx, const unsigned char* der,
                         unsigned long len);

/// @brief Set cipher suite preference
void tlcp_ctx_set_cipher_suites(tlcp_context_t* ctx,
                                const unsigned short* suites, int count);

/* ---- Connection management ---- */

/// @brief Create a new connection from context
void tlcp_conn_init(tlcp_conn_t* conn, tlcp_context_t* ctx);

/// @brief Set I/O callbacks
void tlcp_conn_set_io(tlcp_conn_t* conn, tlcp_read_fn rfn, tlcp_write_fn wfn,
                      void* io_ctx);

/// @brief Perform TLS handshake (client side)
int tlcp_connect(tlcp_conn_t* conn);

/// @brief Perform TLS handshake (server side)
int tlcp_accept(tlcp_conn_t* conn);

/// @brief Send application data
int tlcp_write(tlcp_conn_t* conn, const unsigned char* data, unsigned long len);

/// @brief Receive application data
int tlcp_read(tlcp_conn_t* conn, unsigned char* buf, unsigned long buflen);

/// @brief Send close_notify and shutdown
int tlcp_shutdown(tlcp_conn_t* conn);

/* ---- Record layer ---- */

/// @brief Write a TLS record
int tlcp_record_write(tlcp_conn_t* conn, unsigned char content_type,
                      const unsigned char* data, unsigned long len);

/// @brief Read a TLS record
int tlcp_record_read(tlcp_conn_t* conn, unsigned char* content_type,
                     unsigned char* data, unsigned long* len);

/* ---- PRF ---- */

/// @brief TLCP PRF based on HMAC-SM3
void tlcp_prf(const unsigned char* secret, unsigned long secret_len,
              const char* label,
              const unsigned char* seed, unsigned long seed_len,
              unsigned char* out, unsigned long out_len);

/// @brief Derive master secret from pre-master secret
void tlcp_derive_master_secret(unsigned char master_secret[48],
                               const unsigned char* pre_master_secret,
                               unsigned long pms_len,
                               const unsigned char client_random[32],
                               const unsigned char server_random[32]);

/// @brief Derive key block from master secret
void tlcp_derive_keys(tlcp_security_params_t* params);

/* ---- Alert ---- */

/// @brief Send alert
int tlcp_send_alert(tlcp_conn_t* conn, unsigned char level,
                    unsigned char desc);

/* ---- Certificate ---- */

/// @brief Parse DER certificate and extract SM2 public key
int tlcp_cert_parse(tlcp_cert_t* cert, const unsigned char* der,
                    unsigned long len);

#ifdef __cplusplus
}
#endif

#endif /* GMSM_TLCP_H_ */
