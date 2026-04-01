#include "simple_gmsm/tlcp.h"

#include <string.h>
#include <time.h>

/* ================================================================== */
/*  Small helpers                                                     */
/* ================================================================== */

static void put_u16(unsigned char out[2], unsigned int val) {
    out[0] = (unsigned char)(val >> 8);
    out[1] = (unsigned char)(val);
}

static unsigned int get_u16(const unsigned char in[2]) {
    return ((unsigned int)in[0] << 8) | (unsigned int)in[1];
}

static void put_u24(unsigned char out[3], unsigned long val) {
    out[0] = (unsigned char)(val >> 16);
    out[1] = (unsigned char)(val >> 8);
    out[2] = (unsigned char)(val);
}

static unsigned long get_u24(const unsigned char in[3]) {
    return ((unsigned long)in[0] << 16) |
           ((unsigned long)in[1] << 8) |
            (unsigned long)in[2];
}

/* Simple pseudo-random: fill buf with random-ish bytes.
 * Not cryptographically strong – adequate for this minimal impl. */
static void generate_random(unsigned char *buf, unsigned long len) {
    static unsigned int counter = 0;
    unsigned int seed = (unsigned int)time(NULL) ^ (++counter * 2654435761u);
    for (unsigned long i = 0; i < len; i++) {
        seed = seed * 1103515245u + 12345u;
        buf[i] = (unsigned char)(seed >> 16);
    }
}

/* ================================================================== */
/*  Handshake hash bookkeeping                                        */
/* ================================================================== */

static void hs_hash_init(tlcp_conn_t *conn) {
    sm3_init(&conn->hs_hash.hash);
    conn->hs_hash.active = 1;
}

static void hs_hash_update(tlcp_conn_t *conn, const unsigned char *data,
                           unsigned long len) {
    if (conn->hs_hash.active)
        sm3_update(&conn->hs_hash.hash, data, len);
}

/* Snapshot the current hash (non-destructive) and return 32-byte digest. */
static void hs_hash_snapshot(tlcp_conn_t *conn, unsigned char digest[32]) {
    sm3_context_t tmp = conn->hs_hash.hash;   /* copy */
    sm3_finish(&tmp, digest);
}

/* ================================================================== */
/*  Handshake message framing                                         */
/* ================================================================== */

/* Build a handshake header: type(1) + length(3), return 4 */
static void hs_header(unsigned char *out, unsigned char type,
                      unsigned long body_len) {
    out[0] = type;
    put_u24(out + 1, body_len);
}

/*
 * Send one handshake message.
 *   – builds header
 *   – feeds (header + body) to the running handshake hash
 *   – sends via record layer as TLCP_CONTENT_HANDSHAKE
 */
static int hs_send(tlcp_conn_t *conn, unsigned char type,
                   const unsigned char *body, unsigned long body_len) {
    unsigned char hdr[4];
    hs_header(hdr, type, body_len);

    /* Update handshake hash with this message */
    hs_hash_update(conn, hdr, 4);
    if (body_len)
        hs_hash_update(conn, body, body_len);

    /* Assemble into a single buffer for one record */
    unsigned char msg[TLCP_MAX_HANDSHAKE_SIZE];
    if (4 + body_len > sizeof(msg))
        return -1;
    memcpy(msg, hdr, 4);
    if (body_len)
        memcpy(msg + 4, body, body_len);

    return tlcp_record_write(conn, TLCP_CONTENT_HANDSHAKE, msg, 4 + body_len);
}

/*
 * Receive a record and expect it to be a handshake message of given type.
 * On return, *body points into conn->read_buf (after the 4-byte HS header)
 * and *body_len is set.
 *
 * The full message (header + body) is also fed into the handshake hash.
 */
static int hs_recv(tlcp_conn_t *conn, unsigned char expected_type,
                   const unsigned char **body, unsigned long *body_len) {
    unsigned char ct;
    unsigned long rlen = 0;

    if (tlcp_record_read(conn, &ct, conn->read_buf, &rlen) != 0)
        return -1;

    if (ct != TLCP_CONTENT_HANDSHAKE)
        return -1;
    if (rlen < 4)
        return -1;

    unsigned char msg_type = conn->read_buf[0];
    unsigned long msg_len = get_u24(conn->read_buf + 1);

    if (msg_type != expected_type)
        return -1;
    if (4 + msg_len > rlen)
        return -1;

    /* Feed into handshake hash */
    hs_hash_update(conn, conn->read_buf, 4 + msg_len);

    *body = conn->read_buf + 4;
    *body_len = msg_len;
    return 0;
}

/*
 * Receive a record that may be one of several handshake types.
 * Returns the actual handshake type, or -1 on error.
 */
static int hs_recv_any(tlcp_conn_t *conn, const unsigned char **body,
                       unsigned long *body_len) {
    unsigned char ct;
    unsigned long rlen = 0;

    if (tlcp_record_read(conn, &ct, conn->read_buf, &rlen) != 0)
        return -1;

    if (ct != TLCP_CONTENT_HANDSHAKE)
        return -1;
    if (rlen < 4)
        return -1;

    unsigned char msg_type = conn->read_buf[0];
    unsigned long msg_len = get_u24(conn->read_buf + 1);
    if (4 + msg_len > rlen)
        return -1;

    hs_hash_update(conn, conn->read_buf, 4 + msg_len);

    *body = conn->read_buf + 4;
    *body_len = msg_len;
    return (int)msg_type;
}

/* ================================================================== */
/*  Finished verify_data computation                                  */
/* ================================================================== */

static void compute_verify_data(tlcp_conn_t *conn, int is_client,
                                unsigned char out[TLCP_VERIFY_DATA_LEN]) {
    unsigned char hs_digest[32];
    hs_hash_snapshot(conn, hs_digest);

    const char *label = is_client ? "client finished" : "server finished";

    tlcp_prf(conn->params.master_secret, TLCP_MASTER_SECRET_LEN,
             label, hs_digest, 32,
             out, TLCP_VERIFY_DATA_LEN);
}

/* ================================================================== */
/*  ChangeCipherSpec                                                  */
/* ================================================================== */

static int send_ccs(tlcp_conn_t *conn) {
    unsigned char ccs = 1;
    return tlcp_record_write(conn, TLCP_CONTENT_CHANGE_CIPHER_SPEC, &ccs, 1);
}

static int recv_ccs(tlcp_conn_t *conn) {
    unsigned char ct;
    unsigned long rlen = 0;
    if (tlcp_record_read(conn, &ct, conn->read_buf, &rlen) != 0)
        return -1;
    if (ct != TLCP_CONTENT_CHANGE_CIPHER_SPEC || rlen != 1 ||
        conn->read_buf[0] != 1)
        return -1;
    return 0;
}

/* ================================================================== */
/*  Cipher suite helpers                                              */
/* ================================================================== */

static int is_ecdhe_suite(unsigned short cs) {
    return cs == TLCP_ECDHE_SM4_CBC_SM3 || cs == TLCP_ECDHE_SM4_GCM_SM3;
}

static int is_ecc_suite(unsigned short cs) {
    return cs == TLCP_ECC_SM4_CBC_SM3 || cs == TLCP_ECC_SM4_GCM_SM3;
}

static int select_cipher_suite(const unsigned short *client_suites,
                               int client_count,
                               const unsigned short *server_suites,
                               int server_count,
                               unsigned short *out) {
    /* Server-preference order */
    for (int s = 0; s < server_count; s++) {
        for (int c = 0; c < client_count; c++) {
            if (server_suites[s] == client_suites[c]) {
                *out = server_suites[s];
                return 1;
            }
        }
    }
    return 0;
}

/* ================================================================== */
/*  ClientHello                                                       */
/* ================================================================== */

static int build_client_hello(tlcp_conn_t *conn, unsigned char *buf,
                              unsigned long *len) {
    unsigned long pos = 0;

    /* ProtocolVersion */
    buf[pos++] = TLCP_VERSION_MAJOR;
    buf[pos++] = TLCP_VERSION_MINOR;

    /* Random (32 bytes) */
    generate_random(conn->params.client_random, TLCP_RANDOM_LEN);
    memcpy(buf + pos, conn->params.client_random, TLCP_RANDOM_LEN);
    pos += TLCP_RANDOM_LEN;

    /* SessionID: empty */
    buf[pos++] = 0;

    /* CipherSuites */
    int count = conn->ctx->cipher_suite_count;
    put_u16(buf + pos, (unsigned int)(count * 2));
    pos += 2;
    for (int i = 0; i < count; i++) {
        put_u16(buf + pos, conn->ctx->cipher_suites[i]);
        pos += 2;
    }

    /* CompressionMethods: null only */
    buf[pos++] = 1;
    buf[pos++] = 0;

    *len = pos;
    return 0;
}

static int parse_client_hello(tlcp_conn_t *conn, const unsigned char *body,
                              unsigned long body_len,
                              unsigned short *client_suites,
                              int *client_suite_count) {
    unsigned long pos = 0;

    /* Version */
    if (body_len < 2)
        return -1;
    if (body[pos] != TLCP_VERSION_MAJOR || body[pos + 1] != TLCP_VERSION_MINOR)
        return -1;
    pos += 2;

    /* Client random */
    if (pos + TLCP_RANDOM_LEN > body_len)
        return -1;
    memcpy(conn->params.client_random, body + pos, TLCP_RANDOM_LEN);
    pos += TLCP_RANDOM_LEN;

    /* SessionID */
    if (pos + 1 > body_len)
        return -1;
    unsigned long sid_len = body[pos++];
    if (pos + sid_len > body_len)
        return -1;
    if (sid_len > 0 && sid_len <= TLCP_SESSION_ID_MAX_LEN) {
        memcpy(conn->session_id, body + pos, sid_len);
        conn->session_id_len = sid_len;
    }
    pos += sid_len;

    /* CipherSuites */
    if (pos + 2 > body_len)
        return -1;
    unsigned int cs_len = get_u16(body + pos);
    pos += 2;
    if (pos + cs_len > body_len || (cs_len & 1))
        return -1;
    int n = (int)(cs_len / 2);
    if (n > 4)
        n = 4;
    for (int i = 0; i < n; i++)
        client_suites[i] = (unsigned short)get_u16(body + pos + (unsigned long)i * 2);
    *client_suite_count = n;
    pos += cs_len;

    /* CompressionMethods (skip) */
    if (pos + 1 > body_len)
        return -1;
    unsigned long cm_len = body[pos++];
    pos += cm_len;

    (void)pos;
    return 0;
}

/* ================================================================== */
/*  ServerHello                                                       */
/* ================================================================== */

static int build_server_hello(tlcp_conn_t *conn, unsigned char *buf,
                              unsigned long *len) {
    unsigned long pos = 0;

    buf[pos++] = TLCP_VERSION_MAJOR;
    buf[pos++] = TLCP_VERSION_MINOR;

    generate_random(conn->params.server_random, TLCP_RANDOM_LEN);
    memcpy(buf + pos, conn->params.server_random, TLCP_RANDOM_LEN);
    pos += TLCP_RANDOM_LEN;

    /* SessionID (echo back or generate) */
    if (conn->session_id_len == 0) {
        conn->session_id_len = TLCP_SESSION_ID_MAX_LEN;
        generate_random(conn->session_id, conn->session_id_len);
    }
    buf[pos++] = (unsigned char)conn->session_id_len;
    memcpy(buf + pos, conn->session_id, conn->session_id_len);
    pos += conn->session_id_len;

    /* Selected cipher suite */
    put_u16(buf + pos, conn->params.cipher_suite);
    pos += 2;

    /* Compression: null */
    buf[pos++] = 0;

    *len = pos;
    return 0;
}

static int parse_server_hello(tlcp_conn_t *conn, const unsigned char *body,
                              unsigned long body_len) {
    unsigned long pos = 0;

    if (body_len < 2)
        return -1;
    if (body[pos] != TLCP_VERSION_MAJOR || body[pos + 1] != TLCP_VERSION_MINOR)
        return -1;
    pos += 2;

    if (pos + TLCP_RANDOM_LEN > body_len)
        return -1;
    memcpy(conn->params.server_random, body + pos, TLCP_RANDOM_LEN);
    pos += TLCP_RANDOM_LEN;

    if (pos + 1 > body_len)
        return -1;
    unsigned long sid_len = body[pos++];
    if (pos + sid_len > body_len)
        return -1;
    if (sid_len <= TLCP_SESSION_ID_MAX_LEN) {
        memcpy(conn->session_id, body + pos, sid_len);
        conn->session_id_len = sid_len;
    }
    pos += sid_len;

    if (pos + 2 > body_len)
        return -1;
    conn->params.cipher_suite = (unsigned short)get_u16(body + pos);
    pos += 2;

    /* Compression (skip 1 byte) */
    if (pos + 1 > body_len)
        return -1;
    pos += 1;

    (void)pos;
    return 0;
}

/* ================================================================== */
/*  Certificate message                                               */
/* ================================================================== */

/*
 * Build Certificate message body: total_len(3) + { cert_len(3) + cert }*
 * TLCP sends signing cert first, then encryption cert.
 */
static int build_certificate_msg(const tlcp_cert_t *sign_cert,
                                 const tlcp_cert_t *enc_cert,
                                 unsigned char *buf, unsigned long *len) {
    unsigned long total = 0;
    unsigned long pos = 3; /* reserve 3 bytes for total length */

    if (sign_cert && sign_cert->der_len) {
        put_u24(buf + pos, sign_cert->der_len);
        pos += 3;
        memcpy(buf + pos, sign_cert->der, sign_cert->der_len);
        pos += sign_cert->der_len;
        total += 3 + sign_cert->der_len;
    }

    if (enc_cert && enc_cert->der_len) {
        put_u24(buf + pos, enc_cert->der_len);
        pos += 3;
        memcpy(buf + pos, enc_cert->der, enc_cert->der_len);
        pos += enc_cert->der_len;
        total += 3 + enc_cert->der_len;
    }

    put_u24(buf, total);
    *len = pos;
    return 0;
}

static int parse_certificate_msg(const unsigned char *body,
                                 unsigned long body_len,
                                 tlcp_cert_t *sign_cert,
                                 tlcp_cert_t *enc_cert,
                                 int *cert_count) {
    if (body_len < 3)
        return -1;

    unsigned long total = get_u24(body);
    const unsigned char *p = body + 3;
    unsigned long remain = body_len - 3;
    if (total > remain)
        return -1;

    *cert_count = 0;

    /* Parse first cert -> signing cert */
    if (remain >= 3) {
        unsigned long clen = get_u24(p);
        p += 3;
        remain -= 3;
        if (clen > remain)
            return -1;
        if (!tlcp_cert_parse(sign_cert, p, clen))
            return -1;
        p += clen;
        remain -= clen;
        (*cert_count)++;
    }

    /* Parse second cert -> encryption cert */
    if (remain >= 3) {
        unsigned long clen = get_u24(p);
        p += 3;
        remain -= 3;
        if (clen > remain)
            return -1;
        if (!tlcp_cert_parse(enc_cert, p, clen))
            return -1;
        p += clen;
        remain -= clen;
        (*cert_count)++;
    }

    (void)p;
    (void)remain;
    return 0;
}

/* ================================================================== */
/*  ServerKeyExchange (ECDHE only)                                    */
/* ================================================================== */

static int build_server_key_exchange(tlcp_conn_t *conn,
                                     const big_t *eph_pub_x,
                                     const big_t *eph_pub_y,
                                     const big_t *sign_key,
                                     const big_t *sign_pub_x,
                                     const big_t *sign_pub_y,
                                     unsigned char *buf,
                                     unsigned long *len) {
    unsigned long pos = 0;

    /* ECPoint: length(1) + 04 + x(32) + y(32) */
    buf[pos++] = 65;
    buf[pos++] = 0x04;

    unsigned long blen = 32;
    big_to_bytes(buf + pos, &blen, eph_pub_x);
    /* Right-pad if needed */
    if (blen < 32) {
        memmove(buf + pos + (32 - blen), buf + pos, blen);
        memset(buf + pos, 0, 32 - blen);
    }
    pos += 32;

    blen = 32;
    big_to_bytes(buf + pos, &blen, eph_pub_y);
    if (blen < 32) {
        memmove(buf + pos + (32 - blen), buf + pos, blen);
        memset(buf + pos, 0, 32 - blen);
    }
    pos += 32;

    /* Sign: client_random + server_random + ECPoint(66 bytes from buf[0..65]) */
    unsigned char to_sign[32 + 32 + 66];
    memcpy(to_sign, conn->params.client_random, 32);
    memcpy(to_sign + 32, conn->params.server_random, 32);
    memcpy(to_sign + 64, buf, 66);

    unsigned char za[32];
    sm2_za(za, (unsigned char *)"1234567812345678", 16,
           (big_t *)sign_pub_x, (big_t *)sign_pub_y);

    unsigned char sig[64];
    sm2_sign_generate(sig, to_sign, sizeof(to_sign), za, sign_key);

    /* Signature: length(2) + sig(64) */
    put_u16(buf + pos, 64);
    pos += 2;
    memcpy(buf + pos, sig, 64);
    pos += 64;

    *len = pos;
    return 0;
}

static int parse_server_key_exchange(tlcp_conn_t *conn,
                                     const unsigned char *body,
                                     unsigned long body_len,
                                     big_t *eph_pub_x, big_t *eph_pub_y,
                                     const big_t *sign_pub_x,
                                     const big_t *sign_pub_y) {
    unsigned long pos = 0;

    if (body_len < 66)
        return -1;

    unsigned char point_len = body[pos++];
    if (point_len != 65 || body[pos] != 0x04)
        return -1;
    pos++; /* skip 0x04 */

    big_from_bytes(eph_pub_x, (unsigned char *)(body + pos), 32);
    pos += 32;
    big_from_bytes(eph_pub_y, (unsigned char *)(body + pos), 32);
    pos += 32;

    /* Verify signature */
    if (pos + 2 > body_len)
        return -1;
    unsigned int sig_len = get_u16(body + pos);
    pos += 2;
    if (sig_len != 64 || pos + 64 > body_len)
        return -1;

    unsigned char to_sign[32 + 32 + 66];
    memcpy(to_sign, conn->params.client_random, 32);
    memcpy(to_sign + 32, conn->params.server_random, 32);
    memcpy(to_sign + 64, body, 66);

    unsigned char za[32];
    sm2_za(za, (unsigned char *)"1234567812345678", 16,
           (big_t *)sign_pub_x, (big_t *)sign_pub_y);

    if (!sm2_sign_verify((unsigned char *)(body + pos), to_sign,
                         sizeof(to_sign), za, sign_pub_x, sign_pub_y))
        return -1;

    return 0;
}

/* ================================================================== */
/*  ClientKeyExchange (ECC mode)                                      */
/* ================================================================== */

#define PMS_LEN 48

static int build_client_key_exchange_ecc(tlcp_conn_t *conn,
                                         const big_t *enc_pub_x,
                                         const big_t *enc_pub_y,
                                         unsigned char *buf,
                                         unsigned long *len) {
    unsigned char pms[PMS_LEN];
    /* pre_master_secret = version(2) + random(46) */
    pms[0] = TLCP_VERSION_MAJOR;
    pms[1] = TLCP_VERSION_MINOR;
    generate_random(pms + 2, 46);

    /* SM2 encrypt: output = C1(65) + C3(32) + C2(48) = 145 bytes */
    unsigned char enc_buf[256];
    if (!sm2_encrypt(enc_buf, sizeof(enc_buf), pms, PMS_LEN,
                     enc_pub_x, enc_pub_y))
        return -1;

    unsigned long enc_len = 65 + 32 + PMS_LEN; /* 145 */

    /* Derive master secret now (we have the PMS) */
    tlcp_derive_master_secret(conn->params.master_secret, pms, PMS_LEN,
                              conn->params.client_random,
                              conn->params.server_random);

    /* Body: 2-byte length + encrypted data */
    unsigned long pos = 0;
    put_u16(buf + pos, (unsigned int)enc_len);
    pos += 2;
    memcpy(buf + pos, enc_buf, enc_len);
    pos += enc_len;

    *len = pos;
    return 0;
}

static int parse_client_key_exchange_ecc(tlcp_conn_t *conn,
                                          const unsigned char *body,
                                          unsigned long body_len,
                                          const big_t *enc_priv_key) {
    if (body_len < 2)
        return -1;

    unsigned int enc_len = get_u16(body);
    if (2 + enc_len > body_len)
        return -1;

    const unsigned char *enc_data = body + 2;

    unsigned char pms[PMS_LEN];
    long pms_size = PMS_LEN;
    if (!sm2_decrypt(pms, pms_size, (unsigned char *)enc_data, (long)enc_len,
                     (big_t *)enc_priv_key))
        return -1;

    /* Derive master secret */
    tlcp_derive_master_secret(conn->params.master_secret, pms, PMS_LEN,
                              conn->params.client_random,
                              conn->params.server_random);

    return 0;
}

/* ================================================================== */
/*  CertificateRequest                                                */
/* ================================================================== */

static int build_cert_request(unsigned char *buf, unsigned long *len) {
    unsigned long pos = 0;

    /* certificate_types: 1 type (SM2 sign = type 1 by convention) */
    buf[pos++] = 1;  /* length */
    buf[pos++] = 1;  /* SM2 sign type */

    /* distinguished_names: empty */
    put_u16(buf + pos, 0);
    pos += 2;

    *len = pos;
    return 0;
}

/* ================================================================== */
/*  CertificateVerify                                                 */
/* ================================================================== */

static int build_cert_verify(tlcp_conn_t *conn, const big_t *sign_key,
                             const big_t *sign_pub_x,
                             const big_t *sign_pub_y,
                             unsigned char *buf, unsigned long *len) {
    /* Sign the handshake hash up to this point */
    unsigned char hs_digest[32];
    hs_hash_snapshot(conn, hs_digest);

    unsigned char za[32];
    sm2_za(za, (unsigned char *)"1234567812345678", 16,
           (big_t *)sign_pub_x, (big_t *)sign_pub_y);

    unsigned char sig[64];
    sm2_sign_generate(sig, hs_digest, 32, za, sign_key);

    /* Body: length(2) + signature(64) */
    unsigned long pos = 0;
    put_u16(buf + pos, 64);
    pos += 2;
    memcpy(buf + pos, sig, 64);
    pos += 64;

    *len = pos;
    return 0;
}

static int verify_cert_verify(tlcp_conn_t *conn, const unsigned char *body,
                              unsigned long body_len,
                              const big_t *sign_pub_x,
                              const big_t *sign_pub_y) {
    if (body_len < 2)
        return -1;
    unsigned int sig_len = get_u16(body);
    if (sig_len != 64 || body_len < 2 + 64)
        return -1;

    unsigned char hs_digest[32];
    hs_hash_snapshot(conn, hs_digest);

    unsigned char za[32];
    sm2_za(za, (unsigned char *)"1234567812345678", 16,
           (big_t *)sign_pub_x, (big_t *)sign_pub_y);

    if (!sm2_sign_verify((unsigned char *)(body + 2), hs_digest, 32, za,
                         sign_pub_x, sign_pub_y))
        return -1;

    return 0;
}

/* ================================================================== */
/*  Client handshake                                                  */
/* ================================================================== */

int tlcp_connect(tlcp_conn_t *conn) {
    unsigned char buf[TLCP_MAX_HANDSHAKE_SIZE];
    unsigned long blen;
    const unsigned char *body;
    unsigned long body_len;
    int rc;

    conn->is_server = 0;
    conn->state = TLCP_STATE_INIT;
    hs_hash_init(conn);

    /* --- 1. Send ClientHello --- */
    build_client_hello(conn, buf, &blen);
    if (hs_send(conn, TLCP_HS_CLIENT_HELLO, buf, blen) != 0)
        goto fail;
    conn->state = TLCP_STATE_CLIENT_HELLO;

    /* --- 2. Receive ServerHello --- */
    if (hs_recv(conn, TLCP_HS_SERVER_HELLO, &body, &body_len) != 0)
        goto fail;
    if (parse_server_hello(conn, body, body_len) != 0)
        goto fail;
    conn->state = TLCP_STATE_SERVER_HELLO;

    /* Validate that we support the selected cipher suite */
    {
        unsigned short cs = conn->params.cipher_suite;
        int found = 0;
        for (int i = 0; i < conn->ctx->cipher_suite_count; i++) {
            if (conn->ctx->cipher_suites[i] == cs) {
                found = 1;
                break;
            }
        }
        if (!found)
            goto fail;

        conn->params.is_gcm = (cs == TLCP_ECC_SM4_GCM_SM3 ||
                                cs == TLCP_ECDHE_SM4_GCM_SM3) ? 1 : 0;
    }

    /* --- 3. Receive Certificate --- */
    if (hs_recv(conn, TLCP_HS_CERTIFICATE, &body, &body_len) != 0)
        goto fail;
    if (parse_certificate_msg(body, body_len,
                              &conn->peer_sign_cert, &conn->peer_enc_cert,
                              &conn->peer_cert_count) != 0)
        goto fail;
    if (!conn->peer_sign_cert.has_pubkey || !conn->peer_enc_cert.has_pubkey)
        goto fail;
    conn->state = TLCP_STATE_SERVER_CERT;

    /* --- 4/5/6. Receive ServerKeyExchange / CertificateRequest / ServerHelloDone --- */
    {
        unsigned short cs = conn->params.cipher_suite;
        int need_ske = is_ecdhe_suite(cs);
        int cert_requested = 0;

        if (need_ske) {
            /* Receive ServerKeyExchange */
            big_t eph_x, eph_y;
            big_init(&eph_x);
            big_init(&eph_y);

            if (hs_recv(conn, TLCP_HS_SERVER_KEY_EXCHANGE, &body, &body_len) != 0) {
                big_destroy(&eph_x);
                big_destroy(&eph_y);
                goto fail;
            }
            if (parse_server_key_exchange(conn, body, body_len,
                                          &eph_x, &eph_y,
                                          &conn->peer_sign_cert.pubkey_x,
                                          &conn->peer_sign_cert.pubkey_y) != 0) {
                big_destroy(&eph_x);
                big_destroy(&eph_y);
                goto fail;
            }
            conn->state = TLCP_STATE_SERVER_KEY_EX;

            /* TODO: store ephemeral key for ECDHE computation */
            big_destroy(&eph_x);
            big_destroy(&eph_y);
        }

        /* Next message can be CertificateRequest or ServerHelloDone */
        rc = hs_recv_any(conn, &body, &body_len);
        if (rc == TLCP_HS_CERTIFICATE_REQUEST) {
            cert_requested = 1;
            conn->state = TLCP_STATE_CERT_REQUEST;

            /* Now read ServerHelloDone */
            if (hs_recv(conn, TLCP_HS_SERVER_HELLO_DONE, &body, &body_len) != 0)
                goto fail;
        } else if (rc == TLCP_HS_SERVER_HELLO_DONE) {
            /* Already got it */
        } else {
            goto fail;
        }
        conn->state = TLCP_STATE_SERVER_DONE;

        /* --- 7. Optionally send Certificate --- */
        if (cert_requested && conn->ctx->has_sign_cert) {
            build_certificate_msg(&conn->ctx->sign_cert, &conn->ctx->enc_cert,
                                  buf, &blen);
            if (hs_send(conn, TLCP_HS_CERTIFICATE, buf, blen) != 0)
                goto fail;
            conn->state = TLCP_STATE_CLIENT_CERT;
        }

        /* --- 8. Send ClientKeyExchange --- */
        if (is_ecc_suite(cs)) {
            if (build_client_key_exchange_ecc(conn,
                                              &conn->peer_enc_cert.pubkey_x,
                                              &conn->peer_enc_cert.pubkey_y,
                                              buf, &blen) != 0)
                goto fail;
        } else {
            /* ECDHE: TODO – full ECDHE key exchange */
            /* For now, fall back to ECC-style as placeholder */
            if (build_client_key_exchange_ecc(conn,
                                              &conn->peer_enc_cert.pubkey_x,
                                              &conn->peer_enc_cert.pubkey_y,
                                              buf, &blen) != 0)
                goto fail;
        }
        if (hs_send(conn, TLCP_HS_CLIENT_KEY_EXCHANGE, buf, blen) != 0)
            goto fail;
        conn->state = TLCP_STATE_CLIENT_KEY_EX;

        /* --- 9. Optionally send CertificateVerify --- */
        if (cert_requested && conn->ctx->has_sign_cert) {
            if (build_cert_verify(conn, &conn->ctx->sign_private_key,
                                  &conn->ctx->sign_cert.pubkey_x,
                                  &conn->ctx->sign_cert.pubkey_y,
                                  buf, &blen) != 0)
                goto fail;
            if (hs_send(conn, TLCP_HS_CERTIFICATE_VERIFY, buf, blen) != 0)
                goto fail;
            conn->state = TLCP_STATE_CERT_VERIFY;
        }
    }

    /* --- 10. Derive keys --- */
    tlcp_derive_keys(&conn->params);

    /* --- 11. Send ChangeCipherSpec --- */
    if (send_ccs(conn) != 0)
        goto fail;
    conn->state = TLCP_STATE_CHANGE_CIPHER;

    /* Activate client write cipher */
    conn->client_cipher_active = 1;

    /* --- 12. Send Finished --- */
    {
        unsigned char verify_data[TLCP_VERIFY_DATA_LEN];
        compute_verify_data(conn, 1, verify_data);
        if (hs_send(conn, TLCP_HS_FINISHED, verify_data,
                     TLCP_VERIFY_DATA_LEN) != 0)
            goto fail;
    }
    conn->state = TLCP_STATE_FINISHED;

    /* --- 13. Receive ChangeCipherSpec --- */
    if (recv_ccs(conn) != 0)
        goto fail;

    /* Activate server cipher for reading */
    conn->server_cipher_active = 1;

    /* --- 14. Receive Finished --- */
    if (hs_recv(conn, TLCP_HS_FINISHED, &body, &body_len) != 0)
        goto fail;
    if (body_len != TLCP_VERIFY_DATA_LEN)
        goto fail;

    {
        unsigned char expected[TLCP_VERIFY_DATA_LEN];
        compute_verify_data(conn, 0, expected);

        unsigned char diff = 0;
        for (int i = 0; i < TLCP_VERIFY_DATA_LEN; i++)
            diff |= body[i] ^ expected[i];
        if (diff != 0)
            goto fail;
    }

    conn->state = TLCP_STATE_ESTABLISHED;
    return 0;

fail:
    tlcp_send_alert(conn, TLCP_ALERT_FATAL, TLCP_ALERT_HANDSHAKE_FAILURE);
    conn->state = TLCP_STATE_ERROR;
    return -1;
}

/* ================================================================== */
/*  Server handshake                                                  */
/* ================================================================== */

int tlcp_accept(tlcp_conn_t *conn) {
    unsigned char buf[TLCP_MAX_HANDSHAKE_SIZE];
    unsigned long blen;
    const unsigned char *body;
    unsigned long body_len;

    conn->is_server = 1;
    conn->state = TLCP_STATE_INIT;
    hs_hash_init(conn);

    /* --- 1. Receive ClientHello --- */
    {
        unsigned short client_suites[4];
        int client_suite_count = 0;

        if (hs_recv(conn, TLCP_HS_CLIENT_HELLO, &body, &body_len) != 0)
            goto fail;
        if (parse_client_hello(conn, body, body_len,
                               client_suites, &client_suite_count) != 0)
            goto fail;
        conn->state = TLCP_STATE_CLIENT_HELLO;

        /* Select cipher suite */
        if (!select_cipher_suite(client_suites, client_suite_count,
                                 conn->ctx->cipher_suites,
                                 conn->ctx->cipher_suite_count,
                                 &conn->params.cipher_suite))
            goto fail;

        conn->params.is_gcm = (conn->params.cipher_suite == TLCP_ECC_SM4_GCM_SM3 ||
                                conn->params.cipher_suite == TLCP_ECDHE_SM4_GCM_SM3)
                                   ? 1 : 0;
    }

    /* --- 2. Send ServerHello --- */
    build_server_hello(conn, buf, &blen);
    if (hs_send(conn, TLCP_HS_SERVER_HELLO, buf, blen) != 0)
        goto fail;
    conn->state = TLCP_STATE_SERVER_HELLO;

    /* --- 3. Send Certificate (signing + encryption) --- */
    if (!conn->ctx->has_sign_cert || !conn->ctx->has_enc_cert)
        goto fail;
    build_certificate_msg(&conn->ctx->sign_cert, &conn->ctx->enc_cert,
                          buf, &blen);
    if (hs_send(conn, TLCP_HS_CERTIFICATE, buf, blen) != 0)
        goto fail;
    conn->state = TLCP_STATE_SERVER_CERT;

    /* --- 4. Send ServerKeyExchange (ECDHE only) --- */
    if (is_ecdhe_suite(conn->params.cipher_suite)) {
        big_t eph_d, eph_x, eph_y;
        big_init(&eph_d);
        big_init(&eph_x);
        big_init(&eph_y);

        sm2_gen_key(&eph_d, &eph_x, &eph_y);

        if (build_server_key_exchange(conn, &eph_x, &eph_y,
                                       &conn->ctx->sign_private_key,
                                       &conn->ctx->sign_cert.pubkey_x,
                                       &conn->ctx->sign_cert.pubkey_y,
                                       buf, &blen) != 0) {
            big_destroy(&eph_d);
            big_destroy(&eph_x);
            big_destroy(&eph_y);
            goto fail;
        }

        if (hs_send(conn, TLCP_HS_SERVER_KEY_EXCHANGE, buf, blen) != 0) {
            big_destroy(&eph_d);
            big_destroy(&eph_x);
            big_destroy(&eph_y);
            goto fail;
        }
        conn->state = TLCP_STATE_SERVER_KEY_EX;

        /* TODO: store ephemeral private key for later ECDHE computation */
        big_destroy(&eph_d);
        big_destroy(&eph_x);
        big_destroy(&eph_y);
    }

    /* --- 5. Optionally send CertificateRequest --- */
    if (conn->ctx->verify_client) {
        build_cert_request(buf, &blen);
        if (hs_send(conn, TLCP_HS_CERTIFICATE_REQUEST, buf, blen) != 0)
            goto fail;
        conn->state = TLCP_STATE_CERT_REQUEST;
    }

    /* --- 6. Send ServerHelloDone --- */
    if (hs_send(conn, TLCP_HS_SERVER_HELLO_DONE, NULL, 0) != 0)
        goto fail;
    conn->state = TLCP_STATE_SERVER_DONE;

    /* --- 7/8/9. Receive client messages --- */
    {
        int client_sent_cert = 0;

        /* If we requested client cert, expect Certificate next */
        if (conn->ctx->verify_client) {
            int msg_type = hs_recv_any(conn, &body, &body_len);
            if (msg_type == TLCP_HS_CERTIFICATE) {
                if (parse_certificate_msg(body, body_len,
                                          &conn->peer_sign_cert,
                                          &conn->peer_enc_cert,
                                          &conn->peer_cert_count) != 0)
                    goto fail;
                client_sent_cert = 1;
                conn->state = TLCP_STATE_CLIENT_CERT;

                /* Now receive ClientKeyExchange */
                if (hs_recv(conn, TLCP_HS_CLIENT_KEY_EXCHANGE,
                            &body, &body_len) != 0)
                    goto fail;
            } else if (msg_type == TLCP_HS_CLIENT_KEY_EXCHANGE) {
                /* Client didn't send a certificate – body is CKE */
            } else {
                goto fail;
            }
        } else {
            /* No client cert requested – just receive ClientKeyExchange */
            if (hs_recv(conn, TLCP_HS_CLIENT_KEY_EXCHANGE,
                        &body, &body_len) != 0)
                goto fail;
        }

        /* Parse ClientKeyExchange */
        if (is_ecc_suite(conn->params.cipher_suite)) {
            if (parse_client_key_exchange_ecc(conn, body, body_len,
                                              &conn->ctx->enc_private_key) != 0)
                goto fail;
        } else {
            /* ECDHE: TODO – full ECDHE key exchange */
            if (parse_client_key_exchange_ecc(conn, body, body_len,
                                              &conn->ctx->enc_private_key) != 0)
                goto fail;
        }
        conn->state = TLCP_STATE_CLIENT_KEY_EX;

        /* Optionally receive CertificateVerify */
        if (client_sent_cert && conn->peer_sign_cert.has_pubkey) {
            if (hs_recv(conn, TLCP_HS_CERTIFICATE_VERIFY,
                        &body, &body_len) != 0)
                goto fail;
            if (verify_cert_verify(conn, body, body_len,
                                   &conn->peer_sign_cert.pubkey_x,
                                   &conn->peer_sign_cert.pubkey_y) != 0)
                goto fail;
            conn->state = TLCP_STATE_CERT_VERIFY;
        }
    }

    /* --- 10. Derive keys --- */
    tlcp_derive_keys(&conn->params);

    /* --- 11. Receive ChangeCipherSpec from client --- */
    if (recv_ccs(conn) != 0)
        goto fail;

    /* Activate client cipher for reading */
    conn->client_cipher_active = 1;

    /* --- 12. Receive Finished from client --- */
    if (hs_recv(conn, TLCP_HS_FINISHED, &body, &body_len) != 0)
        goto fail;
    if (body_len != TLCP_VERIFY_DATA_LEN)
        goto fail;

    {
        unsigned char expected[TLCP_VERIFY_DATA_LEN];
        compute_verify_data(conn, 1, expected); /* client finished */

        unsigned char diff = 0;
        for (int i = 0; i < TLCP_VERIFY_DATA_LEN; i++)
            diff |= body[i] ^ expected[i];
        if (diff != 0)
            goto fail;
    }
    conn->state = TLCP_STATE_FINISHED;

    /* --- 13. Send ChangeCipherSpec --- */
    if (send_ccs(conn) != 0)
        goto fail;
    conn->state = TLCP_STATE_CHANGE_CIPHER;

    /* Activate server write cipher */
    conn->server_cipher_active = 1;

    /* --- 14. Send Finished --- */
    {
        unsigned char verify_data[TLCP_VERIFY_DATA_LEN];
        compute_verify_data(conn, 0, verify_data); /* server finished */
        if (hs_send(conn, TLCP_HS_FINISHED, verify_data,
                     TLCP_VERIFY_DATA_LEN) != 0)
            goto fail;
    }

    conn->state = TLCP_STATE_ESTABLISHED;
    return 0;

fail:
    tlcp_send_alert(conn, TLCP_ALERT_FATAL, TLCP_ALERT_HANDSHAKE_FAILURE);
    conn->state = TLCP_STATE_ERROR;
    return -1;
}
