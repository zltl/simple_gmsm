#include "simple_gmsm/tlcp.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/* Encode a 64-bit sequence number into 8 big-endian bytes */
static void put_seq(unsigned char out[8], unsigned long long seq) {
    out[0] = (unsigned char)(seq >> 56);
    out[1] = (unsigned char)(seq >> 48);
    out[2] = (unsigned char)(seq >> 40);
    out[3] = (unsigned char)(seq >> 32);
    out[4] = (unsigned char)(seq >> 24);
    out[5] = (unsigned char)(seq >> 16);
    out[6] = (unsigned char)(seq >> 8);
    out[7] = (unsigned char)(seq);
}

/* Encode a 16-bit value into 2 big-endian bytes */
static void put_u16(unsigned char out[2], unsigned int val) {
    out[0] = (unsigned char)(val >> 8);
    out[1] = (unsigned char)(val);
}

/* Decode a 16-bit value from 2 big-endian bytes */
static unsigned int get_u16(const unsigned char in[2]) {
    return ((unsigned int)in[0] << 8) | (unsigned int)in[1];
}

/* Read exactly len bytes via I/O callback, retrying as needed */
static int io_read_all(tlcp_conn_t* conn, unsigned char* buf,
                       unsigned long len) {
    unsigned long total = 0;
    while (total < len) {
        int n = conn->read_fn(conn->io_ctx, buf + total, len - total);
        if (n <= 0)
            return -1;
        total += (unsigned long)n;
    }
    return 0;
}

/* Write exactly len bytes via I/O callback */
static int io_write_all(tlcp_conn_t* conn, const unsigned char* buf,
                        unsigned long len) {
    unsigned long total = 0;
    while (total < len) {
        int n = conn->write_fn(conn->io_ctx, buf + total, len - total);
        if (n <= 0)
            return -1;
        total += (unsigned long)n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  CBC record encryption                                             */
/*                                                                    */
/*  Fragment = IV(16) + SM4-CBC(plaintext + MAC + padding)            */
/*  MAC = HMAC-SM3(mac_key, seq(8)+type(1)+version(2)+length(2)+data)*/
/* ------------------------------------------------------------------ */

/* Simple per-record IV: use sequence number + zeros */
static void make_record_iv(unsigned char iv[16], unsigned long long seq) {
    memset(iv, 0, 16);
    put_seq(iv, seq);
}

static int cbc_encrypt_record(tlcp_conn_t* conn, unsigned char content_type,
                              const unsigned char* data, unsigned long len,
                              unsigned char* out, unsigned long* out_len) {
    int sending = conn->is_server ? 1 : 0;
    const unsigned char* mac_key = sending
        ? conn->params.server_write_mac_key
        : conn->params.client_write_mac_key;
    const unsigned char* enc_key = sending
        ? conn->params.server_write_key
        : conn->params.client_write_key;
    unsigned long long* seq = sending
        ? &conn->server_seq
        : &conn->client_seq;

    unsigned char mac[32];
    unsigned char hdr_buf[13]; /* seq(8) + type(1) + version(2) + length(2) */
    hmac_sm3_context_t hmac;

    /* Compute MAC over: seq_num || type || version || length || data */
    put_seq(hdr_buf, *seq);
    hdr_buf[8] = content_type;
    hdr_buf[9] = TLCP_VERSION_MAJOR;
    hdr_buf[10] = TLCP_VERSION_MINOR;
    put_u16(hdr_buf + 11, (unsigned int)len);

    hmac_sm3_init(&hmac, mac_key, 32);
    hmac_sm3_update(&hmac, hdr_buf, 13);
    hmac_sm3_update(&hmac, data, len);
    hmac_sm3_finish(&hmac, mac);

    /* Build plaintext for CBC: data + mac */
    unsigned long plain_len = len + 32;

    /* Temporary buffer to hold plaintext for CBC encryption */
    unsigned char plaintext[TLCP_MAX_FRAGMENT_LEN + 32 + 16];
    if (plain_len > sizeof(plaintext))
        return -1;

    memcpy(plaintext, data, len);
    memcpy(plaintext + len, mac, 32);

    /* Generate per-record IV and place it at start of output */
    unsigned char iv[16];
    make_record_iv(iv, *seq);
    memcpy(out, iv, 16);

    /* SM4-CBC encrypt (PKCS#7 padding is handled by sm4_cbc_encrypt) */
    unsigned long ciphertext_len = 0;
    if (!sm4_cbc_encrypt(enc_key, iv, plaintext, plain_len,
                         out + 16, &ciphertext_len))
        return -1;

    *out_len = 16 + ciphertext_len; /* IV + ciphertext */
    (*seq)++;
    return 0;
}

static int cbc_decrypt_record(tlcp_conn_t* conn, unsigned char content_type,
                              const unsigned char* fragment,
                              unsigned long frag_len,
                              unsigned char* out, unsigned long* out_len) {
    int receiving = conn->is_server ? 0 : 1; /* receiving from peer */
    const unsigned char* mac_key = receiving
        ? conn->params.server_write_mac_key
        : conn->params.client_write_mac_key;
    const unsigned char* enc_key = receiving
        ? conn->params.server_write_key
        : conn->params.client_write_key;
    unsigned long long* seq = receiving
        ? &conn->server_seq
        : &conn->client_seq;

    /* Need at least IV(16) + one block(16) */
    if (frag_len < 32)
        return -1;

    const unsigned char* iv = fragment;
    const unsigned char* ciphertext = fragment + 16;
    unsigned long ciphertext_len = frag_len - 16;

    /* Decrypt */
    unsigned char plaintext[TLCP_MAX_FRAGMENT_LEN + 32 + 16];
    unsigned long plain_len = 0;
    if (!sm4_cbc_decrypt(enc_key, iv, ciphertext, ciphertext_len,
                         plaintext, &plain_len))
        return -1;

    /* Plaintext = data + MAC(32). Need at least 32 bytes for MAC. */
    if (plain_len < 32)
        return -1;

    unsigned long data_len = plain_len - 32;

    /* Verify MAC */
    unsigned char mac[32];
    unsigned char hdr_buf[13];
    hmac_sm3_context_t hmac;

    put_seq(hdr_buf, *seq);
    hdr_buf[8] = content_type;
    hdr_buf[9] = TLCP_VERSION_MAJOR;
    hdr_buf[10] = TLCP_VERSION_MINOR;
    put_u16(hdr_buf + 11, (unsigned int)data_len);

    hmac_sm3_init(&hmac, mac_key, 32);
    hmac_sm3_update(&hmac, hdr_buf, 13);
    hmac_sm3_update(&hmac, plaintext, data_len);
    hmac_sm3_finish(&hmac, mac);

    /* Constant-time compare */
    unsigned char diff = 0;
    for (unsigned long i = 0; i < 32; i++)
        diff |= mac[i] ^ plaintext[data_len + i];
    if (diff != 0)
        return -1;

    memcpy(out, plaintext, data_len);
    *out_len = data_len;
    (*seq)++;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  GCM record encryption                                             */
/*                                                                    */
/*  Fragment = nonce_explicit(8) + ciphertext + tag(16)               */
/*  nonce = implicit_iv(4) + nonce_explicit(8)                        */
/*  AAD = seq(8) + type(1) + version(2) + length(2)                  */
/* ------------------------------------------------------------------ */

static int gcm_encrypt_record(tlcp_conn_t* conn, unsigned char content_type,
                              const unsigned char* data, unsigned long len,
                              unsigned char* out, unsigned long* out_len) {
    int sending = conn->is_server ? 1 : 0;
    const unsigned char* enc_key = sending
        ? conn->params.server_write_key
        : conn->params.client_write_key;
    const unsigned char* implicit_iv = sending
        ? conn->params.server_write_iv
        : conn->params.client_write_iv;
    unsigned long long* seq = sending
        ? &conn->server_seq
        : &conn->client_seq;

    /* Build nonce: implicit_iv(4) + explicit_nonce(8) */
    unsigned char nonce[12];
    unsigned char explicit_nonce[8];
    memcpy(nonce, implicit_iv, 4);
    put_seq(explicit_nonce, *seq);
    memcpy(nonce + 4, explicit_nonce, 8);

    /* Build AAD: seq(8) + type(1) + version(2) + length(2) */
    unsigned char aad[13];
    put_seq(aad, *seq);
    aad[8] = content_type;
    aad[9] = TLCP_VERSION_MAJOR;
    aad[10] = TLCP_VERSION_MINOR;
    put_u16(aad + 11, (unsigned int)len);

    /* Output: explicit_nonce(8) + ciphertext(len) + tag(16) */
    memcpy(out, explicit_nonce, 8);

    unsigned char tag[16];
    if (!sm4_gcm_encrypt(enc_key, nonce, 12, aad, 13,
                         data, len, out + 8, tag))
        return -1;

    memcpy(out + 8 + len, tag, 16);
    *out_len = 8 + len + 16;
    (*seq)++;
    return 0;
}

static int gcm_decrypt_record(tlcp_conn_t* conn, unsigned char content_type,
                              const unsigned char* fragment,
                              unsigned long frag_len,
                              unsigned char* out, unsigned long* out_len) {
    int receiving = conn->is_server ? 0 : 1;
    const unsigned char* enc_key = receiving
        ? conn->params.server_write_key
        : conn->params.client_write_key;
    const unsigned char* implicit_iv = receiving
        ? conn->params.server_write_iv
        : conn->params.client_write_iv;
    unsigned long long* seq = receiving
        ? &conn->server_seq
        : &conn->client_seq;

    /* Need at least explicit_nonce(8) + tag(16) */
    if (frag_len < 24)
        return -1;

    unsigned long data_len = frag_len - 8 - 16;

    /* Reconstruct nonce */
    unsigned char nonce[12];
    memcpy(nonce, implicit_iv, 4);
    memcpy(nonce + 4, fragment, 8); /* explicit nonce */

    /* Build AAD */
    unsigned char aad[13];
    put_seq(aad, *seq);
    aad[8] = content_type;
    aad[9] = TLCP_VERSION_MAJOR;
    aad[10] = TLCP_VERSION_MINOR;
    put_u16(aad + 11, (unsigned int)data_len);

    const unsigned char* ciphertext = fragment + 8;
    const unsigned char* tag = fragment + 8 + data_len;

    if (!sm4_gcm_decrypt(enc_key, nonce, 12, aad, 13,
                         ciphertext, data_len, out, tag))
        return -1;

    *out_len = data_len;
    (*seq)++;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public record layer API                                           */
/* ------------------------------------------------------------------ */

int tlcp_record_write(tlcp_conn_t* conn, unsigned char content_type,
                      const unsigned char* data, unsigned long len) {
    unsigned char header[TLCP_RECORD_HEADER_SIZE];
    int cipher_active = conn->is_server
        ? conn->server_cipher_active
        : conn->client_cipher_active;

    if (cipher_active) {
        /* Encrypted record */
        unsigned char fragment[TLCP_MAX_FRAGMENT_LEN + 256];
        unsigned long frag_len = 0;
        int rc;

        if (conn->params.is_gcm)
            rc = gcm_encrypt_record(conn, content_type, data, len,
                                    fragment, &frag_len);
        else
            rc = cbc_encrypt_record(conn, content_type, data, len,
                                    fragment, &frag_len);

        if (rc != 0)
            return -1;

        /* Write record header */
        header[0] = content_type;
        header[1] = TLCP_VERSION_MAJOR;
        header[2] = TLCP_VERSION_MINOR;
        put_u16(header + 3, (unsigned int)frag_len);

        if (io_write_all(conn, header, TLCP_RECORD_HEADER_SIZE) != 0)
            return -1;
        if (io_write_all(conn, fragment, frag_len) != 0)
            return -1;
    } else {
        /* Plaintext record */
        header[0] = content_type;
        header[1] = TLCP_VERSION_MAJOR;
        header[2] = TLCP_VERSION_MINOR;
        put_u16(header + 3, (unsigned int)len);

        if (io_write_all(conn, header, TLCP_RECORD_HEADER_SIZE) != 0)
            return -1;
        if (len > 0 && io_write_all(conn, data, len) != 0)
            return -1;
    }

    return 0;
}

int tlcp_record_read(tlcp_conn_t* conn, unsigned char* content_type,
                     unsigned char* data, unsigned long* len) {
    unsigned char header[TLCP_RECORD_HEADER_SIZE];
    int cipher_active = conn->is_server
        ? conn->client_cipher_active
        : conn->server_cipher_active;

    /* Read 5-byte record header */
    if (io_read_all(conn, header, TLCP_RECORD_HEADER_SIZE) != 0)
        return -1;

    *content_type = header[0];
    unsigned int frag_len = get_u16(header + 3);

    /* Validate version */
    if (header[1] != TLCP_VERSION_MAJOR || header[2] != TLCP_VERSION_MINOR) {
        conn->last_error = TLCP_ALERT_PROTOCOL_VERSION;
        return -1;
    }

    /* Validate length */
    if (frag_len > TLCP_MAX_RECORD_LEN + 256) {
        conn->last_error = TLCP_ALERT_RECORD_OVERFLOW;
        return -1;
    }

    /* Read fragment */
    unsigned char fragment[TLCP_MAX_RECORD_LEN + 256];
    if (io_read_all(conn, fragment, frag_len) != 0)
        return -1;

    if (cipher_active) {
        /* Decrypt */
        int rc;
        if (conn->params.is_gcm)
            rc = gcm_decrypt_record(conn, *content_type,
                                    fragment, frag_len, data, len);
        else
            rc = cbc_decrypt_record(conn, *content_type,
                                    fragment, frag_len, data, len);

        if (rc != 0) {
            conn->last_error = TLCP_ALERT_BAD_RECORD_MAC;
            return -1;
        }
    } else {
        /* Plaintext */
        memcpy(data, fragment, frag_len);
        *len = frag_len;
    }

    return 0;
}
