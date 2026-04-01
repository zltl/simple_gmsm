#include "simple_gmsm/tlcp.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Certificate parsing helpers                                       */
/* ------------------------------------------------------------------ */

/*
 * Minimal ASN.1 DER parser – just enough to walk through a certificate
 * and locate the SubjectPublicKeyInfo containing an SM2 (OID 1.2.840.10045.2.1)
 * public key, i.e. an uncompressed EC point (0x04 || X || Y, 64 bytes).
 *
 * Returns the number of bytes consumed by the TLV, or 0 on error.
 * If tag_out/len_out/value_out are non-NULL they receive the parsed values.
 */
static unsigned long asn1_read_tlv(const unsigned char* buf, unsigned long buflen,
                                   unsigned char* tag_out,
                                   unsigned long* len_out,
                                   const unsigned char** value_out) {
    unsigned long pos = 0;
    unsigned char tag;
    unsigned long length;

    if (buflen < 2)
        return 0;

    tag = buf[pos++];
    if (tag_out)
        *tag_out = tag;

    if (buf[pos] < 0x80) {
        length = buf[pos++];
    } else {
        unsigned int nbytes = buf[pos++] & 0x7F;
        if (nbytes > 4 || pos + nbytes > buflen)
            return 0;
        length = 0;
        for (unsigned int i = 0; i < nbytes; i++)
            length = (length << 8) | buf[pos++];
    }

    if (pos + length > buflen)
        return 0;
    if (len_out)
        *len_out = length;
    if (value_out)
        *value_out = buf + pos;

    return pos + length;
}

/*
 * Search DER data for an uncompressed EC point (0x04 + 32-byte X + 32-byte Y).
 * This is a heuristic scanner: it walks ASN.1 structures looking for a
 * BIT STRING whose payload starts with 0x00 0x04 followed by 64 bytes.
 */
static int find_sm2_pubkey(const unsigned char* der, unsigned long len,
                           const unsigned char** px, const unsigned char** py) {
    for (unsigned long i = 0; i + 66 <= len; i++) {
        /* Look for BIT STRING (tag 0x03) that wraps 0x00 0x04 ... */
        if (der[i] == 0x03) {
            unsigned long inner_len;
            const unsigned char* inner;
            unsigned long consumed = asn1_read_tlv(der + i, len - i,
                                                   NULL, &inner_len, &inner);
            if (consumed && inner_len == 66 &&
                inner[0] == 0x00 && inner[1] == 0x04) {
                *px = inner + 2;
                *py = inner + 2 + 32;
                return 1;
            }
        }
    }
    return 0;
}

int tlcp_cert_parse(tlcp_cert_t* cert, const unsigned char* der,
                    unsigned long len) {
    if (!cert || !der || len == 0 || len > TLCP_MAX_CERT_SIZE)
        return 0;

    memcpy(cert->der, der, len);
    cert->der_len = len;
    cert->has_pubkey = 0;

    const unsigned char *px = NULL, *py = NULL;
    if (find_sm2_pubkey(der, len, &px, &py)) {
        big_from_bytes(&cert->pubkey_x, (unsigned char*)px, 32);
        big_from_bytes(&cert->pubkey_y, (unsigned char*)py, 32);
        cert->has_pubkey = 1;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/*  Context management                                                */
/* ------------------------------------------------------------------ */

void tlcp_ctx_init(tlcp_context_t* ctx) {
    memset(ctx, 0, sizeof(*ctx));

    /* Default cipher suite preference: all four suites */
    ctx->cipher_suites[0] = TLCP_ECC_SM4_CBC_SM3;
    ctx->cipher_suites[1] = TLCP_ECC_SM4_GCM_SM3;
    ctx->cipher_suites[2] = TLCP_ECDHE_SM4_CBC_SM3;
    ctx->cipher_suites[3] = TLCP_ECDHE_SM4_GCM_SM3;
    ctx->cipher_suite_count = 4;

    ctx->is_server = 0;
}

void tlcp_ctx_set_server(tlcp_context_t* ctx, int is_server) {
    ctx->is_server = is_server;
}

int tlcp_ctx_set_sign_cert(tlcp_context_t* ctx, const unsigned char* der,
                           unsigned long len) {
    if (!tlcp_cert_parse(&ctx->sign_cert, der, len))
        return 0;
    ctx->has_sign_cert = 1;
    return 1;
}

int tlcp_ctx_set_enc_cert(tlcp_context_t* ctx, const unsigned char* der,
                          unsigned long len) {
    if (!tlcp_cert_parse(&ctx->enc_cert, der, len))
        return 0;
    ctx->has_enc_cert = 1;
    return 1;
}

void tlcp_ctx_set_sign_key(tlcp_context_t* ctx, const big_t* key) {
    big_set(&ctx->sign_private_key, key);
}

void tlcp_ctx_set_enc_key(tlcp_context_t* ctx, const big_t* key) {
    big_set(&ctx->enc_private_key, key);
}

int tlcp_ctx_add_ca_cert(tlcp_context_t* ctx, const unsigned char* der,
                         unsigned long len) {
    if (ctx->ca_cert_count >= 8)
        return 0;
    if (!tlcp_cert_parse(&ctx->ca_certs[ctx->ca_cert_count], der, len))
        return 0;
    ctx->ca_cert_count++;
    return 1;
}

void tlcp_ctx_set_cipher_suites(tlcp_context_t* ctx,
                                const unsigned short* suites, int count) {
    if (count > 4)
        count = 4;
    for (int i = 0; i < count; i++)
        ctx->cipher_suites[i] = suites[i];
    ctx->cipher_suite_count = count;
}

/* ------------------------------------------------------------------ */
/*  Connection management                                             */
/* ------------------------------------------------------------------ */

void tlcp_conn_init(tlcp_conn_t* conn, tlcp_context_t* ctx) {
    memset(conn, 0, sizeof(*conn));
    conn->ctx = ctx;
    conn->is_server = ctx->is_server;
    conn->state = TLCP_STATE_INIT;
}

void tlcp_conn_set_io(tlcp_conn_t* conn, tlcp_read_fn rfn, tlcp_write_fn wfn,
                      void* io_ctx) {
    conn->read_fn = rfn;
    conn->write_fn = wfn;
    conn->io_ctx = io_ctx;
}
