#include "simple_gmsm/tlcp.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/*  Certificate verification helpers                                  */
/* ------------------------------------------------------------------ */

/*
 * Minimal ASN.1 DER TLV reader (duplicated privately for this TU).
 * Returns total consumed bytes, or 0 on error.
 */
static unsigned long cert_asn1_read_tlv(const unsigned char *buf,
                                        unsigned long buflen,
                                        unsigned char *tag_out,
                                        unsigned long *len_out,
                                        const unsigned char **value_out) {
    unsigned long pos = 0;
    if (buflen < 2)
        return 0;

    unsigned char tag = buf[pos++];
    if (tag_out)
        *tag_out = tag;

    unsigned long length;
    if (buf[pos] < 0x80) {
        length = buf[pos++];
    } else {
        unsigned int nbytes = buf[pos++] & 0x7Fu;
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
 * Locate the TBSCertificate portion (first element of the outer SEQUENCE)
 * and the signatureValue (last element) inside a DER certificate.
 *
 * X.509 Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,    -- SEQUENCE
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 */
static int cert_find_tbs_and_sig(const unsigned char *der, unsigned long len,
                                 const unsigned char **tbs, unsigned long *tbs_len,
                                 const unsigned char **sig, unsigned long *sig_len) {
    /* Outer SEQUENCE */
    unsigned long outer_vlen;
    const unsigned char *outer_val;
    unsigned long consumed = cert_asn1_read_tlv(der, len, NULL, &outer_vlen,
                                                &outer_val);
    if (!consumed)
        return 0;

    unsigned long header_len = consumed - outer_vlen;
    const unsigned char *p = outer_val;
    unsigned long remain = outer_vlen;

    /* 1st element: TBSCertificate (SEQUENCE) */
    unsigned long tbs_vlen;
    const unsigned char *tbs_val;
    unsigned long c1 = cert_asn1_read_tlv(p, remain, NULL, &tbs_vlen, &tbs_val);
    if (!c1)
        return 0;

    /* The full TBS encoding includes tag+length+value */
    *tbs = p;
    *tbs_len = c1;
    p += c1;
    remain -= c1;

    /* 2nd element: signatureAlgorithm */
    unsigned long c2 = cert_asn1_read_tlv(p, remain, NULL, NULL, NULL);
    if (!c2)
        return 0;
    p += c2;
    remain -= c2;

    /* 3rd element: signatureValue (BIT STRING) */
    unsigned long sig_vlen;
    const unsigned char *sig_val;
    unsigned long c3 = cert_asn1_read_tlv(p, remain, NULL, &sig_vlen, &sig_val);
    if (!c3 || sig_vlen < 1)
        return 0;

    /* BIT STRING: first byte is number of unused bits (should be 0) */
    *sig = sig_val + 1;
    *sig_len = sig_vlen - 1;

    (void)header_len;
    return 1;
}

/*
 * Verify the signature on `cert` using the public key from `issuer_cert`.
 * SM2 signature is computed over SM3(ZA || TBSCertificate).
 * For simplicity, we hash TBSCertificate directly with a default ZA.
 *
 * Returns 1 on success, 0 on failure.
 */
int tlcp_cert_verify_signature(const tlcp_cert_t *cert,
                               const tlcp_cert_t *issuer_cert) {
    if (!cert || !issuer_cert)
        return 0;
    if (!cert->der_len || !issuer_cert->has_pubkey)
        return 0;

    const unsigned char *tbs = NULL;
    unsigned long tbs_len = 0;
    const unsigned char *sig = NULL;
    unsigned long sig_len = 0;

    if (!cert_find_tbs_and_sig(cert->der, cert->der_len,
                               &tbs, &tbs_len, &sig, &sig_len))
        return 0;

    /* Need 64-byte raw signature (r || s) */
    if (sig_len < 64)
        return 0;

    /* Compute ZA for issuer */
    unsigned char za[32];
    unsigned char default_id[] = "1234567812345678";
    sm2_za(za, default_id, 16,
           (big_t *)&issuer_cert->pubkey_x,
           (big_t *)&issuer_cert->pubkey_y);

    /* Verify: SM2 signature over (hash of TBS), with ZA */
    return sm2_sign_verify((unsigned char *)sig,
                           (unsigned char *)tbs, tbs_len,
                           za,
                           &issuer_cert->pubkey_x,
                           &issuer_cert->pubkey_y);
}
