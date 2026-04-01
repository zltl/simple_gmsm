#include "test_common.h"
#include "simple_gmsm/sm4.h"

/* GB/T 32907-2016 standard test vector */
static const unsigned char tv_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const unsigned char tv_plain[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const unsigned char tv_cipher[16] = {
    0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
    0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
};

/* Result after 1,000,000 rounds of encryption */
static const unsigned char tv_million[16] = {
    0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F,
    0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66
};

TEST_CASE(test_sm4_encrypt) {
    SM4_KEY ks;
    unsigned char out[16];
    sm4_set_key(tv_key, &ks);
    sm4_encrypt(tv_plain, out, &ks);
    ASSERT_MEM_EQ(out, tv_cipher, 16);
}

TEST_CASE(test_sm4_decrypt) {
    SM4_KEY ks;
    unsigned char out[16];
    sm4_set_key(tv_key, &ks);
    sm4_decrypt(tv_cipher, out, &ks);
    ASSERT_MEM_EQ(out, tv_plain, 16);
}

TEST_CASE(test_sm4_encrypt_decrypt_roundtrip) {
    SM4_KEY ks;
    unsigned char encrypted[16], decrypted[16];
    sm4_set_key(tv_key, &ks);
    sm4_encrypt(tv_plain, encrypted, &ks);
    sm4_decrypt(encrypted, decrypted, &ks);
    ASSERT_MEM_EQ(decrypted, tv_plain, 16);
}

TEST_CASE(test_sm4_1000_rounds) {
    /* Fast variant: 1000 rounds of encryption */
    SM4_KEY ks;
    sm4_set_key(tv_key, &ks);
    unsigned char buf[16];
    memcpy(buf, tv_plain, 16);
    for (int i = 0; i < 1000; i++) {
        unsigned char tmp[16];
        sm4_encrypt(buf, tmp, &ks);
        memcpy(buf, tmp, 16);
    }
    /* We don't have a reference for 1000 rounds, just verify it's deterministic
       by doing it again */
    unsigned char buf2[16];
    memcpy(buf2, tv_plain, 16);
    for (int i = 0; i < 1000; i++) {
        unsigned char tmp[16];
        sm4_encrypt(buf2, tmp, &ks);
        memcpy(buf2, tmp, 16);
    }
    ASSERT_MEM_EQ(buf, buf2, 16);
}

TEST_CASE(test_sm4_million_rounds) {
    /* GB/T 32907-2016: 1,000,000 rounds of encryption */
    SM4_KEY ks;
    sm4_set_key(tv_key, &ks);
    unsigned char buf[16];
    memcpy(buf, tv_plain, 16);
    for (int i = 0; i < 1000000; i++) {
        unsigned char tmp[16];
        sm4_encrypt(buf, tmp, &ks);
        memcpy(buf, tmp, 16);
    }
    ASSERT_MEM_EQ(buf, tv_million, 16);
}

/* ---- CBC tests ---- */

TEST_CASE(test_sm4_cbc_roundtrip) {
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    const unsigned char plain[] = "Hello, SM4-CBC mode test!";
    unsigned long plainlen = sizeof(plain) - 1; /* 25 bytes */
    unsigned char ct[48];
    unsigned char pt[48];
    unsigned long ctlen = 0, ptlen = 0;

    ASSERT_TRUE(sm4_cbc_encrypt(key, iv, plain, plainlen, ct, &ctlen));
    ASSERT_EQ(ctlen, 32UL); /* 25 -> padded to 32 */
    ASSERT_TRUE(sm4_cbc_decrypt(key, iv, ct, ctlen, pt, &ptlen));
    ASSERT_EQ(ptlen, plainlen);
    ASSERT_MEM_EQ(pt, plain, plainlen);
}

TEST_CASE(test_sm4_cbc_block_aligned) {
    /* Input exactly 16 bytes: PKCS#7 adds full block of 0x10 */
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[16] = {0};
    const unsigned char plain[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };
    unsigned char ct[48];
    unsigned char pt[48];
    unsigned long ctlen = 0, ptlen = 0;

    ASSERT_TRUE(sm4_cbc_encrypt(key, iv, plain, 16, ct, &ctlen));
    ASSERT_EQ(ctlen, 32UL); /* 16 + 16 padding */
    ASSERT_TRUE(sm4_cbc_decrypt(key, iv, ct, ctlen, pt, &ptlen));
    ASSERT_EQ(ptlen, 16UL);
    ASSERT_MEM_EQ(pt, plain, 16);
}

TEST_CASE(test_sm4_cbc_empty) {
    const unsigned char key[16] = {0};
    const unsigned char iv[16] = {0};
    unsigned char ct[16];
    unsigned char pt[16];
    unsigned long ctlen = 0, ptlen = 0;

    ASSERT_TRUE(sm4_cbc_encrypt(key, iv, NULL, 0, ct, &ctlen));
    ASSERT_EQ(ctlen, 16UL); /* Even empty input gets one padding block */
    ASSERT_TRUE(sm4_cbc_decrypt(key, iv, ct, ctlen, pt, &ptlen));
    ASSERT_EQ(ptlen, 0UL);
}

/* ---- CTR tests ---- */

TEST_CASE(test_sm4_ctr_roundtrip) {
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char nonce[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    const unsigned char plain[] = "CTR mode encrypts any length!";
    unsigned long len = sizeof(plain) - 1;
    unsigned char ct[64], pt[64];

    sm4_ctr_encrypt(key, nonce, plain, len, ct);
    /* Ciphertext should differ from plaintext */
    ASSERT_TRUE(memcmp(ct, plain, len) != 0);
    /* Decrypt: same operation */
    sm4_ctr_encrypt(key, nonce, ct, len, pt);
    ASSERT_MEM_EQ(pt, plain, len);
}

TEST_CASE(test_sm4_ctr_empty) {
    const unsigned char key[16] = {0};
    const unsigned char nonce[16] = {0};
    unsigned char ct[1];
    sm4_ctr_encrypt(key, nonce, NULL, 0, ct);
    /* No crash on empty input */
}

/* ---- GCM tests ---- */

TEST_CASE(test_sm4_gcm_roundtrip) {
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B
    };
    const unsigned char plain[] = "GCM mode test data for SM4!";
    unsigned long len = sizeof(plain) - 1;
    unsigned char ct[64], pt[64], tag[16];

    ASSERT_TRUE(sm4_gcm_encrypt(key, iv, 12, NULL, 0,
                                plain, len, ct, tag));
    ASSERT_TRUE(sm4_gcm_decrypt(key, iv, 12, NULL, 0,
                                ct, len, pt, tag));
    ASSERT_MEM_EQ(pt, plain, len);
}

TEST_CASE(test_sm4_gcm_with_aad) {
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B
    };
    const unsigned char aad[] = "additional authenticated data";
    unsigned long aadlen = sizeof(aad) - 1;
    const unsigned char plain[] = "secret message";
    unsigned long len = sizeof(plain) - 1;
    unsigned char ct[64], pt[64], tag[16];

    ASSERT_TRUE(sm4_gcm_encrypt(key, iv, 12, aad, aadlen,
                                plain, len, ct, tag));
    ASSERT_TRUE(sm4_gcm_decrypt(key, iv, 12, aad, aadlen,
                                ct, len, pt, tag));
    ASSERT_MEM_EQ(pt, plain, len);
}

TEST_CASE(test_sm4_gcm_tag_failure) {
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B
    };
    const unsigned char plain[] = "tamper test";
    unsigned long len = sizeof(plain) - 1;
    unsigned char ct[64], pt[64], tag[16];

    ASSERT_TRUE(sm4_gcm_encrypt(key, iv, 12, NULL, 0,
                                plain, len, ct, tag));
    /* Tamper with ciphertext */
    ct[0] ^= 0xFF;
    ASSERT_FALSE(sm4_gcm_decrypt(key, iv, 12, NULL, 0,
                                 ct, len, pt, tag));
}

TEST_CASE(test_sm4_gcm_empty_plaintext) {
    /* GCM with AAD only, no plaintext (authentication-only) */
    const unsigned char key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    const unsigned char iv[12] = {0x00,0x01,0x02,0x03,0x04,0x05,
                                  0x06,0x07,0x08,0x09,0x0A,0x0B};
    const unsigned char aad[] = "auth only, no encryption";
    unsigned long aadlen = sizeof(aad) - 1;
    unsigned char tag[16], tag2[16];

    ASSERT_TRUE(sm4_gcm_encrypt(key, iv, 12, aad, aadlen,
                                NULL, 0, NULL, tag));
    /* Verify tag is deterministic */
    ASSERT_TRUE(sm4_gcm_encrypt(key, iv, 12, aad, aadlen,
                                NULL, 0, NULL, tag2));
    ASSERT_MEM_EQ(tag, tag2, 16);
    /* Verify decryption succeeds */
    ASSERT_TRUE(sm4_gcm_decrypt(key, iv, 12, aad, aadlen,
                                NULL, 0, NULL, tag));
}

void test_sm4_suite(void) {
    TEST_SUITE("SM4 Block Cipher");
    RUN_TEST(test_sm4_encrypt);
    RUN_TEST(test_sm4_decrypt);
    RUN_TEST(test_sm4_encrypt_decrypt_roundtrip);
    RUN_TEST(test_sm4_1000_rounds);
    RUN_TEST(test_sm4_million_rounds);
    RUN_TEST(test_sm4_cbc_roundtrip);
    RUN_TEST(test_sm4_cbc_block_aligned);
    RUN_TEST(test_sm4_cbc_empty);
    RUN_TEST(test_sm4_ctr_roundtrip);
    RUN_TEST(test_sm4_ctr_empty);
    RUN_TEST(test_sm4_gcm_roundtrip);
    RUN_TEST(test_sm4_gcm_with_aad);
    RUN_TEST(test_sm4_gcm_tag_failure);
    RUN_TEST(test_sm4_gcm_empty_plaintext);
}
