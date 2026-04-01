#ifndef GMSM_SM4_H_
#define GMSM_SM4_H_

#include "common.h"

/// @file simple_gmsm/sm4.h
/// @brief SM4 加密算法

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SCHEDULE 32

/// sm4 密钥结构
typedef struct SM4_KEY_st {
    unsigned int rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

/// @brief 设置密钥 key 到密钥结构 ks
/// @param[in] key 密钥
/// @param[out] ks 密钥结构
int sm4_set_key(const unsigned char* key, SM4_KEY* ks);

/// @brief 加密一个块
/// @param[in] in 待加密数据
/// @param[out] out 加密结果
/// @param[in] ks 密钥
void sm4_encrypt(const unsigned char* in, unsigned char* out,
                 const SM4_KEY* ks);
/// @brief 解密一个块
/// @param[in] in 待解密数据
/// @param[out] out 解密结果
/// @param[in] ks 密钥
void sm4_decrypt(const unsigned char* in, unsigned char* out,
                 const SM4_KEY* ks);

// ---- Block cipher modes ----

/// @brief SM4-CBC encrypt with PKCS#7 padding
/// @param[in] key 16-byte key
/// @param[in] iv 16-byte initialization vector
/// @param[in] in plaintext
/// @param[in] inlen plaintext length (any length, padding added)
/// @param[out] out ciphertext buffer (must be at least inlen + 16 bytes)
/// @param[out] outlen actual ciphertext length (multiple of 16)
/// @return 1 on success, 0 on failure
int sm4_cbc_encrypt(const unsigned char* key, const unsigned char* iv,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned long* outlen);

/// @brief SM4-CBC decrypt with PKCS#7 unpadding
/// @param[in] key 16-byte key
/// @param[in] iv 16-byte initialization vector
/// @param[in] in ciphertext (must be multiple of 16)
/// @param[in] inlen ciphertext length
/// @param[out] out plaintext buffer (at least inlen bytes)
/// @param[out] outlen actual plaintext length
/// @return 1 on success, 0 on failure (bad padding)
int sm4_cbc_decrypt(const unsigned char* key, const unsigned char* iv,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned long* outlen);

/// @brief SM4-CTR encrypt/decrypt (same operation)
/// @param[in] key 16-byte key
/// @param[in] nonce 16-byte initial counter block
/// @param[in] in input data
/// @param[in] len data length
/// @param[out] out output data (same length as input)
void sm4_ctr_encrypt(const unsigned char* key, const unsigned char* nonce,
                     const unsigned char* in, unsigned long len,
                     unsigned char* out);

/// @brief SM4-GCM encrypt
/// @param[in] key 16-byte key
/// @param[in] iv initialization vector
/// @param[in] ivlen IV length (typically 12)
/// @param[in] aad additional authenticated data
/// @param[in] aadlen AAD length
/// @param[in] in plaintext
/// @param[in] inlen plaintext length
/// @param[out] out ciphertext (same length as plaintext)
/// @param[out] tag 16-byte authentication tag
/// @return 1 on success
int sm4_gcm_encrypt(const unsigned char* key,
                    const unsigned char* iv, unsigned long ivlen,
                    const unsigned char* aad, unsigned long aadlen,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned char tag[16]);

/// @brief SM4-GCM decrypt
/// @param[in] key 16-byte key
/// @param[in] iv initialization vector
/// @param[in] ivlen IV length
/// @param[in] aad additional authenticated data
/// @param[in] aadlen AAD length
/// @param[in] in ciphertext
/// @param[in] inlen ciphertext length
/// @param[out] out plaintext (same length as ciphertext)
/// @param[in] tag 16-byte authentication tag to verify
/// @return 1 on success (tag valid), 0 on failure (tag mismatch)
int sm4_gcm_decrypt(const unsigned char* key,
                    const unsigned char* iv, unsigned long ivlen,
                    const unsigned char* aad, unsigned long aadlen,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, const unsigned char tag[16]);

#ifdef __cplusplus
}
#endif

#endif /* GMSM_SM4_H_ */
