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

#ifdef __cplusplus
}
#endif

#endif /* GMSM_SM4_H_ */
