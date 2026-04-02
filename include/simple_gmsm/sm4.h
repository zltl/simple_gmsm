#ifndef GMSM_SM4_H_
#define GMSM_SM4_H_

#include "common.h"

/// @file simple_gmsm/sm4.h
/// @brief SM4 分组密码算法，提供 ECB、CBC、CTR、GCM 等加解密接口
///
/// @defgroup sm4 SM4 分组密码算法
/// @brief 国密 SM4 对称分组密码算法实现，分组长度与密钥长度均为 128 位（16 字节），
///        支持 ECB（单块加解密）、CBC、CTR、GCM 等工作模式。

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup sm4
/// @{

/// @brief SM4 分组大小（字节）
/// @ingroup sm4
/// @note SM4 的分组固定为 128 位，即 16 字节
#define SM4_BLOCK_SIZE 16

/// @brief SM4 轮密钥数量
/// @ingroup sm4
/// @note SM4 共进行 32 轮迭代变换，因此需要 32 个轮密钥
#define SM4_KEY_SCHEDULE 32

/// @brief SM4 密钥结构，存储密钥扩展后的轮密钥
/// @ingroup sm4
typedef struct SM4_KEY_st {
    unsigned int rk[SM4_KEY_SCHEDULE]; ///< 32 个轮密钥，由密钥扩展算法生成
} SM4_KEY;

/// @brief 设置密钥 key 到密钥结构 ks，执行密钥扩展算法
/// @ingroup sm4
/// @param[in] key 密钥，长度必须为 16 字节
/// @param[out] ks 密钥结构，存储扩展后的 32 个轮密钥
/// @return 成功返回 1，失败返回 0
/// @note 密钥长度固定为 SM4_BLOCK_SIZE（16 字节），调用方须保证 key 指向的缓冲区不小于 16 字节
/// @see sm4_encrypt
/// @see sm4_decrypt
int sm4_set_key(const unsigned char* key, SM4_KEY* ks);

/// @brief 使用 SM4 算法加密单个分组（16 字节）
/// @ingroup sm4
/// @param[in] in 待加密数据，长度为 SM4_BLOCK_SIZE（16 字节）
/// @param[out] out 加密结果，长度为 SM4_BLOCK_SIZE（16 字节）
/// @param[in] ks 密钥结构，须通过 sm4_set_key() 初始化
/// @note in 和 out 的长度均固定为 16 字节，不支持任意长度数据，如需处理任意长度请使用 CBC/CTR/GCM 等模式
/// @see sm4_decrypt
/// @see sm4_set_key
void sm4_encrypt(const unsigned char* in, unsigned char* out,
                 const SM4_KEY* ks);

/// @brief 使用 SM4 算法解密单个分组（16 字节）
/// @ingroup sm4
/// @param[in] in 待解密数据，长度为 SM4_BLOCK_SIZE（16 字节）
/// @param[out] out 解密结果，长度为 SM4_BLOCK_SIZE（16 字节）
/// @param[in] ks 密钥结构，须通过 sm4_set_key() 初始化
/// @note in 和 out 的长度均固定为 16 字节
/// @see sm4_encrypt
/// @see sm4_set_key
void sm4_decrypt(const unsigned char* in, unsigned char* out,
                 const SM4_KEY* ks);

// ---- 分组密码工作模式 ----

/// @brief SM4-CBC 模式加密，使用 PKCS#7 填充
/// @ingroup sm4
/// @param[in] key 密钥，长度为 16 字节
/// @param[in] iv 初始化向量，长度为 16 字节
/// @param[in] in 明文数据
/// @param[in] inlen 明文长度（任意长度，自动添加 PKCS#7 填充）
/// @param[out] out 密文输出缓冲区（至少需要 inlen + 16 字节）
/// @param[out] outlen 实际密文长度（为 16 的整数倍）
/// @return 成功返回 1，失败返回 0
/// @note 密文长度始终为 16 的整数倍，最多比明文长 16 字节；iv 在加密过程中不会被修改
/// @see sm4_cbc_decrypt
/// @example example_sm4.c
int sm4_cbc_encrypt(const unsigned char* key, const unsigned char* iv,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned long* outlen);

/// @brief SM4-CBC 模式解密，自动去除 PKCS#7 填充
/// @ingroup sm4
/// @param[in] key 密钥，长度为 16 字节
/// @param[in] iv 初始化向量，长度为 16 字节
/// @param[in] in 密文数据（长度必须为 16 的整数倍）
/// @param[in] inlen 密文长度
/// @param[out] out 明文输出缓冲区（至少需要 inlen 字节）
/// @param[out] outlen 实际明文长度
/// @return 成功返回 1，填充无效时返回 0
/// @note 如果密文被篡改或密钥/IV 不正确，PKCS#7 去填充可能失败并返回 0
/// @see sm4_cbc_encrypt
int sm4_cbc_decrypt(const unsigned char* key, const unsigned char* iv,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned long* outlen);

/// @brief SM4-CTR 模式加密/解密（加密与解密操作相同）
/// @ingroup sm4
/// @param[in] key 密钥，长度为 16 字节
/// @param[in] nonce 初始计数器块，长度为 16 字节
/// @param[in] in 输入数据（明文或密文）
/// @param[in] len 数据长度
/// @param[out] out 输出数据（与输入等长）
/// @note CTR 模式下加密与解密为同一操作；nonce 不可重复使用，否则会严重影响安全性
/// @see sm4_cbc_encrypt
/// @see sm4_gcm_encrypt
void sm4_ctr_encrypt(const unsigned char* key, const unsigned char* nonce,
                     const unsigned char* in, unsigned long len,
                     unsigned char* out);

/// @brief SM4-GCM 模式认证加密
/// @ingroup sm4
/// @param[in] key 密钥，长度为 16 字节
/// @param[in] iv 初始化向量
/// @param[in] ivlen IV 长度（通常为 12 字节）
/// @param[in] aad 附加认证数据（可为 NULL）
/// @param[in] aadlen 附加认证数据长度
/// @param[in] in 明文数据
/// @param[in] inlen 明文长度
/// @param[out] out 密文输出（与明文等长）
/// @param[out] tag 16 字节认证标签
/// @return 成功返回 1
/// @note GCM 模式同时提供加密和完整性保护；IV 推荐使用 12 字节，且不可重复使用
/// @see sm4_gcm_decrypt
int sm4_gcm_encrypt(const unsigned char* key,
                    const unsigned char* iv, unsigned long ivlen,
                    const unsigned char* aad, unsigned long aadlen,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, unsigned char tag[16]);

/// @brief SM4-GCM 模式认证解密
/// @ingroup sm4
/// @param[in] key 密钥，长度为 16 字节
/// @param[in] iv 初始化向量
/// @param[in] ivlen IV 长度
/// @param[in] aad 附加认证数据（可为 NULL）
/// @param[in] aadlen 附加认证数据长度
/// @param[in] in 密文数据
/// @param[in] inlen 密文长度
/// @param[out] out 明文输出（与密文等长）
/// @param[in] tag 待验证的 16 字节认证标签
/// @return 认证成功返回 1，认证标签不匹配返回 0
/// @note 若认证失败（返回 0），out 中的数据不应被使用
/// @see sm4_gcm_encrypt
int sm4_gcm_decrypt(const unsigned char* key,
                    const unsigned char* iv, unsigned long ivlen,
                    const unsigned char* aad, unsigned long aadlen,
                    const unsigned char* in, unsigned long inlen,
                    unsigned char* out, const unsigned char tag[16]);

/// @} // end of sm4

#ifdef __cplusplus
}
#endif

#endif /* GMSM_SM4_H_ */
