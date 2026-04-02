#ifndef GMSM_HMAC_SM3_H_
#define GMSM_HMAC_SM3_H_

#include "common.h"
#include "sm3.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @file simple_gmsm/hmac_sm3.h
/// @brief HMAC-SM3 消息认证码实现（基于 RFC 2104）
///
/// 本文件提供基于 SM3 哈希算法的 HMAC（散列消息认证码）接口，
/// 支持流式（init/update/finish）和一次性计算两种使用方式。

/// @defgroup hmac_sm3 HMAC-SM3 消息认证码
/// @brief 基于 SM3 哈希算法的 HMAC 实现
///
/// 提供符合 RFC 2104 标准的 HMAC-SM3 消息认证码算法，可用于数据完整性校验
/// 和消息认证。支持流式接口（init / update / finish）与一次性计算接口。
/// @{

/// @brief HMAC-SM3 上下文结构体
/// @ingroup hmac_sm3
typedef struct {
    sm3_context_t inner; ///< 内部哈希上下文（用于内层填充计算）
    sm3_context_t outer; ///< 外部哈希上下文（用于外层填充计算）
} hmac_sm3_context_t;

/// @brief 使用密钥初始化 HMAC-SM3 上下文
/// @ingroup hmac_sm3
/// @param ctx 指向 hmac_sm3_context_t 上下文的指针
/// @param key HMAC 密钥
/// @param keylen HMAC 密钥长度（字节）
/// @note 若密钥长度超过 64 字节，将先对密钥进行 SM3 哈希处理
/// @see hmac_sm3_update
/// @see hmac_sm3_finish
/// @see hmac_sm3
void hmac_sm3_init(hmac_sm3_context_t* ctx, const unsigned char* key,
                   unsigned long keylen);

/// @brief 向 HMAC 计算过程中输入数据
/// @ingroup hmac_sm3
/// @param ctx 指向 hmac_sm3_context_t 上下文的指针
/// @param data 待认证的数据
/// @param len 数据长度（字节）
/// @note 可多次调用以流式方式输入数据
/// @see hmac_sm3_init
/// @see hmac_sm3_finish
void hmac_sm3_update(hmac_sm3_context_t* ctx, const unsigned char* data,
                     unsigned long len);

/// @brief 完成 HMAC 计算并输出 32 字节消息认证码
/// @ingroup hmac_sm3
/// @param ctx 指向 hmac_sm3_context_t 上下文的指针
/// @param mac 输出缓冲区，长度必须至少为 32 字节
/// @note 输出固定为 32 字节（256 位）MAC 值
/// @see hmac_sm3_init
/// @see hmac_sm3_update
void hmac_sm3_finish(hmac_sm3_context_t* ctx, unsigned char mac[32]);

/// @brief 一次性计算 HMAC-SM3 消息认证码
/// @ingroup hmac_sm3
/// @param key HMAC 密钥
/// @param keylen HMAC 密钥长度（字节）
/// @param data 待认证的数据
/// @param datalen 数据长度（字节）
/// @param mac 输出缓冲区，长度必须至少为 32 字节
/// @note 输出固定为 32 字节（256 位）MAC 值
/// @note 若密钥长度超过 64 字节，将先对密钥进行 SM3 哈希处理
/// @see hmac_sm3_init
/// @see hmac_sm3_update
/// @see hmac_sm3_finish
/// @example example_hmac_sm3.c
void hmac_sm3(const unsigned char* key, unsigned long keylen,
              const unsigned char* data, unsigned long datalen,
              unsigned char mac[32]);

/// @}

#ifdef __cplusplus
}
#endif

#endif  // GMSM_HMAC_SM3_H_
