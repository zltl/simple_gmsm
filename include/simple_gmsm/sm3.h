#ifndef GMSM_SM3_H_
#define GMSM_SM3_H_

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @file simple_gmsm/sm3.h
/// @brief SM3 hash function

/// sm3 上下文结构
struct sm3_context {
    unsigned int digest[8];
    unsigned long long length;  // 64 bit
    unsigned char unhandle[64];
    unsigned long long unhandle_len;
};

typedef struct sm3_context sm3_context_t;

/// @brief 初始化 sm3_context_t
/// @param ctx sm3_context_t
void sm3_init(sm3_context_t* ctx);
/// @brief 加入数据
/// @param ctx sm3_context_t
/// @param data 待加入的数据
/// @param len 待加入的数据长度
void sm3_update(sm3_context_t* ctx, const unsigned char* data,
                unsigned long len);
/// @brief 计算哈希结果
/// @param ctx sm3_context_t
/// @param sum 计算结果
void sm3_finish(sm3_context_t* ctx, unsigned char sum[32]);

/// @brief 计算 sm3(data[0..len]) -> sum
/// @param data 待计算的数据
/// @param len 待计算的数据长度
/// @param sum 计算结果
void sm3(const unsigned char* data, unsigned long len, unsigned char sum[32]);

#ifdef __cplusplus
}
#endif

#endif  // GMSM_SM3_H_