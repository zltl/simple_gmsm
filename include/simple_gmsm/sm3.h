#ifndef GMSM_SM3_H_
#define GMSM_SM3_H_

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @file simple_gmsm/sm3.h
/// @brief SM3 密码杂凑算法接口定义
/// @defgroup sm3 SM3 哈希算法
/// SM3 是中国国家密码管理局发布的密码杂凑算法标准（GB/T 32905-2016），
/// 输出 256 位（32 字节）哈希值。本模块提供增量式和一次性两种计算方式。

/// @addtogroup sm3
/// @{

/// @brief SM3 哈希计算上下文结构
/// @ingroup sm3
///
/// 保存 SM3 增量计算过程中的中间状态，配合 sm3_init、sm3_update、sm3_finish 使用。
/// @note 使用前必须调用 sm3_init 进行初始化。
/// @see sm3_init, sm3_update, sm3_finish
struct sm3_context {
    unsigned int digest[8];         ///< 当前哈希中间值（8 × 32 位）
    unsigned long long length;      ///< 已处理的数据总长度（单位：字节）
    unsigned char unhandle[64];     ///< 未凑满一个分组（64 字节）的缓冲区
    unsigned long long unhandle_len; ///< 缓冲区中待处理数据的长度
};

typedef struct sm3_context sm3_context_t;

/// @brief 初始化 SM3 上下文
/// @ingroup sm3
///
/// 将上下文重置为初始状态，设置 SM3 算法规定的初始哈希值。
/// 每次开始新的哈希计算前都必须调用此函数。
///
/// @param ctx 指向待初始化的 SM3 上下文结构体
/// @note 同一 ctx 可重复调用此函数以开始新的哈希计算。
/// @see sm3_update, sm3_finish
void sm3_init(sm3_context_t* ctx);

/// @brief 向 SM3 上下文中追加待哈希数据
/// @ingroup sm3
///
/// 可多次调用以分批输入数据，适用于大文件或流式数据场景。
///
/// @param ctx  指向已初始化的 SM3 上下文结构体
/// @param data 指向待追加数据的缓冲区
/// @param len  待追加数据的字节长度
/// @note 调用前需确保 ctx 已通过 sm3_init 初始化。
/// @see sm3_init, sm3_finish
void sm3_update(sm3_context_t* ctx, const unsigned char* data,
                unsigned long len);

/// @brief 完成 SM3 计算并输出哈希值
/// @ingroup sm3
///
/// 对剩余未处理的数据进行填充和最终压缩，将 32 字节哈希结果写入 sum。
/// 调用后 ctx 不应再用于 sm3_update，如需重新计算应重新调用 sm3_init。
///
/// @param ctx 指向已更新数据的 SM3 上下文结构体
/// @param sum 输出缓冲区，至少 32 字节，用于存放最终哈希值
/// @note 调用完成后，如需计算新数据的哈希，请重新调用 sm3_init。
/// @see sm3_init, sm3_update
void sm3_finish(sm3_context_t* ctx, unsigned char sum[32]);

/// @brief 一次性计算数据的 SM3 哈希值
/// @ingroup sm3
///
/// 等价于依次调用 sm3_init、sm3_update、sm3_finish 的便捷函数。
/// 适用于数据已全部在内存中的简单场景。
///
/// @param data 指向待计算哈希的数据
/// @param len  数据的字节长度
/// @param sum  输出缓冲区，至少 32 字节，用于存放最终哈希值
/// @note 对于需要分批输入数据的场景，请使用 sm3_init / sm3_update / sm3_finish 组合。
/// @see sm3_init, sm3_update, sm3_finish
/// @example example_sm3.c
void sm3(const unsigned char* data, unsigned long len, unsigned char sum[32]);

/// @}

#ifdef __cplusplus
}
#endif

#endif  // GMSM_SM3_H_