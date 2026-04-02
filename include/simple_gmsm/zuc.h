#ifndef GMSM_ZUC_H_
#define GMSM_ZUC_H_

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @file simple_gmsm/zuc.h
/// @brief ZUC 序列密码算法接口（GM/T 0001-2012）
///
/// 本文件提供 ZUC 序列密码的初始化、密钥流生成，
/// 以及 128-EEA3 机密性算法和 128-EIA3 完整性算法的接口定义。

/// @defgroup zuc ZUC 序列密码算法
/// @brief ZUC 序列密码相关接口，包含密钥流生成、128-EEA3 加密与 128-EIA3 完整性校验。
///
/// ZUC 是中国商用密码标准（GM/T 0001-2012）中规定的序列密码算法，
/// 广泛应用于 4G/5G 移动通信中的数据加密与完整性保护。
/// @{

/// @brief ZUC 算法状态结构体
/// @ingroup zuc
///
/// 保存 ZUC 算法运行时所需的线性反馈移位寄存器（LFSR）、
/// 有限状态机寄存器及工作变量。
typedef struct {
    unsigned int lfsr[16];   ///< 线性反馈移位寄存器 s0..s15（共 16 级）
    unsigned int r1, r2;     ///< 有限状态机（F 函数）寄存器 R1、R2
    unsigned int x[4];       ///< 工作变量 X0..X3
} zuc_state_t;

/// @brief 使用 128 位密钥和 128 位初始向量初始化 ZUC 状态
/// @ingroup zuc
///
/// @param state  指向待初始化的 ZUC 状态结构体的指针
/// @param key    128 位密钥（16 字节）
/// @param iv     128 位初始向量（16 字节）
///
/// @note key 和 iv 必须各为 16 字节，调用者需确保缓冲区大小正确。
/// @note 初始化完成后，可调用 zuc_generate() 或 zuc_generate_keystream() 生成密钥流。
/// @see zuc_generate
/// @see zuc_generate_keystream
/// @example example_zuc.c
void zuc_init(zuc_state_t* state, const unsigned char key[16], const unsigned char iv[16]);

/// @brief 生成一个 32 位密钥流字
/// @ingroup zuc
///
/// @param state  指向已初始化的 ZUC 状态结构体的指针
/// @return 生成的 32 位密钥流字
///
/// @note 调用前必须先通过 zuc_init() 完成初始化。
/// @see zuc_init
/// @see zuc_generate_keystream
unsigned int zuc_generate(zuc_state_t* state);

/// @brief 批量生成指定数量的 32 位密钥流字
/// @ingroup zuc
///
/// @param state     指向已初始化的 ZUC 状态结构体的指针
/// @param keystream 输出缓冲区，用于存放生成的密钥流字
/// @param nwords    需要生成的密钥流字数量
///
/// @note 调用者需确保 keystream 缓冲区至少能容纳 nwords 个 unsigned int。
/// @note 调用前必须先通过 zuc_init() 完成初始化。
/// @see zuc_init
/// @see zuc_generate
void zuc_generate_keystream(zuc_state_t* state, unsigned int* keystream, unsigned long nwords);

/// @brief 128-EEA3 机密性算法（加密/解密）
/// @ingroup zuc
///
/// 基于 ZUC 密钥流对比特流进行异或加密或解密，适用于 LTE/5G 用户面数据保护。
///
/// @param key       128 位密钥（16 字节）
/// @param count     32 位计数器（COUNT）
/// @param bearer    5 位承载标识（BEARER，取值 0~31）
/// @param direction 1 位传输方向（0 = 上行，1 = 下行）
/// @param input     输入比特流
/// @param output    输出比特流（可与 input 指向同一缓冲区）
/// @param bitlen    比特流长度（单位：比特）
///
/// @note key 必须为 16 字节；bearer 仅使用低 5 位；direction 仅使用最低位。
/// @see zuc_eia3
/// @see zuc_init
void zuc_eea3(const unsigned char key[16], unsigned int count,
              unsigned int bearer, unsigned int direction,
              const unsigned char* input, unsigned char* output,
              unsigned int bitlen);

/// @brief 128-EIA3 完整性算法（消息认证码计算）
/// @ingroup zuc
///
/// 基于 ZUC 密钥流计算 32 位消息认证码（MAC），适用于 LTE/5G 信令面完整性保护。
///
/// @param key       128 位密钥（16 字节）
/// @param count     32 位计数器（COUNT）
/// @param bearer    5 位承载标识（BEARER，取值 0~31）
/// @param direction 1 位传输方向（0 = 上行，1 = 下行）
/// @param message   输入消息比特流
/// @param bitlen    消息长度（单位：比特）
/// @return 计算得到的 32 位消息认证码（MAC）
///
/// @note key 必须为 16 字节；bearer 仅使用低 5 位；direction 仅使用最低位。
/// @see zuc_eea3
/// @see zuc_init
unsigned int zuc_eia3(const unsigned char key[16], unsigned int count,
                      unsigned int bearer, unsigned int direction,
                      const unsigned char* message, unsigned int bitlen);

/// @}

#ifdef __cplusplus
}
#endif

#endif // GMSM_ZUC_H_
