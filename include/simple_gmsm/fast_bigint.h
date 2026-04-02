#ifndef GMSM_FAST_BIGINT_H_
#define GMSM_FAST_BIGINT_H_

/// @file simple_gmsm/fast_bigint.h
/// @brief 高性能大数实现，使用机器字长进行运算。
/// @details 本文件提供了一套高性能的大数运算实现，使用 uint32_t 或 uint64_t
/// 作为内部存储单元（limb），并采用 Knuth Algorithm D 进行除法运算。
/// 在 64 位平台上自动使用 uint64_t + __uint128_t，在 32 位平台上使用
/// uint32_t + uint64_t。接口与 slow_dirty_bigint.h 完全兼容。

/// @defgroup bigint 大数运算实现
/// @brief 大数运算的具体实现，提供国密算法所需的全部大数操作。
/// @see big

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup bigint
/// @{

#ifndef SM_STATIC
#ifdef SM_SMALL_STACK
#define SM_STATIC static
#else
#define SM_STATIC
#endif
#endif

/// @def MAX_INT_BYTE
/// @brief 定义整数最大能占用的字节数，保持与 slow_dirty_bigint.h 兼容。
/// @ingroup bigint
#define MAX_INT_BYTE 70

#if defined(__SIZEOF_INT128__)
typedef uint64_t big_limb_t;
__extension__ typedef __uint128_t big_dlimb_t;
#define BIG_LIMB_BITS 64
#define BIG_LIMB_BYTES 8
/// 9 个 uint64_t = 72 字节, 足以容纳 70 字节的大数
#define BIG_LIMBS 9
#else
typedef uint32_t big_limb_t;
typedef uint64_t big_dlimb_t;
#define BIG_LIMB_BITS 32
#define BIG_LIMB_BYTES 4
/// 18 个 uint32_t = 72 字节, 足以容纳 70 字节的大数
#define BIG_LIMBS 18
#endif

/// @brief 定义大数的结构体 (limb-based, 小端序)。
/// @ingroup bigint
struct big_p {
    /// 符号: 0 表示零, 1 表示正数, -1 表示负数
    int sign;
    /// limb 数组, limbs[0] 为最低有效字
    big_limb_t limbs[BIG_LIMBS];
};
typedef struct big_p big_t;

/// @brief 初始化整数上下文。
/// @see big_finished
/// @ingroup bigint
void big_prepare(void);
/// @brief 反初始化整数上下文。
/// @see big_prepare
/// @ingroup bigint
void big_finished(void);

/// @brief 初始化大数对象。
/// @param[in,out] a 大数对象
/// @see big_destroy
/// @ingroup bigint
void big_init(big_t* a);
/// @brief 大数对象清理。
/// @param[in,out] a 大数对象
/// @see big_init
/// @ingroup bigint
void big_destroy(big_t* a);

/// @brief 整数 0
/// @ingroup bigint
extern big_t big_zero;
/// @brief 整数 1
/// @ingroup bigint
extern big_t big_one;
/// @brief 整数 2
/// @ingroup bigint
extern big_t big_two;
/// @brief 整数 3
/// @ingroup bigint
extern big_t big_three;

/// @brief 比较 a, b 的大小。
/// @return -1, 0, +1
/// @ingroup bigint
int big_cmp(const big_t* a, const big_t* b);

/// @brief 计算 c = a + b
/// @ingroup bigint
void big_add(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a - b
/// @ingroup bigint
void big_sub(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a * b
/// @ingroup bigint
void big_mul(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a / b
/// @ingroup bigint
void big_div(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a % b
/// @ingroup bigint
void big_mod(big_t* c, const big_t* a, const big_t* b);

/// @brief 计算模逆元 r = a^-1 mod p
/// @return 逆元存在返回非零值，不存在返回 0
/// @ingroup bigint
int big_inv(big_t* r, const big_t* a, const big_t* p);

/// @brief 从字节串导入大数 (大端序)。
/// @see big_to_bytes
/// @ingroup bigint
void big_from_bytes(big_t* a, unsigned char* buf, long buf_len);
/// @brief 导出大数为字节串 (大端序)。
/// @see big_from_bytes
/// @ingroup bigint
void big_to_bytes(unsigned char* buf, unsigned long* buf_len, const big_t* a);

/// @brief 复制大数 a <- b
/// @ingroup bigint
void big_set(big_t* a, const big_t* b);

/// @brief 交换大数。
/// @ingroup bigint
void big_swap(big_t* a, big_t* b);

/// @brief 生成随机大数，a <= [0, 2^n-1]
/// @ingroup bigint
void big_rand(big_t* a, unsigned long n);

/// @brief 判断大数是否为奇数。
/// @return 奇数返回 1，否则返回 0
/// @ingroup bigint
int big_odd_p(big_t* a);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* GMSM_FAST_BIGINT_H_ */
