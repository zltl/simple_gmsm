#ifndef GMSM_PORT_H_
#define GMSM_PORT_H_

/// @file simple_gmsm/slow_dirty_bigint.h
/// @brief 很慢的大数实现，建议改用 gmp 或者 mbedtls 的 bigint。
/// @details 本文件提供了一套简单但完整的大数运算实现，包括基本算术运算、
/// 模逆运算、字节串转换、随机数生成等功能。该实现以简洁为目标，
/// 性能较低，适合学习和测试用途。生产环境建议替换为 GMP 或 mbedTLS 的大数库。

/// @defgroup bigint 大数运算实现
/// @brief 大数运算的具体实现，提供国密算法所需的全部大数操作。
/// @details 本模块实现了大数的初始化、算术运算、比较、序列化以及随机数生成等功能。
/// 所有大数使用 @ref big_t 结构体表示，最大支持 @ref MAX_INT_BYTE 字节的整数。
/// @see big

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup bigint
/// @{

/// @def SM_SMALL_STACK
/// @brief 编译期定义这个宏定，使用较小的栈空间。 函数中的大数将被定义成
/// static , 优点是可以使用较小的栈， 缺点是不能用于多线程。 如果要使用多线程，
/// 请不要定义 SM_SMALL_STACK 。
/// @ingroup bigint

#ifndef SM_STATIC
#ifdef SM_SMALL_STACK
#define SM_STATIC static
#else
#define SM_STATIC
#endif  // SM_SMALL_STACK
#endif  // SM_STATIC

/// @def MAX_INT_BYTE
/// @brief 定义整数最大能占用的字节数。
/// @details 国密算法中都是 32 字节整数的运算，为了防止溢出，我们使用 70 字节。
/// @ingroup bigint
#define MAX_INT_BYTE 70

/// @brief 定义大数的结构体。
/// @ingroup bigint
struct big_p {
    /// 是否有符号
    int sign;
    /// 整数内容
    unsigned char num[MAX_INT_BYTE];
};
typedef struct big_p big_t;

/// @brief 初始化整数上下文。
/// @details 初始化整数上下文，在所有其他函数之前调用。 将初始化 big_zero,
/// big_one, 随机数种子等。
/// @see big_finished
/// @ingroup bigint
void big_prepare(void);
/// @brief 反初始化整数上下文，与 big_prepare() 对应。
/// @see big_prepare
/// @ingroup bigint
void big_finished(void);

/// @brief 初始化大数对象。
/// @details 初始化大数对象, big_t 结构初始化之后才能使用。
/// @param[in,out] a 大数对象
/// @see big_destroy
/// @ingroup bigint
void big_init(big_t* a);
/// @brief 大数对象清理。
/// @details 大数对象清理，清理之后不能再使用。
/// @param[in,out] a 大数对象
/// @note big_init() 过的 big_t 结构必须使用 big_destroy() 清理。
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
/// @param[in] a 大数对象
/// @param[in] b 大数对象
/// @return 比较结果：
///   - -1 表示 a < b
///   -  0 表示 a == b
///   - +1 表示 a > b
/// @ingroup bigint
int big_cmp(const big_t* a, const big_t* b);

/// @brief 计算 c = a + b
/// @param[in] a 大数对象
/// @param[in] b 大数对象
/// @param[out] c 大数对象, c = a + b 的结果
/// @ingroup bigint
void big_add(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a - b
/// @param[in] a 大数对象
/// @param[in] b 大数对象
/// @param[out] c 大数对象, c = a - b 的结果
/// @ingroup bigint
void big_sub(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a * b
/// @param[in] a 大数对象
/// @param[in] b 大数对象
/// @param[out] c 大数对象, c = a * b 的结果
/// @ingroup bigint
void big_mul(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a / b
/// @param[in] a 大数对象
/// @param[in] b 大数对象
/// @param[out] c 大数对象, c = a / b 的结果
/// @ingroup bigint
void big_div(big_t* c, const big_t* a, const big_t* b);
/// @brief 计算 c = a % b
/// @param[in] a 大数对象
/// @param[in] b 大数对象
/// @param[out] c 大数对象, c = a % b的结果
/// @ingroup bigint
void big_mod(big_t* c, const big_t* a, const big_t* b);

/// @brief 计算模 p 乘法逆元 r = a^-1 mod p
/// @param[in] a 大数对象
/// @param[in] p 大数对象
/// @param[out] r 大数对象, r = a^-1 mod p 的结果
/// @return 如果逆元存在返回非零值，如果逆元不存在则返回 0
/// @ingroup bigint
int big_inv(big_t* r, const big_t* a, const big_t* p);

/// @brief 从字节串导入大数。
/// @param[out] a 大数对象
/// @param[in] buf 字节串
/// @param[in] buf_len buf 长度
/// @see big_to_bytes
/// @ingroup bigint
void big_from_bytes(big_t* a, unsigned char* buf, long buf_len);
/// @brief 导出大数为字节串。
/// @param[out] buf 导出的字节串
/// @param[out] buf_len 导出的字节串长度
/// @param[in] a 要导出的大数对象
/// @note buf 的长度不小于 MAX_INT_BYTE
/// @see big_from_bytes
/// @ingroup bigint
void big_to_bytes(unsigned char* buf, unsigned long* buf_len, const big_t* a);

/// @brief 复制大数 a <- b
/// @param[out] a 大数对象
/// @param[in] b 大数对象
/// @ingroup bigint
void big_set(big_t* a, const big_t* b);

/// @brief 交换大数。
/// @param[in,out] a 大数对象
/// @param[in,out] b 大数对象
/// @ingroup bigint
void big_swap(big_t* a, big_t* b);

/// @brief 生成随机大数，a <= [0, 2^n-1]
/// @param[out] a 大数对象
/// @param[in] n 位数
/// @ingroup bigint
void big_rand(big_t* a, unsigned long n);

/// @brief 判断大数是否为奇数。
/// @param[in] a 大数对象
/// @return 如果为奇数返回 1，否则返回 0
/// @ingroup bigint
int big_odd_p(big_t* a);

/// @}

#ifdef __cplusplus
}
#endif

#endif  // GMSM_PORT_H_
