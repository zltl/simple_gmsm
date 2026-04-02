#ifndef GMSM_SM2_H_
#define GMSM_SM2_H_

/// @file simple_gmsm/sm2.h
/// @brief SM2 椭圆曲线公钥密码算法接口
///
/// @defgroup sm2 SM2 椭圆曲线公钥密码算法
/// @brief 提供 SM2 椭圆曲线公钥密码算法的完整实现，包括密钥生成、数字签名、
///        公钥加密/解密、密钥交换以及底层椭圆曲线点运算。
/// @details
/// SM2 是中国国家密码管理局发布的椭圆曲线公钥密码算法标准（GM/T 0003）。
/// 本模块实现了以下功能：
/// - 椭圆曲线点的加法、倍点、标量乘法等基本运算
/// - SM2 密钥对生成
/// - SM2 数字签名生成与验证
/// - SM2 公钥加密与解密
/// - SM2 密钥交换协议
///
/// @note 使用任何 SM2 函数之前，必须先调用 sm2_init() 初始化参数。
/// @note 使用完毕后，应调用 sm2_destroy() 释放资源。

#ifdef __cplusplus
extern "C" {
#endif

#include "big.h"
#include "common.h"

/// @addtogroup sm2
/// @{

// ---------------------------------------------------------------------------
/// @name SM2 曲线常量参数
/// @brief SM2 推荐椭圆曲线系统参数（GM/T 0003.5）
/// @{
// ---------------------------------------------------------------------------

/// @brief SM2 推荐曲线参数
/// @ingroup sm2
/// @details
/// - sm2_p: 素数域的素数 p
/// - sm2_a: 曲线方程系数 a
/// - sm2_b: 曲线方程系数 b
/// - sm2_n: 基点的阶 n
/// - sm2_gx: 基点 G 的 x 坐标
/// - sm2_gy: 基点 G 的 y 坐标
extern big_t sm2_p, sm2_a, sm2_b, sm2_n, sm2_gx, sm2_gy;

/// @brief 私钥最大值上界
/// @ingroup sm2
extern big_t sm2_d_max;

/// @brief 密钥交换协议中使用的辅助常量
/// @ingroup sm2
/// @details sm2_2w = 2^w, sm2_2w_1 = 2^w - 1，其中 w = ceil(ceil(log2(n)) / 2) - 1
extern big_t sm2_2w, sm2_2w_1;

/// @}

// ---------------------------------------------------------------------------
/// @name 初始化与销毁
/// @brief SM2 模块的生命周期管理
/// @{
// ---------------------------------------------------------------------------

/// @brief 初始化 SM2 参数，必须在调用任何其他 SM2 函数之前调用
/// @ingroup sm2
/// @note 该函数会初始化所有 SM2 曲线常量参数，整个程序生命周期内只需调用一次。
/// @see sm2_destroy
void sm2_init(void);

/// @brief 销毁 SM2 参数，释放相关资源
/// @ingroup sm2
/// @note 与 sm2_init() 成对使用，在不再需要 SM2 功能时调用。
/// @see sm2_init
void sm2_destroy(void);

/// @}

// ---------------------------------------------------------------------------
/// @name 椭圆曲线点运算
/// @brief SM2 椭圆曲线上的基本点运算（加法、倍点、标量乘法、坐标变换）
/// @{
// ---------------------------------------------------------------------------

/// @brief 椭圆曲线点加法
/// @ingroup sm2
/// @details 计算仿射坐标下的点加法: (x3, y3) = (x1, y1) + (x2, y2)
/// @param[out] x3 结果点的 x 坐标
/// @param[out] y3 结果点的 y 坐标
/// @param[in]  x1 第一个点的 x 坐标
/// @param[in]  y1 第一个点的 y 坐标
/// @param[in]  x2 第二个点的 x 坐标
/// @param[in]  y2 第二个点的 y 坐标
/// @note 输入点必须在 SM2 曲线上，否则结果未定义。
/// @see sm2_double, sm2_scalar_mult
void sm2_add(big_t* x3, big_t* y3, big_t* x1, big_t* y1, big_t* x2, big_t* y2);

/// @brief 生成 SM2 密钥对
/// @ingroup sm2
/// @param[out] d  私钥（随机生成，范围 [1, n-2]）
/// @param[out] Px 公钥的 x 坐标
/// @param[out] Py 公钥的 y 坐标
/// @note 公钥 P = d * G，其中 G 为 SM2 基点。
/// @see sm2_scalar_mult
void sm2_gen_key(big_t* d, big_t* Px, big_t* Py);

/// @brief 雅可比（Jacobian）坐标转换为仿射（Affine）坐标
/// @ingroup sm2
/// @param[out] xout 输出仿射坐标 x
/// @param[out] yout 输出仿射坐标 y
/// @param[in]  x    雅可比坐标 X
/// @param[in]  y    雅可比坐标 Y
/// @param[in]  z    雅可比坐标 Z
/// @note 转换公式: xout = X / Z^2, yout = Y / Z^3
/// @see sm2_double_jacobian
void sm2_jacobian_to_affine(big_t* xout, big_t* yout, const big_t* x,
                            const big_t* y, const big_t* z);

/// @brief 椭圆曲线点倍乘（仿射坐标）
/// @ingroup sm2
/// @details 计算 (x3, y3) = 2 * (x1, y1)
/// @param[out] x3 结果点的 x 坐标
/// @param[out] y3 结果点的 y 坐标
/// @param[in]  x1 输入点的 x 坐标
/// @param[in]  y1 输入点的 y 坐标
/// @see sm2_double_jacobian, sm2_add
void sm2_double(big_t* x3, big_t* y3, big_t* x1, big_t* y1);

/// @brief 椭圆曲线点倍乘（雅可比坐标）
/// @ingroup sm2
/// @details sm2_double() 的雅可比坐标版本，避免模逆运算以提高性能。
/// @param[out] x3 结果点的雅可比坐标 X
/// @param[out] y3 结果点的雅可比坐标 Y
/// @param[out] z3 结果点的雅可比坐标 Z
/// @param[in]  x1 输入点的雅可比坐标 X
/// @param[in]  y1 输入点的雅可比坐标 Y
/// @param[in]  z1 输入点的雅可比坐标 Z
/// @note 使用雅可比坐标可显著减少模逆运算次数。
/// @see sm2_double, sm2_jacobian_to_affine
void sm2_double_jacobian(big_t* x3, big_t* y3, big_t* z3, const big_t* x1,
                         const big_t* y1, const big_t* z1);

/// @brief 椭圆曲线标量乘法
/// @ingroup sm2
/// @details 计算 (x3, y3) = k * (bx, by)
/// @param[out] x3 结果点的 x 坐标
/// @param[out] y3 结果点的 y 坐标
/// @param[in]  bx 基点的 x 坐标
/// @param[in]  by 基点的 y 坐标
/// @param[in]  k  标量乘数
/// @note 这是 SM2 算法中最核心的运算，签名、加密、密钥交换等均依赖此函数。
/// @see sm2_add, sm2_double
void sm2_scalar_mult(big_t* x3, big_t* y3, const big_t* bx, const big_t* by,
                     const big_t* k);

/// @}

// ---------------------------------------------------------------------------
/// @name 辅助函数
/// @brief 密钥派生函数（KDF）、用户杂凑值（ZA）及曲线点判定
/// @{
// ---------------------------------------------------------------------------

/// @brief SM2 密钥派生函数（KDF），基于 SM3 杂凑算法
/// @ingroup sm2
/// @details 根据 GM/T 0003.4 规范，从共享信息中派生指定长度的密钥数据。
/// @param[out] k    输出的派生密钥数据
/// @param[in]  klen 需要派生的密钥长度（字节）
/// @param[in]  z    输入的共享信息
/// @param[in]  zlen 共享信息长度（字节）
/// @note 内部使用 SM3 杂凑算法进行迭代计算。
/// @see sm2_za
void sm2_kdf(unsigned char* k, unsigned int klen, unsigned char* z,
             unsigned int zlen);

/// @brief 计算用户杂凑值 ZA
/// @ingroup sm2
/// @details 根据 GM/T 0003 规范，由用户身份标识 ID 和公钥计算用户杂凑值。
///          ZA = SM3(ENTLA || IDA || a || b || gx || gy || px || py)
/// @param[out] z     输出的杂凑值（32 字节）
/// @param[in]  id    用户身份标识
/// @param[in]  idlen 用户身份标识的比特长度
/// @param[in]  px    用户公钥的 x 坐标
/// @param[in]  py    用户公钥的 y 坐标
/// @note ZA 用于签名和验签流程中，是消息摘要计算的前置步骤。
/// @see sm2_sign_generate, sm2_sign_verify, sm2_kdf
void sm2_za(unsigned char* z, unsigned char* id, unsigned int idlen, big_t* px,
            big_t* py);

/// @brief 判断点是否在 SM2 椭圆曲线上
/// @ingroup sm2
/// @param[in] x 点的 x 坐标
/// @param[in] y 点的 y 坐标
/// @return 非零值表示点在曲线上，0 表示不在曲线上
/// @see sm2_infinit_p
int sm2_on_curve_p(const big_t* x, const big_t* y);

/// @brief 判断点是否为无穷远点（零点）
/// @ingroup sm2
/// @param[in] x 点的 x 坐标
/// @param[in] y 点的 y 坐标
/// @return 非零值表示是无穷远点，0 表示不是
/// @see sm2_on_curve_p
int sm2_infinit_p(const big_t* x, const big_t* y);

/// @}

// ---------------------------------------------------------------------------
/// @name 密钥交换协议
/// @brief SM2 密钥交换协议（GM/T 0003.3），分为四个步骤完成双方密钥协商
/// @{
// ---------------------------------------------------------------------------

/// @brief 密钥交换协议第一步：发起方生成临时密钥对
/// @ingroup sm2
/// @param[out] rax 临时公钥的 x 坐标
/// @param[out] ray 临时公钥的 y 坐标
/// @param[out] ra  临时私钥
/// @note 发起方（A）调用此函数生成临时密钥对，并将临时公钥 (rax, ray) 发送给响应方（B）。
/// @see sm2_ke_2, sm2_ke_3, sm2_ke_opt_4
void sm2_ke_1(big_t* rax, big_t* ray, big_t* ra);

/// @brief 密钥交换协议第二步：响应方计算共享密钥及验证哈希
/// @ingroup sm2
/// @param[out] kb    响应方派生的共享密钥
/// @param[in]  kblen 共享密钥长度（字节）
/// @param[out] vx    响应方计算的椭圆曲线点 V 的 x 坐标
/// @param[out] vy    响应方计算的椭圆曲线点 V 的 y 坐标
/// @param[out] sb    响应方计算的验证哈希值 SB
/// @param[in]  rbx   响应方临时公钥的 x 坐标
/// @param[in]  rby   响应方临时公钥的 y 坐标
/// @param[in]  rb    响应方临时私钥
/// @param[in]  db    响应方长期私钥
/// @param[in]  rax   发起方临时公钥的 x 坐标
/// @param[in]  ray   发起方临时公钥的 y 坐标
/// @param[in]  pax   发起方长期公钥的 x 坐标
/// @param[in]  pay   发起方长期公钥的 y 坐标
/// @param[in]  za    发起方的用户杂凑值 ZA
/// @param[in]  zb    响应方的用户杂凑值 ZB
/// @param[in]  opt   可选标志位，控制是否计算可选的验证哈希
/// @return 0 表示成功，非零值表示失败
/// @note 响应方（B）调用此函数，并将 (rbx, rby, sb) 发送给发起方（A）。
/// @see sm2_ke_1, sm2_ke_3, sm2_ke_opt_4, sm2_za
int sm2_ke_2(unsigned char* kb, unsigned long kblen, big_t* vx, big_t* vy,
             unsigned char* sb, big_t* rbx, big_t* rby, big_t* rb, big_t* db,
             big_t* rax, big_t* ray, big_t* pax, big_t* pay, unsigned char* za,
             unsigned char* zb, int opt);

/// @brief 密钥交换协议第三步：发起方计算共享密钥并验证响应方
/// @ingroup sm2
/// @param[out] ka    发起方派生的共享密钥
/// @param[in]  kalen 共享密钥长度（字节）
/// @param[out] sa    发起方计算的验证哈希值 SA（可选）
/// @param[in]  sb    响应方提供的验证哈希值 SB
/// @param[in]  rax   发起方临时公钥的 x 坐标
/// @param[in]  ray   发起方临时公钥的 y 坐标
/// @param[in]  ra    发起方临时私钥
/// @param[in]  da    发起方长期私钥
/// @param[in]  rbx   响应方临时公钥的 x 坐标
/// @param[in]  rby   响应方临时公钥的 y 坐标
/// @param[in]  pbx   响应方长期公钥的 x 坐标
/// @param[in]  pby   响应方长期公钥的 y 坐标
/// @param[in]  za    发起方的用户杂凑值 ZA
/// @param[in]  zb    响应方的用户杂凑值 ZB
/// @param[in]  opt   可选标志位，控制是否计算可选的验证哈希 SA
/// @return 0 表示成功（含 SB 验证通过），非零值表示失败
/// @note 发起方（A）调用此函数验证 SB，并可选地将 SA 发送给响应方进行确认。
/// @see sm2_ke_1, sm2_ke_2, sm2_ke_opt_4, sm2_za
int sm2_ke_3(unsigned char* ka, unsigned long kalen, unsigned char* sa,
             unsigned char* sb, big_t* rax, big_t* ray, big_t* ra, big_t* da,
             big_t* rbx, big_t* rby, big_t* pbx, big_t* pby, unsigned char* za,
             unsigned char* zb, int opt);

/// @brief 密钥交换协议第四步（可选）：响应方验证发起方的确认哈希
/// @ingroup sm2
/// @param[in] sa  发起方提供的验证哈希值 SA
/// @param[in] vx  响应方在第二步中计算的椭圆曲线点 V 的 x 坐标
/// @param[in] vy  响应方在第二步中计算的椭圆曲线点 V 的 y 坐标
/// @param[in] za  发起方的用户杂凑值 ZA
/// @param[in] zb  响应方的用户杂凑值 ZB
/// @param[in] rax 发起方临时公钥的 x 坐标
/// @param[in] ray 发起方临时公钥的 y 坐标
/// @param[in] rbx 响应方临时公钥的 x 坐标
/// @param[in] rby 响应方临时公钥的 y 坐标
/// @return 0 表示验证通过，非零值表示验证失败
/// @note 此步骤为可选步骤，响应方（B）可通过此函数验证发起方的 SA 以完成双向认证。
/// @see sm2_ke_1, sm2_ke_2, sm2_ke_3
int sm2_ke_opt_4(unsigned char* sa, big_t* vx, big_t* vy, unsigned char* za,
                 unsigned char* zb, big_t* rax, big_t* ray, big_t* rbx,
                 big_t* rby);

/// @}

// ---------------------------------------------------------------------------
/// @name 数字签名
/// @brief SM2 数字签名生成与验证（GM/T 0003.2）
/// @{
// ---------------------------------------------------------------------------

/// @brief 生成 SM2 数字签名
/// @ingroup sm2
/// @param[out] sign 输出签名值（64 字节，前 32 字节为 r，后 32 字节为 s）
/// @param[in]  m    待签名的消息
/// @param[in]  mlen 消息长度（字节）
/// @param[in]  za   签名者的用户杂凑值 ZA
/// @param[in]  da   签名者的私钥
/// @note 签名前需先通过 sm2_za() 计算用户杂凑值 ZA。
/// @see sm2_sign_verify, sm2_za
/// @example example_sm2.c
void sm2_sign_generate(unsigned char* sign /*64byte*/, unsigned char* m,
                       unsigned long mlen, unsigned char* za, const big_t* da);

/// @brief 验证 SM2 数字签名
/// @ingroup sm2
/// @param[in] sign 待验证的签名值（64 字节）
/// @param[in] m    原始消息
/// @param[in] mlen 消息长度（字节）
/// @param[in] za   签名者的用户杂凑值 ZA
/// @param[in] pax  签名者公钥的 x 坐标
/// @param[in] pay  签名者公钥的 y 坐标
/// @return 0 表示签名验证通过，非零值表示验证失败
/// @note 验证方需使用与签名方相同的 ID 和公钥来计算 ZA。
/// @see sm2_sign_generate, sm2_za
int sm2_sign_verify(unsigned char* sign, unsigned char* m, unsigned long mlen,
                    unsigned char* za, const big_t* pax, const big_t* pay);

/// @}

// ---------------------------------------------------------------------------
/// @name 公钥加密与解密
/// @brief SM2 公钥加密与解密（GM/T 0003.4）
/// @{
// ---------------------------------------------------------------------------

/// @brief SM2 公钥加密
/// @ingroup sm2
/// @param[out] c     输出的密文数据
/// @param[in]  csize 密文缓冲区大小（字节）
/// @param[in]  m     待加密的明文数据
/// @param[in]  mlen  明文数据长度（字节）
/// @param[in]  px    接收方公钥的 x 坐标
/// @param[in]  py    接收方公钥的 y 坐标
/// @return 0 表示加密成功，非零值表示加密失败
/// @note 密文格式为 C1 || C3 || C2，其中 C1 为椭圆曲线点，C3 为 SM3 杂凑值，C2 为加密数据。
/// @see sm2_decrypt, sm2_kdf
int sm2_encrypt(unsigned char* c, unsigned long csize, unsigned char* m,
                unsigned long mlen, const big_t* px, const big_t* py);

/// @brief SM2 私钥解密
/// @ingroup sm2
/// @param[out] m     输出的明文数据
/// @param[in]  msize 明文缓冲区大小（字节）
/// @param[in]  c     待解密的密文数据
/// @param[in]  clen  密文数据长度（字节）
/// @param[in]  d     接收方的私钥
/// @return 0 表示解密成功，非零值表示解密失败（如密文被篡改）
/// @note 解密时会验证 C3 杂凑值以确保密文完整性。
/// @see sm2_encrypt, sm2_kdf
int sm2_decrypt(unsigned char* m, long msize, unsigned char* c, long clen,
                big_t* d);

/// @}

/// @} // end of addtogroup sm2

#ifdef __cplusplus
}
#endif

#endif  // GMSM_SM2_H_
