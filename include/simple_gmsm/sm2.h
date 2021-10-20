#ifndef GMSM_SM2_H_
#define GMSM_SM2_H_

/// @file simple_gmsm/sm2.h
/// @brief SM2 algorithm

#ifdef __cplusplus
extern "C" {
#endif

#include "big.h"
#include "common.h"

/// @brief SM2 contant parameters
extern big_t sm2_p, sm2_a, sm2_b, sm2_n, sm2_gx, sm2_gy;
extern big_t sm2_d_max;
extern big_t sm2_2w, sm2_2w_1;

/// @brief 初始化 sm3 参数， 任何其他函数之前调用
void sm2_init(void);
/// @brief 与 sm2_init 相对
void sm2_destroy(void);
/// @brief 曲线相加
/// @details (x3, y3) = (x1, y1) + (x2, y2)
void sm2_add(big_t* x3, big_t* y3, big_t* x1, big_t* y1, big_t* x2, big_t* y2);
/// @brief 生成 sm2 密钥
/// @param[out] d 密钥
/// @param[out] Px 公钥 x
/// @param[out] Py 公钥 y
void sm2_gen_key(big_t* d, big_t* Px, big_t* Py);
/// @brief 雅可比坐标转换为笛卡尔坐标
void sm2_jacobian_to_affine(big_t* xout, big_t* yout, const big_t* x,
                            const big_t* y, const big_t* z);
/// @brief (x3, y3) = 2(x1, y1)
void sm2_double(big_t* x3, big_t* y3, big_t* x1, big_t* y1);
/// @brief sm2_double() 的雅可比坐标版本
void sm2_double_jacobian(big_t* x3, big_t* y3, big_t* z3, const big_t* x1,
                         const big_t* y1, const big_t* z1);
/// @brief (x3, y3) = k(bx, by)
void sm2_scalar_mult(big_t* x3, big_t* y3, const big_t* bx, const big_t* by,
                     const big_t* k);

/// kdf
void sm2_kdf(unsigned char* k, unsigned int klen, unsigned char* z,
             unsigned int zlen);
/// za
void sm2_za(unsigned char* z, unsigned char* id, unsigned int idlen, big_t* px,
            big_t* py);
/// 判断是否在曲线上
int sm2_on_curve_p(const big_t* x, const big_t* y);
/// 判断是否无穷点
int sm2_infinit_p(const big_t* x, const big_t* y);

/// @brief 密钥交换第一步
void sm2_ke_1(big_t* rax, big_t* ray, big_t* ra);
/// 密钥交换第二步
int sm2_ke_2(unsigned char* kb, unsigned long kblen, big_t* vx, big_t* vy,
             unsigned char* sb, big_t* rbx, big_t* rby, big_t* rb, big_t* db,
             big_t* rax, big_t* ray, big_t* pax, big_t* pay, unsigned char* za,
             unsigned char* zb, int opt);
/// 密钥交换第三步
int sm2_ke_3(unsigned char* ka, unsigned long kalen, unsigned char* sa,
             unsigned char* sb, big_t* rax, big_t* ray, big_t* ra, big_t* da,
             big_t* rbx, big_t* rby, big_t* pbx, big_t* pby, unsigned char* za,
             unsigned char* zb, int opt);
/// 密钥交换第四步
int sm2_ke_opt_4(unsigned char* sa, big_t* vx, big_t* vy, unsigned char* za,
                 unsigned char* zb, big_t* rax, big_t* ray, big_t* rbx,
                 big_t* rby);

/// 签名
void sm2_sign_generate(unsigned char* sign /*64byte*/, unsigned char* m,
                       unsigned long mlen, unsigned char* za, const big_t* da);
/// 验证签名
int sm2_sign_verify(unsigned char* sign, unsigned char* m, unsigned long mlen,
                    unsigned char* za, const big_t* pax, const big_t* pay);

// 加密
int sm2_encrypt(unsigned char* c, unsigned long csize, unsigned char* m,
                unsigned long mlen, const big_t* px, const big_t* py);
/// 解密
int sm2_decrypt(unsigned char* m, long msize, unsigned char* c, long clen,
                big_t* d);

#ifdef __cplusplus
}
#endif

#endif  // GMSM_SM3_H_
