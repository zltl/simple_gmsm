#ifndef GMSM_SM9_H_
#define GMSM_SM9_H_

/// @file simple_gmsm/sm9.h
/// @brief SM9 标识密码算法（GB/T 38635）
///
/// @defgroup sm9 SM9 标识密码算法
/// @brief SM9 基于双线性对的标识密码算法，包含签名、加密、密钥交换等功能。
/// @details SM9 是中国国家密码管理局发布的标识密码算法标准（GB/T 38635），
///          基于 BN 曲线上的双线性对构造，支持：
///          - 数字签名与验签
///          - 基于 KEM-DEM 的公钥加密与解密
///          - 双方密钥交换协议
///          - 用户密钥提取（从主密钥派生用户私钥）

#ifdef __cplusplus
extern "C" {
#endif

#include "big.h"
#include "common.h"

/// @addtogroup sm9
/// @{

/* ── 扩域元素类型 ─────────────────────────────────────────────────── */

/// @brief Fp2 扩域元素：Fp[u]/(u²+1)，表示为 (a0 + a1·u)
/// @ingroup sm9
typedef struct {
    big_t a0; ///< 实部分量
    big_t a1; ///< 虚部分量（u 的系数）
} fp2_t;

/// @brief Fp4 扩域元素：Fp2[v]/(v²−u)，表示为 (a0 + a1·v)
/// @ingroup sm9
typedef struct {
    fp2_t a0; ///< 常数项（Fp2 元素）
    fp2_t a1; ///< v 的系数（Fp2 元素）
} fp4_t;

/// @brief Fp12 扩域元素：Fp4[w]/(w³−v)，表示为 (a0 + a1·w + a2·w²)
/// @ingroup sm9
typedef struct {
    fp4_t a0; ///< 常数项（Fp4 元素）
    fp4_t a1; ///< w 的系数（Fp4 元素）
    fp4_t a2; ///< w² 的系数（Fp4 元素）
} fp12_t;

/* ── 曲线点类型 ───────────────────────────────────────────────────── */

/// @brief G1 群上的点，位于曲线 E(Fp): y² = x³ + 5
/// @ingroup sm9
typedef struct {
    big_t x; ///< 仿射坐标 x
    big_t y; ///< 仿射坐标 y
} sm9_g1_t;

/// @brief G2 群上的点，位于扭曲线 E'(Fp2)
/// @ingroup sm9
typedef struct {
    fp2_t x; ///< 仿射坐标 x（Fp2 元素）
    fp2_t y; ///< 仿射坐标 y（Fp2 元素）
} sm9_g2_t;

/* ── 密钥类型 ─────────────────────────────────────────────────────── */

/// @brief SM9 签名主密钥对
/// @ingroup sm9
typedef struct {
    big_t  ks;      ///< 签名主私钥（随机数，取值范围 [1, N-1]）
    sm9_g2_t Ppub;  ///< 签名主公钥 Ppub = ks · P2
} sm9_sign_master_key_t;

/// @brief SM9 加密主密钥对
/// @ingroup sm9
typedef struct {
    big_t  ke;      ///< 加密主私钥（随机数，取值范围 [1, N-1]）
    sm9_g1_t Ppub;  ///< 加密主公钥 Ppub = ke · P1
} sm9_enc_master_key_t;

/// @brief SM9 用户签名私钥（G1 群上的点）
/// @ingroup sm9
typedef sm9_g1_t sm9_sign_user_key_t;

/// @brief SM9 用户解密私钥（G2 群上的点）
/// @ingroup sm9
typedef sm9_g2_t sm9_enc_user_key_t;

/* ── 曲线参数（由 sm9_init 初始化）────────────────────────────────── */

/// @brief 基域素数 p
/// @ingroup sm9
extern big_t sm9_p;
/// @brief 群阶 N
/// @ingroup sm9
extern big_t sm9_n;
/// @brief 曲线参数 b = 5
/// @ingroup sm9
extern big_t sm9_b;
/// @brief G1 群生成元 P1
/// @ingroup sm9
extern sm9_g1_t sm9_P1;
/// @brief G2 群生成元 P2
/// @ingroup sm9
extern sm9_g2_t sm9_P2;

/* ── 生命周期管理 ─────────────────────────────────────────────────── */

/// @brief 初始化 SM9 曲线参数，必须在调用其他 SM9 函数之前调用
/// @ingroup sm9
/// @note 使用完毕后应调用 sm9_destroy() 释放资源
/// @see sm9_destroy
void sm9_init(void);

/// @brief 清理 SM9 曲线参数，释放相关资源
/// @ingroup sm9
/// @note 与 sm9_init() 配对使用
/// @see sm9_init
void sm9_destroy(void);

/* ── 密钥生成 ─────────────────────────────────────────────────────── */

/// @brief 生成 SM9 签名主密钥对
/// @ingroup sm9
/// @param[out] mk 输出的签名主密钥对（包含主私钥和主公钥）
/// @note 调用前须先调用 sm9_init()
/// @see sm9_sign_user_key_extract, sm9_enc_master_keygen
void sm9_sign_master_keygen(sm9_sign_master_key_t* mk);

/// @brief 生成 SM9 加密主密钥对
/// @ingroup sm9
/// @param[out] mk 输出的加密主密钥对（包含主私钥和主公钥）
/// @note 调用前须先调用 sm9_init()
/// @see sm9_enc_user_key_extract, sm9_sign_master_keygen
void sm9_enc_master_keygen(sm9_enc_master_key_t* mk);

/// @brief 从签名主密钥和用户标识提取用户签名私钥
/// @ingroup sm9
/// @param[out] uk    输出的用户签名私钥
/// @param[in]  mk    签名主密钥对
/// @param[in]  id    用户标识（二进制串）
/// @param[in]  idlen 用户标识长度（字节）
/// @return 成功返回 1，失败返回 0
/// @note 调用前须先调用 sm9_init()
/// @see sm9_sign_master_keygen, sm9_sign
int sm9_sign_user_key_extract(sm9_sign_user_key_t* uk,
                              const sm9_sign_master_key_t* mk,
                              const unsigned char* id, unsigned long idlen);

/// @brief 从加密主密钥和用户标识提取用户解密私钥
/// @ingroup sm9
/// @param[out] uk    输出的用户解密私钥
/// @param[in]  mk    加密主密钥对
/// @param[in]  id    用户标识（二进制串）
/// @param[in]  idlen 用户标识长度（字节）
/// @return 成功返回 1，失败返回 0
/// @note 调用前须先调用 sm9_init()
/// @see sm9_enc_master_keygen, sm9_decrypt
int sm9_enc_user_key_extract(sm9_enc_user_key_t* uk,
                             const sm9_enc_master_key_t* mk,
                             const unsigned char* id, unsigned long idlen);

/* ── 签名与验签 ───────────────────────────────────────────────────── */

/// @brief SM9 数字签名生成
/// @ingroup sm9
/// @param[out] h      签名的哈希分量（32 字节）
/// @param[out] S      签名点（G1 群上的点）
/// @param[in]  msg    待签名消息
/// @param[in]  msglen 消息长度（字节）
/// @param[in]  uk     用户签名私钥
/// @param[in]  Ppub   签名主公钥
/// @note 调用前须先调用 sm9_init()
/// @see sm9_verify, sm9_sign_user_key_extract
/// @example example_sm9.c
void sm9_sign(unsigned char h[32], sm9_g1_t* S,
              const unsigned char* msg, unsigned long msglen,
              const sm9_sign_user_key_t* uk,
              const sm9_g2_t* Ppub);

/// @brief SM9 数字签名验证
/// @ingroup sm9
/// @param[in] h      签名的哈希分量（32 字节）
/// @param[in] S      签名点（G1 群上的点）
/// @param[in] msg    待验证消息
/// @param[in] msglen 消息长度（字节）
/// @param[in] id     签名者标识（二进制串）
/// @param[in] idlen  签名者标识长度（字节）
/// @param[in] Ppub   签名主公钥
/// @return 验证通过返回 1，验证失败返回 0
/// @note 调用前须先调用 sm9_init()
/// @see sm9_sign
int sm9_verify(const unsigned char h[32], const sm9_g1_t* S,
               const unsigned char* msg, unsigned long msglen,
               const unsigned char* id, unsigned long idlen,
               const sm9_g2_t* Ppub);

/* ── 加密与解密（KEM+DEM）─────────────────────────────────────────── */

/// @brief SM9 公钥加密（KEM-DEM 模式，使用 SM4-CBC + SM3-HMAC）
/// @ingroup sm9
/// @param[out] ct      密文输出缓冲区
/// @param[in]  ctsize  密文缓冲区大小（字节）
/// @param[out] ctlen   实际写入的密文长度（字节）
/// @param[in]  msg     明文数据
/// @param[in]  msglen  明文长度（字节）
/// @param[in]  id      接收方标识（二进制串）
/// @param[in]  idlen   接收方标识长度（字节）
/// @param[in]  Ppub    加密主密钥（含主公钥）
/// @return 成功返回 1，失败返回 0
/// @note 调用前须先调用 sm9_init()。密文缓冲区大小须足够容纳加密结果。
/// @see sm9_decrypt, sm9_enc_master_keygen
int sm9_encrypt(unsigned char* ct, unsigned long ctsize, unsigned long* ctlen,
                const unsigned char* msg, unsigned long msglen,
                const unsigned char* id, unsigned long idlen,
                const sm9_enc_master_key_t* Ppub);

/// @brief SM9 解密
/// @ingroup sm9
/// @param[out] msg     明文输出缓冲区
/// @param[in]  msgsize 明文缓冲区大小（字节）
/// @param[out] msglen  实际解密得到的明文长度（字节）
/// @param[in]  ct      密文数据
/// @param[in]  ctlen   密文长度（字节）
/// @param[in]  id      本方标识（二进制串）
/// @param[in]  idlen   本方标识长度（字节）
/// @param[in]  uk      用户解密私钥
/// @return 成功返回 1，失败返回 0（密文篡改或密钥不匹配）
/// @note 调用前须先调用 sm9_init()
/// @see sm9_encrypt, sm9_enc_user_key_extract
int sm9_decrypt(unsigned char* msg, unsigned long msgsize, unsigned long* msglen,
                const unsigned char* ct, unsigned long ctlen,
                const unsigned char* id, unsigned long idlen,
                const sm9_enc_user_key_t* uk);

/* ── 密钥交换 ─────────────────────────────────────────────────────── */

/// @brief 密钥交换第一步：生成临时密钥对
/// @ingroup sm9
/// @param[out] R    临时公开点（G1 群上的点）
/// @param[out] r    临时秘密标量
/// @param[in]  Ppub 加密主密钥（含主公钥）
/// @note 调用前须先调用 sm9_init()。生成的临时密钥对用于 sm9_key_exchange_finish()。
/// @see sm9_key_exchange_finish
void sm9_key_exchange_init(sm9_g1_t* R, big_t* r,
                           const sm9_enc_master_key_t* Ppub);

/// @brief 密钥交换第二步：计算共享密钥
/// @ingroup sm9
/// @param[out] sk          共享密钥输出缓冲区
/// @param[in]  sklen       期望的共享密钥长度（字节）
/// @param[in]  is_init     发起方为 1，响应方为 0
/// @param[in]  id_self     本方标识（二进制串）
/// @param[in]  id_self_len 本方标识长度（字节）
/// @param[in]  id_peer     对方标识（二进制串）
/// @param[in]  id_peer_len 对方标识长度（字节）
/// @param[in]  uk          本方用户解密私钥
/// @param[in]  r           本方临时秘密标量（来自 sm9_key_exchange_init）
/// @param[in]  R_self      本方临时公开点（来自 sm9_key_exchange_init）
/// @param[in]  R_peer      对方临时公开点
/// @param[in]  Ppub        加密主密钥（含主公钥）
/// @return 成功返回 1，失败返回 0
/// @note 调用前须先调用 sm9_init()。双方须使用相同的主公钥。
/// @see sm9_key_exchange_init, sm9_enc_user_key_extract
int sm9_key_exchange_finish(unsigned char* sk, unsigned long sklen,
                            int is_init,
                            const unsigned char* id_self,
                            unsigned long id_self_len,
                            const unsigned char* id_peer,
                            unsigned long id_peer_len,
                            const sm9_enc_user_key_t* uk,
                            const big_t* r,
                            const sm9_g1_t* R_self,
                            const sm9_g1_t* R_peer,
                            const sm9_enc_master_key_t* Ppub);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* GMSM_SM9_H_ */
