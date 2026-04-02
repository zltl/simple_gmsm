#ifndef GMSM_TLCP_H_
#define GMSM_TLCP_H_

/**
 * @file simple_gmsm/tlcp.h
 * @brief TLCP 传输层密码协议实现 (GB/T 38636-2020)
 *
 * @defgroup tlcp TLCP 传输层密码协议
 * @{
 *
 * 本模块实现了符合 GB/T 38636-2020 标准的传输层密码协议 (TLCP)。
 * TLCP 基于 SM2/SM3/SM4 国密算法，提供安全的传输层通信，
 * 包括握手协议、记录层协议、告警协议和密钥派生等功能。
 *
 * 典型使用流程：
 * 1. 调用 tlcp_ctx_init() 初始化上下文
 * 2. 设置证书和密钥
 * 3. 调用 tlcp_conn_init() 创建连接
 * 4. 设置 I/O 回调
 * 5. 执行握手 (tlcp_connect() 或 tlcp_accept())
 * 6. 使用 tlcp_write() / tlcp_read() 收发数据
 * 7. 调用 tlcp_shutdown() 关闭连接
 */

#include "common.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "hmac_sm3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name 协议版本
 * @brief TLCP 协议版本号定义 (1.1)
 * @ingroup tlcp
 * @{
 */
#define TLCP_VERSION_MAJOR 0x01  ///< 主版本号
#define TLCP_VERSION_MINOR 0x01  ///< 次版本号
/** @brief 完整协议版本号 (主版本号 << 8 | 次版本号) */
#define TLCP_VERSION ((TLCP_VERSION_MAJOR << 8) | TLCP_VERSION_MINOR)
/** @} */

/**
 * @name 内容类型
 * @brief TLS 记录层内容类型标识
 * @ingroup tlcp
 * @{
 */
#define TLCP_CONTENT_CHANGE_CIPHER_SPEC 20  ///< 密钥变更通知
#define TLCP_CONTENT_ALERT              21  ///< 告警消息
#define TLCP_CONTENT_HANDSHAKE          22  ///< 握手消息
#define TLCP_CONTENT_APPLICATION_DATA   23  ///< 应用数据
/** @} */

/**
 * @name 握手消息类型
 * @brief TLCP 握手协议消息类型标识
 * @ingroup tlcp
 * @{
 */
#define TLCP_HS_CLIENT_HELLO          1   ///< 客户端问候
#define TLCP_HS_SERVER_HELLO          2   ///< 服务端问候
#define TLCP_HS_CERTIFICATE           11  ///< 证书消息
#define TLCP_HS_SERVER_KEY_EXCHANGE   12  ///< 服务端密钥交换
#define TLCP_HS_CERTIFICATE_REQUEST   13  ///< 证书请求
#define TLCP_HS_SERVER_HELLO_DONE     14  ///< 服务端问候完成
#define TLCP_HS_CERTIFICATE_VERIFY    15  ///< 证书验证
#define TLCP_HS_CLIENT_KEY_EXCHANGE   16  ///< 客户端密钥交换
#define TLCP_HS_FINISHED              20  ///< 握手完成
/** @} */

/**
 * @name 密码套件
 * @brief TLCP 支持的密码套件标识
 * @ingroup tlcp
 * @note 密码套件决定了握手过程中使用的密钥交换、加密和MAC算法组合
 * @{
 */
#define TLCP_ECC_SM4_CBC_SM3    0xE013  ///< ECC_SM4_CBC_SM3 密码套件
#define TLCP_ECC_SM4_GCM_SM3   0xE053  ///< ECC_SM4_GCM_SM3 密码套件 (AEAD)
#define TLCP_ECDHE_SM4_CBC_SM3 0xE011  ///< ECDHE_SM4_CBC_SM3 密码套件
#define TLCP_ECDHE_SM4_GCM_SM3 0xE051  ///< ECDHE_SM4_GCM_SM3 密码套件 (AEAD)
/** @} */

/**
 * @name 告警级别
 * @brief TLCP 告警消息的严重级别
 * @ingroup tlcp
 * @{
 */
#define TLCP_ALERT_WARNING  1  ///< 警告级别（连接可继续）
#define TLCP_ALERT_FATAL    2  ///< 致命级别（连接必须终止）
/** @} */

/**
 * @name 告警描述码
 * @brief TLCP 告警消息的具体错误描述
 * @ingroup tlcp
 * @see tlcp_send_alert
 * @{
 */
#define TLCP_ALERT_CLOSE_NOTIFY             0    ///< 关闭通知
#define TLCP_ALERT_UNEXPECTED_MESSAGE        10  ///< 意外消息
#define TLCP_ALERT_BAD_RECORD_MAC           20   ///< 记录MAC校验失败
#define TLCP_ALERT_DECRYPTION_FAILED        21   ///< 解密失败
#define TLCP_ALERT_RECORD_OVERFLOW          22   ///< 记录溢出
#define TLCP_ALERT_HANDSHAKE_FAILURE        40   ///< 握手失败
#define TLCP_ALERT_BAD_CERTIFICATE          42   ///< 无效证书
#define TLCP_ALERT_UNSUPPORTED_CERTIFICATE  43   ///< 不支持的证书类型
#define TLCP_ALERT_CERTIFICATE_REVOKED      44   ///< 证书已吊销
#define TLCP_ALERT_CERTIFICATE_EXPIRED      45   ///< 证书已过期
#define TLCP_ALERT_CERTIFICATE_UNKNOWN      46   ///< 未知证书错误
#define TLCP_ALERT_ILLEGAL_PARAMETER        47   ///< 非法参数
#define TLCP_ALERT_UNKNOWN_CA               48   ///< 未知CA
#define TLCP_ALERT_ACCESS_DENIED            49   ///< 拒绝访问
#define TLCP_ALERT_DECODE_ERROR             50   ///< 解码错误
#define TLCP_ALERT_DECRYPT_ERROR            51   ///< 解密错误
#define TLCP_ALERT_PROTOCOL_VERSION         70   ///< 协议版本不支持
#define TLCP_ALERT_INSUFFICIENT_SECURITY    71   ///< 安全性不足
#define TLCP_ALERT_INTERNAL_ERROR           80   ///< 内部错误
#define TLCP_ALERT_USER_CANCELED            90   ///< 用户取消
#define TLCP_ALERT_UNSUPPORTED_SITE2SITE    200  ///< 不支持站点到站点
/** @} */

/**
 * @name 尺寸限制
 * @brief 协议中各数据结构的最大尺寸定义（字节）
 * @ingroup tlcp
 * @{
 */
#define TLCP_MAX_RECORD_LEN      16384  ///< 最大记录长度
#define TLCP_MAX_FRAGMENT_LEN    16384  ///< 最大分片长度
#define TLCP_RANDOM_LEN          32     ///< 随机数长度
#define TLCP_SESSION_ID_MAX_LEN  32     ///< 会话ID最大长度
#define TLCP_MASTER_SECRET_LEN   48     ///< 主密钥长度
#define TLCP_VERIFY_DATA_LEN     12     ///< 验证数据长度
#define TLCP_MAX_CERT_SIZE       4096   ///< 最大证书大小
#define TLCP_MAX_HANDSHAKE_SIZE  8192   ///< 最大握手消息大小
/** @} */

/**
 * @name 连接状态
 * @brief TLCP 握手过程中的状态机状态值
 * @ingroup tlcp
 * @note 状态按握手消息顺序递增，TLCP_STATE_ESTABLISHED 表示握手成功完成
 * @{
 */
#define TLCP_STATE_INIT              0    ///< 初始状态
#define TLCP_STATE_CLIENT_HELLO      1    ///< 已发送/接收 ClientHello
#define TLCP_STATE_SERVER_HELLO      2    ///< 已发送/接收 ServerHello
#define TLCP_STATE_SERVER_CERT       3    ///< 已发送/接收服务端证书
#define TLCP_STATE_SERVER_KEY_EX     4    ///< 已发送/接收服务端密钥交换
#define TLCP_STATE_CERT_REQUEST      5    ///< 已发送/接收证书请求
#define TLCP_STATE_SERVER_DONE       6    ///< 已发送/接收 ServerHelloDone
#define TLCP_STATE_CLIENT_CERT       7    ///< 已发送/接收客户端证书
#define TLCP_STATE_CLIENT_KEY_EX     8    ///< 已发送/接收客户端密钥交换
#define TLCP_STATE_CERT_VERIFY       9    ///< 已发送/接收证书验证
#define TLCP_STATE_CHANGE_CIPHER     10   ///< 已发送/接收 ChangeCipherSpec
#define TLCP_STATE_FINISHED          11   ///< 已发送/接收 Finished
#define TLCP_STATE_ESTABLISHED       12   ///< 连接已建立
#define TLCP_STATE_ERROR             255  ///< 错误状态
/** @} */

/**
 * @name 记录头
 * @brief 记录层头部大小常量
 * @ingroup tlcp
 * @{
 */
/** @brief 记录层头部大小（5字节：类型1 + 版本2 + 长度2） */
#define TLCP_RECORD_HEADER_SIZE  5
/** @} */

/**
 * @name I/O 回调类型
 * @brief 用于 TLCP 连接的读写回调函数类型定义
 * @ingroup tlcp
 * @{
 */

/**
 * @brief 数据读取回调函数类型
 * @ingroup tlcp
 *
 * 用户需实现此回调以提供底层数据读取能力（如 socket recv）。
 *
 * @param ctx  用户自定义上下文指针，通过 tlcp_conn_set_io() 传入
 * @param buf  接收数据的缓冲区
 * @param len  期望读取的字节数
 * @return 实际读取的字节数，失败时返回负值
 * @see tlcp_conn_set_io
 */
typedef int (*tlcp_read_fn)(void* ctx, unsigned char* buf, unsigned long len);

/**
 * @brief 数据写入回调函数类型
 * @ingroup tlcp
 *
 * 用户需实现此回调以提供底层数据写入能力（如 socket send）。
 *
 * @param ctx  用户自定义上下文指针，通过 tlcp_conn_set_io() 传入
 * @param buf  待发送数据的缓冲区
 * @param len  待发送的字节数
 * @return 实际写入的字节数，失败时返回负值
 * @see tlcp_conn_set_io
 */
typedef int (*tlcp_write_fn)(void* ctx, const unsigned char* buf, unsigned long len);

/** @} */

/**
 * @brief TLS 记录层头部结构（5字节）
 * @ingroup tlcp
 *
 * 每条 TLS 记录以此固定大小的头部开始，
 * 包含内容类型、协议版本和载荷长度信息。
 */
typedef struct {
    unsigned char content_type;  ///< 内容类型 @see TLCP_CONTENT_CHANGE_CIPHER_SPEC
    unsigned char version[2];    ///< 协议版本号（大端序）
    unsigned char length[2];     ///< 载荷长度（大端序）
} tlcp_record_header_t;

/**
 * @brief 证书结构（简化表示）
 * @ingroup tlcp
 *
 * 存储 DER 编码的原始证书数据以及从中提取的 SM2 公钥。
 *
 * @note 公钥仅在证书解析成功时有效，需检查 has_pubkey 字段
 * @see tlcp_cert_parse
 */
typedef struct {
    unsigned char der[TLCP_MAX_CERT_SIZE];  ///< DER 编码的证书原始数据
    unsigned long der_len;                  ///< DER 数据的实际长度（字节）
    big_t pubkey_x;                         ///< SM2 公钥 X 坐标
    big_t pubkey_y;                         ///< SM2 公钥 Y 坐标
    int has_pubkey;                         ///< 是否已成功提取公钥（0=否，1=是）
} tlcp_cert_t;

/**
 * @brief 安全参数结构
 * @ingroup tlcp
 *
 * 保存握手协商过程中派生的所有安全参数，
 * 包括主密钥、随机数、读写密钥和MAC密钥等。
 *
 * @note 该结构由 tlcp_derive_keys() 填充
 * @see tlcp_derive_master_secret
 * @see tlcp_derive_keys
 */
typedef struct {
    unsigned char master_secret[TLCP_MASTER_SECRET_LEN];  ///< 主密钥（48字节）
    unsigned char client_random[TLCP_RANDOM_LEN];         ///< 客户端随机数（32字节）
    unsigned char server_random[TLCP_RANDOM_LEN];         ///< 服务端随机数（32字节）
    unsigned char client_write_key[16];                   ///< 客户端写加密密钥
    unsigned char server_write_key[16];                   ///< 服务端写加密密钥
    unsigned char client_write_iv[16];                    ///< 客户端写初始化向量
    unsigned char server_write_iv[16];                    ///< 服务端写初始化向量
    unsigned char client_write_mac_key[32];               ///< 客户端写MAC密钥
    unsigned char server_write_mac_key[32];               ///< 服务端写MAC密钥
    unsigned short cipher_suite;                          ///< 协商的密码套件
    int is_gcm;                                           ///< 是否使用GCM模式（0=CBC，1=GCM）
} tlcp_security_params_t;

/**
 * @brief 握手哈希上下文
 * @ingroup tlcp
 *
 * 用于计算握手消息的SM3哈希值，在 Finished 消息中使用。
 *
 * @note 握手哈希在收到 ClientHello 后开始累积
 */
typedef struct {
    sm3_context_t hash;  ///< SM3 哈希上下文
    int active;          ///< 哈希是否已激活（0=未激活，1=已激活）
} tlcp_handshake_hash_t;

/**
 * @brief TLCP 上下文结构（全局配置）
 * @ingroup tlcp
 *
 * 存储 TLCP 连接所需的全局配置信息，包括本端证书、私钥、
 * 可信CA证书和密码套件偏好等。一个上下文可用于创建多个连接。
 *
 * @note 使用前必须调用 tlcp_ctx_init() 进行初始化
 * @see tlcp_ctx_init
 * @see tlcp_conn_init
 */
typedef struct {
    tlcp_cert_t sign_cert;                ///< 本端签名证书
    tlcp_cert_t enc_cert;                 ///< 本端加密证书
    big_t sign_private_key;               ///< 签名私钥
    big_t enc_private_key;                ///< 加密私钥
    int has_sign_cert;                    ///< 是否已设置签名证书
    int has_enc_cert;                     ///< 是否已设置加密证书
    tlcp_cert_t ca_certs[8];              ///< 可信CA证书列表（最多8个）
    int ca_cert_count;                    ///< 已加载的CA证书数量
    unsigned short cipher_suites[4];      ///< 支持的密码套件列表（按偏好排序）
    int cipher_suite_count;               ///< 密码套件数量
    int is_server;                        ///< 是否为服务端模式（0=客户端，1=服务端）
    int verify_client;                    ///< 是否要求客户端证书认证（仅服务端有效）
} tlcp_context_t;

/**
 * @brief TLCP 连接状态结构
 * @ingroup tlcp
 *
 * 维护单个 TLCP 连接的完整运行时状态，包括 I/O 回调、
 * 安全参数、对端证书、序列号和缓冲区等。
 *
 * @note 使用前必须调用 tlcp_conn_init() 进行初始化
 * @see tlcp_conn_init
 * @see tlcp_conn_set_io
 */
typedef struct {
    tlcp_context_t* ctx;                                    ///< 关联的上下文配置
    tlcp_read_fn read_fn;                                   ///< 数据读取回调函数
    tlcp_write_fn write_fn;                                 ///< 数据写入回调函数
    void* io_ctx;                                           ///< I/O 回调的用户上下文指针
    int state;                                              ///< 当前连接状态 @see TLCP_STATE_INIT
    int is_server;                                          ///< 是否为服务端
    tlcp_security_params_t params;                          ///< 安全参数
    tlcp_cert_t peer_sign_cert;                             ///< 对端签名证书
    tlcp_cert_t peer_enc_cert;                              ///< 对端加密证书
    int peer_cert_count;                                    ///< 对端证书数量
    unsigned long long client_seq;                          ///< 客户端消息序列号
    unsigned long long server_seq;                          ///< 服务端消息序列号
    tlcp_handshake_hash_t hs_hash;                          ///< 握手哈希上下文
    int client_cipher_active;                               ///< 客户端加密是否已激活
    int server_cipher_active;                               ///< 服务端加密是否已激活
    unsigned char read_buf[TLCP_MAX_RECORD_LEN + 256];      ///< 读缓冲区
    unsigned long read_buf_len;                             ///< 读缓冲区中的数据长度
    unsigned char session_id[TLCP_SESSION_ID_MAX_LEN];      ///< 会话ID
    unsigned long session_id_len;                           ///< 会话ID长度
    int last_error;                                         ///< 最近一次错误码
    unsigned char last_alert_level;                         ///< 最近一次告警级别
    unsigned char last_alert_desc;                          ///< 最近一次告警描述码
} tlcp_conn_t;

/* ---- 上下文管理 ---- */

/**
 * @brief 初始化 TLCP 上下文
 * @ingroup tlcp
 *
 * 将上下文结构清零并设置默认值。在使用上下文之前必须调用此函数。
 *
 * @param ctx  指向待初始化的上下文结构的指针
 *
 * @note 初始化后默认为客户端模式，可通过 tlcp_ctx_set_server() 切换
 * @see tlcp_ctx_set_server
 * @see tlcp_conn_init
 */
void tlcp_ctx_init(tlcp_context_t* ctx);

/**
 * @brief 设置上下文为服务端或客户端模式
 * @ingroup tlcp
 *
 * @param ctx        指向上下文结构的指针
 * @param is_server  1=服务端模式，0=客户端模式
 *
 * @see tlcp_ctx_init
 */
void tlcp_ctx_set_server(tlcp_context_t* ctx, int is_server);

/**
 * @brief 加载签名证书（DER编码格式）
 * @ingroup tlcp
 *
 * 解析并设置本端的签名证书，用于握手过程中的身份认证。
 *
 * @param ctx  指向上下文结构的指针
 * @param der  DER编码的证书数据
 * @param len  证书数据长度（字节）
 * @return 0 表示成功，负值表示失败
 *
 * @note TLCP 双证书体系要求同时设置签名证书和加密证书
 * @see tlcp_ctx_set_enc_cert
 * @see tlcp_cert_parse
 */
int tlcp_ctx_set_sign_cert(tlcp_context_t* ctx, const unsigned char* der,
                           unsigned long len);

/**
 * @brief 加载加密证书（DER编码格式）
 * @ingroup tlcp
 *
 * 解析并设置本端的加密证书，用于握手过程中的密钥交换。
 *
 * @param ctx  指向上下文结构的指针
 * @param der  DER编码的证书数据
 * @param len  证书数据长度（字节）
 * @return 0 表示成功，负值表示失败
 *
 * @note TLCP 双证书体系要求同时设置签名证书和加密证书
 * @see tlcp_ctx_set_sign_cert
 * @see tlcp_cert_parse
 */
int tlcp_ctx_set_enc_cert(tlcp_context_t* ctx, const unsigned char* der,
                          unsigned long len);

/**
 * @brief 设置签名私钥
 * @ingroup tlcp
 *
 * @param ctx  指向上下文结构的指针
 * @param key  指向 SM2 签名私钥的指针
 *
 * @note 私钥必须与签名证书中的公钥匹配
 * @see tlcp_ctx_set_sign_cert
 * @see tlcp_ctx_set_enc_key
 */
void tlcp_ctx_set_sign_key(tlcp_context_t* ctx, const big_t* key);

/**
 * @brief 设置加密私钥
 * @ingroup tlcp
 *
 * @param ctx  指向上下文结构的指针
 * @param key  指向 SM2 加密私钥的指针
 *
 * @note 私钥必须与加密证书中的公钥匹配
 * @see tlcp_ctx_set_enc_cert
 * @see tlcp_ctx_set_sign_key
 */
void tlcp_ctx_set_enc_key(tlcp_context_t* ctx, const big_t* key);

/**
 * @brief 添加可信CA证书
 * @ingroup tlcp
 *
 * 将一个CA证书添加到可信证书列表中，用于验证对端证书链。
 *
 * @param ctx  指向上下文结构的指针
 * @param der  DER编码的CA证书数据
 * @param len  证书数据长度（字节）
 * @return 0 表示成功，负值表示失败（如列表已满或解析失败）
 *
 * @note 最多支持8个CA证书
 * @see tlcp_cert_verify_signature
 */
int tlcp_ctx_add_ca_cert(tlcp_context_t* ctx, const unsigned char* der,
                         unsigned long len);

/**
 * @brief 设置密码套件偏好列表
 * @ingroup tlcp
 *
 * @param ctx     指向上下文结构的指针
 * @param suites  密码套件数组（按偏好降序排列）
 * @param count   密码套件数量（最多4个）
 *
 * @note 如未设置，将使用默认密码套件顺序
 * @see TLCP_ECC_SM4_CBC_SM3
 */
void tlcp_ctx_set_cipher_suites(tlcp_context_t* ctx,
                                const unsigned short* suites, int count);

/* ---- 连接管理 ---- */

/**
 * @brief 从上下文创建新的 TLCP 连接
 * @ingroup tlcp
 *
 * 初始化连接结构并关联到指定的上下文配置。
 *
 * @param conn  指向待初始化的连接结构的指针
 * @param ctx   指向已配置的上下文结构的指针
 *
 * @note 初始化后需调用 tlcp_conn_set_io() 设置 I/O 回调
 * @see tlcp_ctx_init
 * @see tlcp_conn_set_io
 */
void tlcp_conn_init(tlcp_conn_t* conn, tlcp_context_t* ctx);

/**
 * @brief 设置连接的 I/O 回调函数
 * @ingroup tlcp
 *
 * @param conn    指向连接结构的指针
 * @param rfn     数据读取回调函数
 * @param wfn     数据写入回调函数
 * @param io_ctx  传递给回调函数的用户上下文指针
 *
 * @see tlcp_read_fn
 * @see tlcp_write_fn
 * @see tlcp_conn_init
 */
void tlcp_conn_set_io(tlcp_conn_t* conn, tlcp_read_fn rfn, tlcp_write_fn wfn,
                      void* io_ctx);

/**
 * @brief 执行客户端 TLCP 握手
 * @ingroup tlcp
 *
 * 发起客户端握手流程，包括发送 ClientHello、处理服务端响应、
 * 密钥交换和 Finished 验证等步骤。
 *
 * @param conn  指向已初始化的连接结构的指针
 * @return 0 表示握手成功，负值表示失败
 *
 * @note 调用前需确保已通过 tlcp_conn_set_io() 设置 I/O 回调
 * @see tlcp_accept
 * @see tlcp_conn_set_io
 */
int tlcp_connect(tlcp_conn_t* conn);

/**
 * @brief 执行服务端 TLCP 握手
 * @ingroup tlcp
 *
 * 等待并处理客户端握手请求，完成服务端侧的握手流程。
 *
 * @param conn  指向已初始化的连接结构的指针
 * @return 0 表示握手成功，负值表示失败
 *
 * @note 上下文必须已设置为服务端模式（is_server=1）
 * @see tlcp_connect
 * @see tlcp_ctx_set_server
 */
int tlcp_accept(tlcp_conn_t* conn);

/**
 * @brief 发送应用层数据
 * @ingroup tlcp
 *
 * 将数据加密后通过记录层协议发送到对端。
 *
 * @param conn  指向已建立的连接结构的指针
 * @param data  待发送的数据缓冲区
 * @param len   待发送的数据长度（字节）
 * @return 0 表示成功，负值表示失败
 *
 * @note 必须在握手成功完成后调用
 * @see tlcp_read
 * @see tlcp_record_write
 */
int tlcp_write(tlcp_conn_t* conn, const unsigned char* data, unsigned long len);

/**
 * @brief 接收应用层数据
 * @ingroup tlcp
 *
 * 从记录层读取并解密对端发来的应用数据。
 *
 * @param conn    指向已建立的连接结构的指针
 * @param buf     接收数据的缓冲区
 * @param buflen  缓冲区大小（字节）
 * @return 实际读取的字节数，0 表示连接关闭，负值表示错误
 *
 * @note 必须在握手成功完成后调用
 * @see tlcp_write
 * @see tlcp_record_read
 */
int tlcp_read(tlcp_conn_t* conn, unsigned char* buf, unsigned long buflen);

/**
 * @brief 发送 close_notify 告警并关闭连接
 * @ingroup tlcp
 *
 * 向对端发送 close_notify 告警以优雅关闭连接。
 *
 * @param conn  指向连接结构的指针
 * @return 0 表示成功，负值表示失败
 *
 * @note 关闭后连接不可再用于数据收发
 * @see tlcp_send_alert
 */
int tlcp_shutdown(tlcp_conn_t* conn);

/* ---- 记录层 ---- */

/**
 * @brief 写入一条 TLS 记录
 * @ingroup tlcp
 *
 * 将数据封装为 TLS 记录格式并通过 I/O 回调发送。
 * 如果加密已激活，数据将被加密和认证。
 *
 * @param conn          指向连接结构的指针
 * @param content_type  记录内容类型 @see TLCP_CONTENT_HANDSHAKE
 * @param data          记录载荷数据
 * @param len           载荷数据长度（字节）
 * @return 0 表示成功，负值表示失败
 *
 * @see tlcp_record_read
 * @see TLCP_CONTENT_APPLICATION_DATA
 */
int tlcp_record_write(tlcp_conn_t* conn, unsigned char content_type,
                      const unsigned char* data, unsigned long len);

/**
 * @brief 读取一条 TLS 记录
 * @ingroup tlcp
 *
 * 从 I/O 回调读取一条完整的 TLS 记录并解析。
 * 如果加密已激活，数据将被解密和验证。
 *
 * @param conn          指向连接结构的指针
 * @param content_type  [out] 接收到的记录内容类型
 * @param data          [out] 接收记录载荷的缓冲区
 * @param len           [in,out] 输入为缓冲区大小，输出为实际载荷长度
 * @return 0 表示成功，负值表示失败
 *
 * @see tlcp_record_write
 */
int tlcp_record_read(tlcp_conn_t* conn, unsigned char* content_type,
                     unsigned char* data, unsigned long* len);

/* ---- 伪随机函数 (PRF) ---- */

/**
 * @brief 基于 HMAC-SM3 的 TLCP 伪随机函数
 * @ingroup tlcp
 *
 * 实现 GB/T 38636-2020 中定义的 PRF 算法，用于密钥派生。
 *
 * @param secret      密钥材料
 * @param secret_len  密钥材料长度（字节）
 * @param label       ASCII 标签字符串
 * @param seed        种子数据
 * @param seed_len    种子数据长度（字节）
 * @param out         输出缓冲区
 * @param out_len     期望输出长度（字节）
 *
 * @note 内部使用 HMAC-SM3 进行迭代扩展
 * @see tlcp_derive_master_secret
 * @see tlcp_derive_keys
 */
void tlcp_prf(const unsigned char* secret, unsigned long secret_len,
              const char* label,
              const unsigned char* seed, unsigned long seed_len,
              unsigned char* out, unsigned long out_len);

/**
 * @brief 从预主密钥派生主密钥
 * @ingroup tlcp
 *
 * 使用 PRF 从预主密钥和客户端/服务端随机数计算48字节的主密钥。
 *
 * @param master_secret      [out] 输出的主密钥（48字节）
 * @param pre_master_secret  预主密钥数据
 * @param pms_len            预主密钥长度（字节）
 * @param client_random      客户端随机数（32字节）
 * @param server_random      服务端随机数（32字节）
 *
 * @see tlcp_prf
 * @see tlcp_derive_keys
 */
void tlcp_derive_master_secret(unsigned char master_secret[48],
                               const unsigned char* pre_master_secret,
                               unsigned long pms_len,
                               const unsigned char client_random[32],
                               const unsigned char server_random[32]);

/**
 * @brief 从主密钥派生读写密钥
 * @ingroup tlcp
 *
 * 使用 PRF 从安全参数中的主密钥和随机数派生出所有的
 * 加密密钥、IV和MAC密钥，并填充到安全参数结构中。
 *
 * @param params  指向安全参数结构的指针，需已填充 master_secret、
 *                client_random 和 server_random
 *
 * @note 调用前 params 中的 master_secret 和随机数必须已设置
 * @see tlcp_derive_master_secret
 * @see tlcp_prf
 */
void tlcp_derive_keys(tlcp_security_params_t* params);

/* ---- 告警 ---- */

/**
 * @brief 发送告警消息
 * @ingroup tlcp
 *
 * 构造并发送一条 TLCP 告警消息到对端。
 *
 * @param conn   指向连接结构的指针
 * @param level  告警级别 @see TLCP_ALERT_WARNING
 * @param desc   告警描述码 @see TLCP_ALERT_CLOSE_NOTIFY
 * @return 0 表示成功，负值表示失败
 *
 * @note 发送致命告警后连接将进入错误状态
 * @see tlcp_shutdown
 */
int tlcp_send_alert(tlcp_conn_t* conn, unsigned char level,
                    unsigned char desc);

/* ---- 证书 ---- */

/**
 * @brief 解析 DER 编码的证书并提取 SM2 公钥
 * @ingroup tlcp
 *
 * 解析 X.509 DER 格式的证书数据，存储原始数据并提取 SM2 公钥坐标。
 *
 * @param cert  指向证书结构的指针
 * @param der   DER 编码的证书数据
 * @param len   证书数据长度（字节）
 * @return 0 表示成功，负值表示解析失败
 *
 * @note 仅支持包含 SM2 公钥的证书
 * @see tlcp_cert_verify_signature
 * @see tlcp_ctx_set_sign_cert
 */
int tlcp_cert_parse(tlcp_cert_t* cert, const unsigned char* der,
                    unsigned long len);

/**
 * @brief 使用颁发者公钥验证证书签名
 * @ingroup tlcp
 *
 * 使用颁发者证书中的 SM2 公钥验证目标证书的签名是否有效。
 *
 * @param cert         指向待验证证书的指针
 * @param issuer_cert  指向颁发者证书的指针
 * @return 0 表示验证成功，负值表示验证失败
 *
 * @note 颁发者证书的公钥必须已成功提取
 * @see tlcp_cert_parse
 * @see tlcp_ctx_add_ca_cert
 */
int tlcp_cert_verify_signature(const tlcp_cert_t* cert,
                               const tlcp_cert_t* issuer_cert);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* GMSM_TLCP_H_ */
