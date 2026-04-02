# simple_gmsm

Chinese National Cryptography (国密) C Library — 国密加密算法全套实现

[![C11](https://img.shields.io/badge/C-C11-blue.svg)](https://en.cppreference.com/w/c/11)
[![License](https://img.shields.io/badge/License-see%20LICENSE-green.svg)](LICENSE)

## 简介 / Overview

simple_gmsm 是一个纯 C11 实现的国密密码算法库，**无任何外部依赖**。涵盖所有主要国密
算法及 TLCP 国密传输层协议，适用于嵌入式系统、IoT 设备及对依赖要求严格的应用场景。

A pure C11 implementation of China's national cryptographic standards (GM/SM),
with **zero external dependencies**. Covers all major GM algorithms and the TLCP
transport layer protocol.

## 支持的算法 / Supported Algorithms

| 算法 | 标准 | 说明 |
|------|------|------|
| **SM2** | GB/T 32918 | 椭圆曲线公钥密码：签名/验签、加密/解密、密钥交换 |
| **SM3** | GB/T 32905 | 密码杂凑算法（256-bit 哈希） |
| **SM4** | GB/T 32907 | 分组密码（128-bit 分组）：ECB / CBC / CTR / GCM 模式 |
| **SM9** | GB/T 38635 | 标识密码：签名/验签、加密/解密、密钥封装 |
| **ZUC** | GM/T 0001 | 流密码：EEA3 加密、EIA3 完整性 |
| **HMAC-SM3** | RFC 2104 + SM3 | 基于 SM3 的消息认证码 |
| **TLCP** | GB/T 38636-2020 | 国密传输层协议（双证书体系） |

## 快速开始 / Quick Start

### 系统要求

- C11 兼容编译器（GCC ≥ 4.9, Clang ≥ 3.5）
- GNU Make
- Doxygen（可选，用于生成文档）

### 构建

```bash
# 构建静态库(.a) 和动态库(.so)
make libsimple_gmsm

# 运行所有单元测试 (56 个测试用例)
make test

# 编译示例程序
make examples

# 生成 Doxygen 文档
make doxy

# 清理构建产物
make clean
```

### 链接到你的项目

```bash
# 编译并链接静态库
cc -O2 -I./include -o myapp myapp.c target/libsimple_gmsm.a -lm

# 或链接动态库
cc -O2 -I./include -o myapp myapp.c -L./target -lsimple_gmsm -lm
```

## 使用示例 / Usage Examples

### SM3 哈希

```c
#include "simple_gmsm/sm3.h"

unsigned char hash[32];
sm3((const unsigned char *)"hello", 5, hash);

// 流式哈希
sm3_context_t ctx;
sm3_init(&ctx);
sm3_update(&ctx, data1, len1);
sm3_update(&ctx, data2, len2);
sm3_finish(&ctx, hash);
```

### SM4 加解密

```c
#include "simple_gmsm/sm4.h"

// ECB 单块
SM4_KEY ks;
sm4_set_key(key, &ks);
sm4_encrypt(plain, cipher, &ks);
sm4_decrypt(cipher, plain, &ks);

// CBC 模式 (含 PKCS#7 填充)
sm4_cbc_encrypt(key, iv, plain, plen, cipher, &clen);
sm4_cbc_decrypt(key, iv, cipher, clen, plain, &plen);

// GCM 认证加密
sm4_gcm_encrypt(key, iv, ivlen, aad, aadlen, plain, plen, cipher, tag);
sm4_gcm_decrypt(key, iv, ivlen, aad, aadlen, cipher, clen, plain, tag);
```

### SM2 签名与加密

```c
#include "simple_gmsm/slow_dirty_bigint.h"
#include "simple_gmsm/sm2.h"

big_prepare();
sm2_init();

// 密钥生成
big_t d, px, py;
big_init(&d); big_init(&px); big_init(&py);
sm2_gen_key(&d, &px, &py);

// 签名
unsigned char za[32], sig[64];
sm2_za(za, id, idlen, &px, &py);
sm2_sign_generate(sig, msg, msglen, za, &d);
sm2_sign_verify(sig, msg, msglen, za, &px, &py);

// 加密
sm2_encrypt(cipher, clen, plain, plen, &px, &py);
sm2_decrypt(plain, plen, cipher, clen, &d);

sm2_destroy();
```

### SM9 标识加密

```c
#include "simple_gmsm/slow_dirty_bigint.h"
#include "simple_gmsm/sm9.h"

big_prepare();
sm9_init();

// 生成主密钥 & 用户密钥
sm9_enc_master_key_t mk;
sm9_enc_master_keygen(&mk);
sm9_enc_user_key_t uk;
sm9_enc_user_key_extract(&uk, &mk, id, idlen);

// 加密/解密
sm9_encrypt(ct, sizeof(ct), &ctlen, msg, msglen, id, idlen, &mk);
sm9_decrypt(pt, sizeof(pt), &ptlen, ct, ctlen, id, idlen, &uk);

sm9_destroy();
```

### HMAC-SM3

```c
#include "simple_gmsm/hmac_sm3.h"

unsigned char mac[32];
hmac_sm3(key, keylen, msg, msglen, mac);
```

### ZUC 流密码

```c
#include "simple_gmsm/zuc.h"

// 密钥流生成
zuc_state_t state;
zuc_init(&state, key, iv);
uint32_t word = zuc_generate(&state);

// EEA3 加解密
zuc_eea3(key, count, bearer, direction, plain, cipher, bitlen);
```

> 💡 完整可运行的示例见 `examples/` 目录，使用 `make examples` 编译。

## API 参考 / API Reference

### 头文件

| 头文件 | 说明 |
|--------|------|
| [simple_gmsm/sm2.h](@ref sm2.h) | SM2 椭圆曲线：签名/加密/密钥交换 |
| [simple_gmsm/sm3.h](@ref sm3.h) | SM3 密码杂凑算法 |
| [simple_gmsm/sm4.h](@ref sm4.h) | SM4 分组密码（ECB/CBC/CTR/GCM） |
| [simple_gmsm/sm9.h](@ref sm9.h) | SM9 标识密码 |
| [simple_gmsm/zuc.h](@ref zuc.h) | ZUC 流密码（EEA3/EIA3） |
| [simple_gmsm/hmac_sm3.h](@ref hmac_sm3.h) | HMAC-SM3 消息认证码 |
| [simple_gmsm/tlcp.h](@ref tlcp.h) | TLCP 国密传输层协议 |
| [simple_gmsm/big.h](@ref big.h) | 大整数运算接口 |

### TLCP 协议

TLCP (GB/T 38636-2020) 实现支持：

- **双证书体系**：签名证书 + 加密证书
- **密码套件**：
  - `ECC_SM4_CBC_SM3` (0xe013)
  - `ECC_SM4_GCM_SM3` (0xe053)
  - `ECDHE_SM4_CBC_SM3` (0xe011)
  - `ECDHE_SM4_GCM_SM3` (0xe051)
- **完整协议栈**：握手、记录层、PRF、Alert、应用数据
- **基于文件描述符的 I/O 抽象**

## 项目结构 / Project Structure

```
simple_gmsm/
├── include/simple_gmsm/   # 公共头文件
│   ├── sm2.h, sm3.h, sm4.h, sm9.h, zuc.h
│   ├── hmac_sm3.h, tlcp.h
│   ├── big.h, common.h, slow_dirty_bigint.h
├── *.c                     # 算法及协议实现
├── examples/               # 示例程序
│   ├── example_sm3.c       # SM3 哈希示例
│   ├── example_sm4.c       # SM4 加密示例 (ECB/CBC/GCM)
│   ├── example_sm2.c       # SM2 签名/加密示例
│   ├── example_sm9.c       # SM9 标识加密示例
│   ├── example_hmac_sm3.c  # HMAC-SM3 示例
│   └── example_zuc.c       # ZUC 流密码示例
├── tests/                  # 单元测试 (56 test cases)
├── doxy/                   # Doxygen 样式文件
├── Doxyfile                # Doxygen 配置
├── Makefile                # 构建系统
└── target/                 # 构建输出目录
    ├── libsimple_gmsm.a    # 静态库
    ├── libsimple_gmsm.so   # 动态库
    ├── examples/            # 编译后的示例
    └── doc/                 # 生成的文档
```

## 标准合规 / Standards Compliance

本库实现遵循以下国家标准：

- **GB/T 32918** — SM2 椭圆曲线公钥密码算法
- **GB/T 32905** — SM3 密码杂凑算法
- **GB/T 32907** — SM4 分组密码算法
- **GB/T 38635** — SM9 标识密码算法
- **GM/T 0001** — ZUC 流密码算法
- **GB/T 38636-2020** — 信息安全技术 传输层密码协议 (TLCP)

## 注意事项 / Notes

- 大整数后端 (`slow_dirty_bigint`) 功能正确但速度较慢，SM9 操作可能耗时较长
- 本库面向学习和原型验证，生产环境请评估性能需求
- 所有测试使用国标文档中的标准测试向量

## 许可证 / License

详见 [LICENSE](LICENSE) 文件。
