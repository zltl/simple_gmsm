simple_gmsm
---

国密加密算法全套实现，包含 SM2/SM3/SM4/SM9/ZUC 及 TLCP 协议。纯 C11 实现，无外部依赖。文档由 doxygen 生成。

### 密码算法

- [simple_gmsm/sm2.h](@ref include/simple_gmsm/sm2.h) SM2 椭圆曲线算法（签名/加密/密钥交换）
- [simple_gmsm/sm3.h](@ref include/simple_gmsm/sm3.h) SM3 密码杂凑算法
- [simple_gmsm/sm4.h](@ref include/simple_gmsm/sm4.h) SM4 分组密码（ECB/CBC/CTR/GCM 模式）
- [simple_gmsm/hmac_sm3.h](@ref include/simple_gmsm/hmac_sm3.h) HMAC-SM3 消息认证码
- [simple_gmsm/zuc.h](@ref include/simple_gmsm/zuc.h) ZUC 流密码（EEA3/EIA3）
- [simple_gmsm/sm9.h](@ref include/simple_gmsm/sm9.h) SM9 标识密码（签名/加密/密钥交换）

### TLCP 协议

- [simple_gmsm/tlcp.h](@ref include/simple_gmsm/tlcp.h) TLCP 协议（GB/T 38636-2020）
  - 双证书体系（签名证书 + 加密证书）
  - 密码套件：ECC_SM4_CBC_SM3, ECC_SM4_GCM_SM3, ECDHE 变体
  - 完整握手协议、记录层、PRF、Alert 协议

### 构建与测试

```bash
make          # 构建静态库 libsimple_gmsm.a
make test     # 编译并运行所有单元测试
make clean    # 清理构建产物
```
