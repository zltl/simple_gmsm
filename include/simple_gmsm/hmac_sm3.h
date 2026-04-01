#ifndef GMSM_HMAC_SM3_H_
#define GMSM_HMAC_SM3_H_

#include "common.h"
#include "sm3.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @file simple_gmsm/hmac_sm3.h
/// @brief HMAC-SM3 implementation (RFC 2104)

/// HMAC-SM3 context
typedef struct {
    sm3_context_t inner;
    sm3_context_t outer;
} hmac_sm3_context_t;

/// @brief Initialize HMAC-SM3 context with key
/// @param ctx hmac_sm3_context_t
/// @param key HMAC key
/// @param keylen HMAC key length in bytes
void hmac_sm3_init(hmac_sm3_context_t* ctx, const unsigned char* key,
                   unsigned long keylen);

/// @brief Feed data into HMAC
/// @param ctx hmac_sm3_context_t
/// @param data data to authenticate
/// @param len data length in bytes
void hmac_sm3_update(hmac_sm3_context_t* ctx, const unsigned char* data,
                     unsigned long len);

/// @brief Finalize HMAC and produce 32-byte MAC
/// @param ctx hmac_sm3_context_t
/// @param mac 32-byte output buffer
void hmac_sm3_finish(hmac_sm3_context_t* ctx, unsigned char mac[32]);

/// @brief One-shot HMAC-SM3
/// @param key HMAC key
/// @param keylen HMAC key length in bytes
/// @param data data to authenticate
/// @param datalen data length in bytes
/// @param mac 32-byte output buffer
void hmac_sm3(const unsigned char* key, unsigned long keylen,
              const unsigned char* data, unsigned long datalen,
              unsigned char mac[32]);

#ifdef __cplusplus
}
#endif

#endif  // GMSM_HMAC_SM3_H_
