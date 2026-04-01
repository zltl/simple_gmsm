#ifndef GMSM_SM9_H_
#define GMSM_SM9_H_

/// @file simple_gmsm/sm9.h
/// @brief SM9 identity-based cryptographic algorithm (GB/T 38635)

#ifdef __cplusplus
extern "C" {
#endif

#include "big.h"
#include "common.h"

/* ── Extension field element types ─────────────────────────────────── */

/// @brief Fp2 = Fp[u]/(u^2+1), element (a0 + a1*u)
typedef struct {
    big_t a0;
    big_t a1;
} fp2_t;

/// @brief Fp4 = Fp2[v]/(v^2-u), element (a0 + a1*v)
typedef struct {
    fp2_t a0;
    fp2_t a1;
} fp4_t;

/// @brief Fp12 = Fp4[w]/(w^3-v), element (a0 + a1*w + a2*w^2)
typedef struct {
    fp4_t a0;
    fp4_t a1;
    fp4_t a2;
} fp12_t;

/* ── Point types ───────────────────────────────────────────────────── */

/// @brief G1 point on E(Fp): y^2 = x^3 + 5
typedef struct {
    big_t x;
    big_t y;
} sm9_g1_t;

/// @brief G2 point on E'(Fp2)
typedef struct {
    fp2_t x;
    fp2_t y;
} sm9_g2_t;

/* ── Key types ─────────────────────────────────────────────────────── */

/// @brief SM9 sign master key pair
typedef struct {
    big_t  ks;      ///< master secret (random in [1, N-1])
    sm9_g2_t Ppub;  ///< master public key  Ppub = ks * P2
} sm9_sign_master_key_t;

/// @brief SM9 encrypt master key pair
typedef struct {
    big_t  ke;      ///< master secret
    sm9_g1_t Ppub;  ///< master public key  Ppub = ke * P1
} sm9_enc_master_key_t;

/// @brief SM9 user signing key (point on G1)
typedef sm9_g1_t sm9_sign_user_key_t;

/// @brief SM9 user decryption key (point on G2)
typedef sm9_g2_t sm9_enc_user_key_t;

/* ── Curve parameters (set by sm9_init) ────────────────────────────── */

extern big_t sm9_p;   ///< base field prime
extern big_t sm9_n;   ///< group order
extern big_t sm9_b;   ///< curve parameter b = 5
extern sm9_g1_t sm9_P1; ///< G1 generator
extern sm9_g2_t sm9_P2; ///< G2 generator

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/// @brief Initialize SM9 curve parameters. Call before any other sm9 function.
void sm9_init(void);
/// @brief Cleanup SM9 parameters. Paired with sm9_init().
void sm9_destroy(void);

/* ── Key generation ────────────────────────────────────────────────── */

/// @brief Generate sign master key pair
void sm9_sign_master_keygen(sm9_sign_master_key_t* mk);
/// @brief Generate encrypt master key pair
void sm9_enc_master_keygen(sm9_enc_master_key_t* mk);
/// @brief Extract user signing key from master key and identity
/// @return 1 on success, 0 on failure
int sm9_sign_user_key_extract(sm9_sign_user_key_t* uk,
                              const sm9_sign_master_key_t* mk,
                              const unsigned char* id, unsigned long idlen);
/// @brief Extract user decryption key from master key and identity
/// @return 1 on success, 0 on failure
int sm9_enc_user_key_extract(sm9_enc_user_key_t* uk,
                             const sm9_enc_master_key_t* mk,
                             const unsigned char* id, unsigned long idlen);

/* ── Sign / Verify ─────────────────────────────────────────────────── */

/// @brief SM9 signature generation
/// @param[out] h   hash component (32 bytes)
/// @param[out] S   signature point on G1
/// @param[in]  msg message
/// @param[in]  msglen message length
/// @param[in]  uk  user signing key
/// @param[in]  Ppub master public signing key
void sm9_sign(unsigned char h[32], sm9_g1_t* S,
              const unsigned char* msg, unsigned long msglen,
              const sm9_sign_user_key_t* uk,
              const sm9_g2_t* Ppub);

/// @brief SM9 signature verification
/// @return 1 if valid, 0 if invalid
int sm9_verify(const unsigned char h[32], const sm9_g1_t* S,
               const unsigned char* msg, unsigned long msglen,
               const unsigned char* id, unsigned long idlen,
               const sm9_g2_t* Ppub);

/* ── Encrypt (KEM+DEM) / Decrypt ───────────────────────────────────── */

/// @brief SM9 encryption (KEM-DEM with SM4-CBC + SM3-HMAC)
/// @param[out] ct      ciphertext buffer
/// @param[in]  ctsize  ciphertext buffer size
/// @param[out] ctlen   actual ciphertext length written
/// @param[in]  msg     plaintext
/// @param[in]  msglen  plaintext length
/// @param[in]  id      recipient identity
/// @param[in]  idlen   identity length
/// @param[in]  Ppub    master public encryption key
/// @return 1 on success, 0 on failure
int sm9_encrypt(unsigned char* ct, unsigned long ctsize, unsigned long* ctlen,
                const unsigned char* msg, unsigned long msglen,
                const unsigned char* id, unsigned long idlen,
                const sm9_enc_master_key_t* Ppub);

/// @brief SM9 decryption
/// @param[out] msg     plaintext buffer
/// @param[in]  msgsize plaintext buffer size
/// @param[out] msglen  actual plaintext length
/// @param[in]  ct      ciphertext
/// @param[in]  ctlen   ciphertext length
/// @param[in]  id      own identity
/// @param[in]  idlen   identity length
/// @param[in]  uk      user decryption key
/// @return 1 on success, 0 on failure
int sm9_decrypt(unsigned char* msg, unsigned long msgsize, unsigned long* msglen,
                const unsigned char* ct, unsigned long ctlen,
                const unsigned char* id, unsigned long idlen,
                const sm9_enc_user_key_t* uk);

/* ── Key Exchange ──────────────────────────────────────────────────── */

/// @brief Key exchange step 1 – generate ephemeral key pair
/// @param[out] R     ephemeral public point (G1)
/// @param[out] r     ephemeral secret scalar
/// @param[in]  Ppub  master public encryption key
void sm9_key_exchange_init(sm9_g1_t* R, big_t* r,
                           const sm9_enc_master_key_t* Ppub);

/// @brief Key exchange step 2 – compute shared key
/// @param[out] sk      shared key buffer
/// @param[in]  sklen   desired shared key length
/// @param[in]  is_init 1 if initiator, 0 if responder
/// @param[in]  id_self own identity
/// @param[in]  id_self_len own identity length
/// @param[in]  id_peer peer identity
/// @param[in]  id_peer_len peer identity length
/// @param[in]  uk      own user decryption key
/// @param[in]  r       own ephemeral secret
/// @param[in]  R_self  own ephemeral public point
/// @param[in]  R_peer  peer ephemeral public point
/// @param[in]  Ppub    master public encryption key
/// @return 1 on success, 0 on failure
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

#ifdef __cplusplus
}
#endif

#endif /* GMSM_SM9_H_ */
