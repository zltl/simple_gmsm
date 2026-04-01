#ifndef GMSM_ZUC_H_
#define GMSM_ZUC_H_

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @file simple_gmsm/zuc.h
/// @brief ZUC stream cipher (GM/T 0001-2012)

/// ZUC state
typedef struct {
    unsigned int lfsr[16];   // LFSR registers s0..s15
    unsigned int r1, r2;     // F function registers
    unsigned int x[4];       // working variables
} zuc_state_t;

/// @brief Initialize ZUC with 128-bit key and 128-bit IV
void zuc_init(zuc_state_t* state, const unsigned char key[16], const unsigned char iv[16]);

/// @brief Generate one 32-bit keystream word
unsigned int zuc_generate(zuc_state_t* state);

/// @brief Generate keystream words
void zuc_generate_keystream(zuc_state_t* state, unsigned int* keystream, unsigned long nwords);

/// @brief 128-EEA3 confidentiality algorithm
/// @param key 128-bit key
/// @param count 32-bit counter
/// @param bearer 5-bit bearer id
/// @param direction 1-bit direction
/// @param input input bitstream
/// @param output output bitstream
/// @param bitlen length in bits
void zuc_eea3(const unsigned char key[16], unsigned int count,
              unsigned int bearer, unsigned int direction,
              const unsigned char* input, unsigned char* output,
              unsigned int bitlen);

/// @brief 128-EIA3 integrity algorithm
/// @param key 128-bit key
/// @param count 32-bit counter
/// @param bearer 5-bit bearer id
/// @param direction 1-bit direction
/// @param message input message
/// @param bitlen length in bits
/// @return 32-bit MAC
unsigned int zuc_eia3(const unsigned char key[16], unsigned int count,
                      unsigned int bearer, unsigned int direction,
                      const unsigned char* message, unsigned int bitlen);

#ifdef __cplusplus
}
#endif

#endif // GMSM_ZUC_H_
