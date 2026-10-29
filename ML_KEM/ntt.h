/* FIPS 203, Section 4.3: Number-Theoretic Transform
 *  Alg 9 NTT, Alg 10 NTT^-1, Alg 11 MultiplyNTTs, Alg 12 BaseCaseMultiply
 */
#ifndef MLKEM_NTT_H
#define MLKEM_NTT_H
#include "params.h"

void NTT(uint16_t f[MLKEM_N]);        /* in place, R_q -> T_q */
void NTT_inv(uint16_t f[MLKEM_N]);    /* in place, T_q -> R_q */
void MultiplyNTTs(uint16_t h[MLKEM_N], const uint16_t f[MLKEM_N], const uint16_t g[MLKEM_N]);
void BaseCaseMultiply(uint16_t *c0, uint16_t *c1, uint16_t a0, uint16_t a1,
                      uint16_t b0, uint16_t b1, uint16_t gamma);

/* coefficient-wise helpers, valid in either domain */
void poly_add(uint16_t r[MLKEM_N], const uint16_t a[MLKEM_N], const uint16_t b[MLKEM_N]);
void poly_sub(uint16_t r[MLKEM_N], const uint16_t a[MLKEM_N], const uint16_t b[MLKEM_N]);

#endif
