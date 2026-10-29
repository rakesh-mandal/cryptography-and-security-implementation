#include "ntt.h"
#include "ntt_tables.h"

void NTT(uint16_t f[MLKEM_N]) {                                  /* Alg 9 */
    unsigned i = 1;
    for (unsigned len = 128; len >= 2; len >>= 1)
        for (unsigned start = 0; start < MLKEM_N; start += 2 * len) {
            uint32_t zeta = ZETAS[i++];
            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = (uint16_t)(zeta * f[j + len] % MLKEM_Q);
                f[j + len] = (uint16_t)((f[j] + MLKEM_Q - t) % MLKEM_Q);
                f[j]       = (uint16_t)((f[j] + t) % MLKEM_Q);
            }
        }
}

void NTT_inv(uint16_t f[MLKEM_N]) {                              /* Alg 10 */
    unsigned i = 127;
    for (unsigned len = 2; len <= 128; len <<= 1)
        for (unsigned start = 0; start < MLKEM_N; start += 2 * len) {
            uint32_t zeta = ZETAS[i--];
            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = f[j];
                f[j]       = (uint16_t)((t + f[j + len]) % MLKEM_Q);
                f[j + len] = (uint16_t)(zeta * ((f[j + len] + MLKEM_Q - t) % MLKEM_Q) % MLKEM_Q);
            }
        }
    for (unsigned j = 0; j < MLKEM_N; j++)
        f[j] = (uint16_t)(f[j] * 3303u % MLKEM_Q);               /* 128^-1 mod q */
}

void BaseCaseMultiply(uint16_t *c0, uint16_t *c1, uint16_t a0, uint16_t a1,
                      uint16_t b0, uint16_t b1, uint16_t gamma) {    /* Alg 12 */
    uint32_t t = (uint32_t)a1 * b1 % MLKEM_Q * gamma;
    *c0 = (uint16_t)(((uint32_t)a0 * b0 + t) % MLKEM_Q);
    *c1 = (uint16_t)(((uint32_t)a0 * b1 + (uint32_t)a1 * b0) % MLKEM_Q);
}

void MultiplyNTTs(uint16_t h[MLKEM_N], const uint16_t f[MLKEM_N], const uint16_t g[MLKEM_N]) { /* Alg 11 */
    for (unsigned i = 0; i < 128; i++)
        BaseCaseMultiply(&h[2*i], &h[2*i+1], f[2*i], f[2*i+1], g[2*i], g[2*i+1], GAMMAS[i]);
}

void poly_add(uint16_t r[MLKEM_N], const uint16_t a[MLKEM_N], const uint16_t b[MLKEM_N]) {
    for (int i = 0; i < MLKEM_N; i++) r[i] = (uint16_t)((a[i] + b[i]) % MLKEM_Q);
}
void poly_sub(uint16_t r[MLKEM_N], const uint16_t a[MLKEM_N], const uint16_t b[MLKEM_N]) {
    for (int i = 0; i < MLKEM_N; i++) r[i] = (uint16_t)((a[i] + MLKEM_Q - b[i]) % MLKEM_Q);
}
