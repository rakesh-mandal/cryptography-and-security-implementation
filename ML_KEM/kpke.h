/* FIPS 203, Section 5: K-PKE component scheme (Alg 13, 14, 15) */
#ifndef MLKEM_KPKE_H
#define MLKEM_KPKE_H
#include "params.h"

/* ek: 384k+32 bytes, dk: 384k bytes, d: 32 random bytes */
void kpke_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk, const uint8_t d[32]);
/* c: 32(du*k+dv) bytes */
void kpke_encrypt(const mlkem_params *p, uint8_t *c, const uint8_t *ek,
                  const uint8_t m[32], const uint8_t r[32]);
void kpke_decrypt(const mlkem_params *p, uint8_t m[32], const uint8_t *dk, const uint8_t *c);

#endif
