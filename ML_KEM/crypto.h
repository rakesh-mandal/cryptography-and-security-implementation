/* FIPS 203, Section 4.1: Cryptographic functions (PRF, H, J, G, XOF) */
#ifndef MLKEM_CRYPTO_H
#define MLKEM_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

/* Generic Keccak sponge (FIPS 202) */
typedef struct {
    uint64_t s[25];
    unsigned rate, pos;
    uint8_t  ds;          /* domain-separation/padding byte: 0x06 SHA3, 0x1F SHAKE */
    int      finalized;
} keccak_ctx;

void keccak_init(keccak_ctx *c, unsigned rate, uint8_t ds);
void keccak_absorb(keccak_ctx *c, const uint8_t *in, size_t len);
void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len);

/* PRF_eta(s,b) = SHAKE256(s || b, 8*64*eta)  -> 64*eta bytes */
void mlkem_PRF(int eta, uint8_t *out, const uint8_t s[32], uint8_t b);
/* H(s) = SHA3-256(s) */
void mlkem_H(uint8_t out[32], const uint8_t *in, size_t len);
/* J(s) = SHAKE256(s, 8*32) */
void mlkem_J(uint8_t out[32], const uint8_t *in, size_t len);
/* G(c) = SHA3-512(c), returned as (a,b) = first 32 bytes, last 32 bytes */
void mlkem_G(uint8_t out[64], const uint8_t *in, size_t len);

/* XOF = SHAKE128 with Init / Absorb / Squeeze interface */
typedef keccak_ctx xof_ctx;
void xof_init(xof_ctx *c);
void xof_absorb(xof_ctx *c, const uint8_t *in, size_t len);
void xof_squeeze(xof_ctx *c, uint8_t *out, size_t len);

/* Randomness (approved RBG stand-in: OS CSPRNG) and helpers */
int  mlkem_randombytes(uint8_t *out, size_t len);   /* 0 on success */
void mlkem_cleanse(void *p, size_t len);
/* Constant-time: returns 0xFF if a==b for len bytes, else 0x00 */
uint8_t mlkem_ct_equal_mask(const uint8_t *a, const uint8_t *b, size_t len);

#endif
