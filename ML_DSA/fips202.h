/* Minimal incremental SHAKE128/SHAKE256 (FIPS 202). */
#ifndef FIPS202_H
#define FIPS202_H
#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

typedef struct {
    uint64_t s[25];
    unsigned pos;      /* byte position inside the current rate block */
    unsigned rate;
    int squeezing;
} shake_ctx;

void shake128_init(shake_ctx *c);
void shake256_init(shake_ctx *c);
void shake_absorb(shake_ctx *c, const uint8_t *in, size_t len);
void shake_squeeze(shake_ctx *c, uint8_t *out, size_t len); /* finalizes on first call */

/* One-shot helpers */
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

void shake_clear(shake_ctx *c);
#endif
