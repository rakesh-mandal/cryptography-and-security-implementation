#include <stdio.h>
#include <string.h>
#include "crypto.h"

/* ---------------- Keccak-f[1600] ---------------- */
static const uint64_t RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int ROTC[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PILN[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

static inline uint64_t rol64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

static void keccakf(uint64_t A[25]) {
    uint64_t bc[5], t;
    for (int r = 0; r < 24; r++) {
        for (int i = 0; i < 5; i++) bc[i] = A[i] ^ A[i+5] ^ A[i+10] ^ A[i+15] ^ A[i+20];   /* theta */
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ rol64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) A[j+i] ^= t;
        }
        t = A[1];                                                                          /* rho+pi */
        for (int i = 0; i < 24; i++) { int j = PILN[i]; uint64_t b = A[j]; A[j] = rol64(t, ROTC[i]); t = b; }
        for (int j = 0; j < 25; j += 5) {                                                  /* chi */
            for (int i = 0; i < 5; i++) bc[i] = A[j+i];
            for (int i = 0; i < 5; i++) A[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }
        A[0] ^= RC[r];                                                                     /* iota */
    }
}

/* ---------------- Sponge ---------------- */
void keccak_init(keccak_ctx *c, unsigned rate, uint8_t ds) {
    memset(c->s, 0, sizeof c->s);
    c->rate = rate; c->pos = 0; c->ds = ds; c->finalized = 0;
}
static inline void xor_byte(keccak_ctx *c, unsigned pos, uint8_t b) {
    c->s[pos >> 3] ^= (uint64_t)b << (8 * (pos & 7));
}
void keccak_absorb(keccak_ctx *c, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        xor_byte(c, c->pos++, in[i]);
        if (c->pos == c->rate) { keccakf(c->s); c->pos = 0; }
    }
}
static void finalize(keccak_ctx *c) {
    xor_byte(c, c->pos, c->ds);
    xor_byte(c, c->rate - 1, 0x80);
    keccakf(c->s);
    c->pos = 0; c->finalized = 1;
}
void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len) {
    if (!c->finalized) finalize(c);
    for (size_t i = 0; i < len; i++) {
        if (c->pos == c->rate) { keccakf(c->s); c->pos = 0; }
        out[i] = (uint8_t)(c->s[c->pos >> 3] >> (8 * (c->pos & 7)));
        c->pos++;
    }
}

static void oneshot(unsigned rate, uint8_t ds, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    keccak_ctx c;
    keccak_init(&c, rate, ds);
    keccak_absorb(&c, in, inlen);
    keccak_squeeze(&c, out, outlen);
    mlkem_cleanse(&c, sizeof c);
}

/* ---------------- Section 4.1 ---------------- */
void mlkem_PRF(int eta, uint8_t *out, const uint8_t s[32], uint8_t b) {
    uint8_t in[33];
    memcpy(in, s, 32); in[32] = b;
    oneshot(136, 0x1F, in, 33, out, 64 * (size_t)eta);   /* SHAKE256 */
    mlkem_cleanse(in, sizeof in);
}
void mlkem_H(uint8_t out[32], const uint8_t *in, size_t len) { oneshot(136, 0x06, in, len, out, 32); } /* SHA3-256 */
void mlkem_J(uint8_t out[32], const uint8_t *in, size_t len) { oneshot(136, 0x1F, in, len, out, 32); } /* SHAKE256 */
void mlkem_G(uint8_t out[64], const uint8_t *in, size_t len) { oneshot(72,  0x06, in, len, out, 64); } /* SHA3-512 */

void xof_init(xof_ctx *c) { keccak_init(c, 168, 0x1F); }                              /* SHAKE128 */
void xof_absorb(xof_ctx *c, const uint8_t *in, size_t len) { keccak_absorb(c, in, len); }
void xof_squeeze(xof_ctx *c, uint8_t *out, size_t len) { keccak_squeeze(c, out, len); }

/* ---------------- Helpers ---------------- */
int mlkem_randombytes(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}
void mlkem_cleanse(void *p, size_t len) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
}
uint8_t mlkem_ct_equal_mask(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return (uint8_t)(((uint32_t)diff - 1) >> 8);   /* diff==0 -> 0xFF, else 0x00 */
}
