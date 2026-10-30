#include <string.h>
#include "fips202.h"

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const unsigned rotc[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
static const unsigned piln[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                                  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

static void keccak_f1600(uint64_t st[25]) {
    uint64_t bc[5], t;
    for (int r = 0; r < 24; r++) {
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        t = st[1];
        for (int i = 0; i < 24; i++) {
            unsigned j = piln[i];
            bc[0] = st[j];
            st[j] = ROL64(t, rotc[i]);
            t = bc[0];
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= RC[r];
    }
}

/* Endianness-independent byte access into the lane array. */
static inline void xor_byte(shake_ctx *c, unsigned i, uint8_t b) {
    c->s[i >> 3] ^= (uint64_t)b << (8 * (i & 7));
}
static inline uint8_t get_byte(const shake_ctx *c, unsigned i) {
    return (uint8_t)(c->s[i >> 3] >> (8 * (i & 7)));
}

static void init(shake_ctx *c, unsigned rate) {
    memset(c, 0, sizeof *c);
    c->rate = rate;
}
void shake128_init(shake_ctx *c) { init(c, SHAKE128_RATE); }
void shake256_init(shake_ctx *c) { init(c, SHAKE256_RATE); }

void shake_absorb(shake_ctx *c, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        xor_byte(c, c->pos++, in[i]);
        if (c->pos == c->rate) {
            keccak_f1600(c->s);
            c->pos = 0;
        }
    }
}

void shake_squeeze(shake_ctx *c, uint8_t *out, size_t len) {
    if (!c->squeezing) {
        xor_byte(c, c->pos, 0x1F);            /* SHAKE domain separation + pad start */
        xor_byte(c, c->rate - 1, 0x80);       /* pad end */
        keccak_f1600(c->s);
        c->pos = 0;
        c->squeezing = 1;
    }
    for (size_t i = 0; i < len; i++) {
        if (c->pos == c->rate) {
            keccak_f1600(c->s);
            c->pos = 0;
        }
        out[i] = get_byte(c, c->pos++);
    }
}

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake_ctx c;
    shake128_init(&c);
    shake_absorb(&c, in, inlen);
    shake_squeeze(&c, out, outlen);
    shake_clear(&c);
}
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake_ctx c;
    shake256_init(&c);
    shake_absorb(&c, in, inlen);
    shake_squeeze(&c, out, outlen);
    shake_clear(&c);
}

void shake_clear(shake_ctx *c) {
    volatile uint8_t *p = (volatile uint8_t *)c;
    for (size_t i = 0; i < sizeof *c; i++) p[i] = 0;
}
