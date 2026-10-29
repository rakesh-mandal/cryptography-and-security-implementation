#include <string.h>
#include "general.h"
#include "crypto.h"

/* ---------- 4.2.1 Conversion ---------- */
void BitsToBytes(uint8_t *B, const uint8_t *b, size_t l) {          /* Alg 3 */
    memset(B, 0, l);
    for (size_t i = 0; i < 8 * l; i++)
        B[i / 8] |= (uint8_t)(b[i] << (i % 8));
}
void BytesToBits(uint8_t *b, const uint8_t *B, size_t l) {          /* Alg 4 */
    for (size_t i = 0; i < l; i++)
        for (int j = 0; j < 8; j++)
            b[8 * i + j] = (B[i] >> j) & 1;
}
void ByteEncode(uint8_t *B, const uint16_t F[MLKEM_N], int d) {     /* Alg 5 */
    uint8_t b[MLKEM_N * 12];
    for (int i = 0; i < MLKEM_N; i++) {
        uint16_t a = F[i];
        for (int j = 0; j < d; j++) { b[i * d + j] = a & 1; a >>= 1; }
    }
    BitsToBytes(B, b, 32 * (size_t)d);
}
void ByteDecode(uint16_t F[MLKEM_N], const uint8_t *B, int d) {     /* Alg 6 */
    uint8_t b[MLKEM_N * 12];
    BytesToBits(b, B, 32 * (size_t)d);
    for (int i = 0; i < MLKEM_N; i++) {
        uint32_t v = 0;
        for (int j = 0; j < d; j++) v |= (uint32_t)b[i * d + j] << j;
        F[i] = (uint16_t)(d < 12 ? v : v % MLKEM_Q);     /* mod m */
    }
}

/* ---------- 4.2.1 Compression ---------- */
/* Compress_d(x) = round(2^d / q * x) mod 2^d.  Division by the constant q is
 * turned into a multiply by the compiler, so no variable-time divide on secrets. */
uint16_t Compress(uint16_t x, int d) {
    uint32_t t = ((uint32_t)x << d) + (MLKEM_Q / 2);
    return (uint16_t)((t / MLKEM_Q) & ((1u << d) - 1));
}
/* Decompress_d(y) = round(q / 2^d * y) */
uint16_t Decompress(uint16_t y, int d) {
    return (uint16_t)(((uint32_t)y * MLKEM_Q + (1u << (d - 1))) >> d);
}
void poly_compress(uint16_t f[MLKEM_N], int d)   { for (int i = 0; i < MLKEM_N; i++) f[i] = Compress(f[i], d); }
void poly_decompress(uint16_t f[MLKEM_N], int d) { for (int i = 0; i < MLKEM_N; i++) f[i] = Decompress(f[i], d); }

/* ---------- 4.2.2 Sampling ---------- */
void SampleNTT(uint16_t a[MLKEM_N], const uint8_t B[34]) {          /* Alg 7 */
    xof_ctx ctx;
    uint8_t C[3];
    xof_init(&ctx);
    xof_absorb(&ctx, B, 34);
    int j = 0;
    while (j < MLKEM_N) {
        xof_squeeze(&ctx, C, 3);
        uint16_t d1 = (uint16_t)(C[0] + 256 * (C[1] & 0x0F));
        uint16_t d2 = (uint16_t)((C[1] >> 4) + 16 * C[2]);
        if (d1 < MLKEM_Q) a[j++] = d1;        /* public data (rho): variable time is fine */
        if (d2 < MLKEM_Q && j < MLKEM_N) a[j++] = d2;
    }
}
void SamplePolyCBD(uint16_t f[MLKEM_N], const uint8_t *B, int eta) { /* Alg 8 */
    uint8_t b[64 * 3 * 8];
    BytesToBits(b, B, 64 * (size_t)eta);
    for (int i = 0; i < MLKEM_N; i++) {
        int x = 0, y = 0;
        for (int j = 0; j < eta; j++) {
            x += b[2 * i * eta + j];
            y += b[2 * i * eta + eta + j];
        }
        f[i] = (uint16_t)((x - y + MLKEM_Q) % MLKEM_Q);
    }
    mlkem_cleanse(b, sizeof b);
}
