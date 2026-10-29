/* FIPS 203, Section 4.2: General algorithms
 *  4.2.1 Conversion and compression: Alg 3-6, Compress/Decompress (Eq 4.7/4.8)
 *  4.2.2 Sampling: Alg 7 SampleNTT, Alg 8 SamplePolyCBD
 */
#ifndef MLKEM_GENERAL_H
#define MLKEM_GENERAL_H
#include "params.h"

/* Alg 3: bit array (one bit per byte, length 8*l) -> l bytes */
void BitsToBytes(uint8_t *B, const uint8_t *b, size_t l);
/* Alg 4: l bytes -> bit array (length 8*l, one bit per byte) */
void BytesToBits(uint8_t *b, const uint8_t *B, size_t l);

/* Alg 5: encode 256 d-bit integers into 32*d bytes (1 <= d <= 12) */
void ByteEncode(uint8_t *B, const uint16_t F[MLKEM_N], int d);
/* Alg 6: decode 32*d bytes into 256 integers mod m (m = 2^d, or q when d = 12) */
void ByteDecode(uint16_t F[MLKEM_N], const uint8_t *B, int d);

/* Compress_d / Decompress_d on a scalar and on a whole polynomial */
uint16_t Compress(uint16_t x, int d);
uint16_t Decompress(uint16_t y, int d);
void poly_compress(uint16_t f[MLKEM_N], int d);
void poly_decompress(uint16_t f[MLKEM_N], int d);

/* Alg 7: B is 34 bytes (rho || j || i); output a in NTT domain */
void SampleNTT(uint16_t a[MLKEM_N], const uint8_t B[34]);
/* Alg 8: B is 64*eta bytes; output f in R_q with small coefficients */
void SamplePolyCBD(uint16_t f[MLKEM_N], const uint8_t *B, int eta);

#endif
