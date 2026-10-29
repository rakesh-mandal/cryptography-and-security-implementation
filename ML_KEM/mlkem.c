#include <string.h>
#include "mlkem.h"
#include "kpke.h"
#include "crypto.h"
#include "general.h"

void mlkem_keygen_internal(const mlkem_params *p, uint8_t *ek, uint8_t *dk,
                           const uint8_t d[32], const uint8_t z[32]) {          /* Alg 16 */
    int k = p->k;
    kpke_keygen(p, ek, dk, d);                         /* dk = dk_PKE */
    size_t ekl = 384 * (size_t)k + 32;
    memcpy(dk + 384 * k, ek, ekl);                     /* || ek       */
    mlkem_H(dk + 384 * k + ekl, ek, ekl);              /* || H(ek)    */
    memcpy(dk + 384 * k + ekl + 32, z, 32);            /* || z        */
}

void mlkem_encaps_internal(const mlkem_params *p, uint8_t K[32], uint8_t *c,
                           const uint8_t *ek, const uint8_t m[32]) {            /* Alg 17 */
    uint8_t in[64], g[64];
    memcpy(in, m, 32);
    mlkem_H(in + 32, ek, mlkem_ek_bytes(p));           /* m || H(ek) */
    mlkem_G(g, in, 64);                                /* (K, r)     */
    memcpy(K, g, 32);
    kpke_encrypt(p, c, ek, m, g + 32);
    mlkem_cleanse(g, sizeof g);
}

void mlkem_decaps_internal(const mlkem_params *p, uint8_t K[32], const uint8_t *dk, const uint8_t *c) { /* Alg 18 */
    int k = p->k;
    size_t ekl = 384 * (size_t)k + 32, ctl = mlkem_ct_bytes(p);
    const uint8_t *dk_pke = dk;
    const uint8_t *ek_pke = dk + 384 * k;
    const uint8_t *h      = dk + 384 * k + ekl;
    const uint8_t *z      = dk + 384 * k + ekl + 32;

    uint8_t m[32], in[64], g[64], Kbar[32], c2[MLKEM_CT_MAX], zc[32 + MLKEM_CT_MAX];

    kpke_decrypt(p, m, dk_pke, c);
    memcpy(in, m, 32); memcpy(in + 32, h, 32);
    mlkem_G(g, in, 64);                                /* (K', r') */

    memcpy(zc, z, 32); memcpy(zc + 32, c, ctl);
    mlkem_J(Kbar, zc, 32 + ctl);                       /* implicit-rejection key */

    kpke_encrypt(p, c2, ek_pke, m, g + 32);            /* re-encrypt */

    uint8_t eq = mlkem_ct_equal_mask(c, c2, ctl);      /* 0xFF if equal */
    for (int i = 0; i < 32; i++)                       /* constant-time select */
        K[i] = Kbar[i] ^ (eq & (g[i] ^ Kbar[i]));

    mlkem_cleanse(m, sizeof m); mlkem_cleanse(g, sizeof g); mlkem_cleanse(Kbar, sizeof Kbar);
}

/* ---------- input checks ---------- */
int mlkem_check_ek(const mlkem_params *p, const uint8_t *ek) {
    uint16_t F[MLKEM_N];
    uint8_t  B[384];
    for (int i = 0; i < p->k; i++) {
        ByteDecode(F, ek + 384 * i, 12);
        ByteEncode(B, F, 12);
        if (memcmp(B, ek + 384 * i, 384) != 0) return -1;
    }
    return 0;
}
int mlkem_check_dk(const mlkem_params *p, const uint8_t *dk) {
    size_t ekl = 384 * (size_t)p->k + 32;
    uint8_t h[32];
    mlkem_H(h, dk + 384 * p->k, ekl);
    return mlkem_ct_equal_mask(h, dk + 384 * p->k + ekl, 32) == 0xFF ? 0 : -1;
}

/* ---------- external algorithms ---------- */
int mlkem_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk) {             /* Alg 19 */
    uint8_t d[32], z[32];
    if (mlkem_randombytes(d, 32) || mlkem_randombytes(z, 32)) return -1;
    mlkem_keygen_internal(p, ek, dk, d, z);
    mlkem_cleanse(d, 32); mlkem_cleanse(z, 32);
    return 0;
}
int mlkem_encaps(const mlkem_params *p, uint8_t K[32], uint8_t *c, const uint8_t *ek) { /* Alg 20 */
    uint8_t m[32];
    if (mlkem_check_ek(p, ek)) return -2;
    if (mlkem_randombytes(m, 32)) return -1;
    mlkem_encaps_internal(p, K, c, ek, m);
    mlkem_cleanse(m, 32);
    return 0;
}
int mlkem_decaps(const mlkem_params *p, uint8_t K[32], const uint8_t *dk, const uint8_t *c) { /* Alg 21 */
    if (mlkem_check_dk(p, dk)) return -3;
    mlkem_decaps_internal(p, K, dk, c);
    return 0;
}
