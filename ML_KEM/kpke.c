#include <string.h>
#include "kpke.h"
#include "crypto.h"
#include "general.h"
#include "ntt.h"

/* A_hat[i][j] = SampleNTT(rho || j || i) */
static void gen_matrix(poly_t A[MLKEM_KMAX][MLKEM_KMAX], const uint8_t rho[32], int k) {
    uint8_t B[34];
    memcpy(B, rho, 32);
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++) {
            B[32] = (uint8_t)j; B[33] = (uint8_t)i;
            SampleNTT(A[i][j], B);
        }
}

void kpke_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk, const uint8_t d[32]) {   /* Alg 13 */
    int k = p->k;
    uint8_t in[33], g[64], buf[64 * 3], N = 0;
    poly_t A[MLKEM_KMAX][MLKEM_KMAX], s[MLKEM_KMAX], e[MLKEM_KMAX], t[MLKEM_KMAX], tmp;

    memcpy(in, d, 32); in[32] = (uint8_t)k;
    mlkem_G(g, in, 33);
    const uint8_t *rho = g, *sigma = g + 32;

    gen_matrix(A, rho, k);
    for (int i = 0; i < k; i++) { mlkem_PRF(p->eta1, buf, sigma, N++); SamplePolyCBD(s[i], buf, p->eta1); }
    for (int i = 0; i < k; i++) { mlkem_PRF(p->eta1, buf, sigma, N++); SamplePolyCBD(e[i], buf, p->eta1); }
    for (int i = 0; i < k; i++) { NTT(s[i]); NTT(e[i]); }

    /* t_hat = A_hat o s_hat + e_hat */
    for (int i = 0; i < k; i++) {
        memcpy(t[i], e[i], sizeof(poly_t));
        for (int j = 0; j < k; j++) {
            MultiplyNTTs(tmp, A[i][j], s[j]);
            poly_add(t[i], t[i], tmp);
        }
    }
    for (int i = 0; i < k; i++) {
        ByteEncode(ek + 384 * i, t[i], 12);
        ByteEncode(dk + 384 * i, s[i], 12);
    }
    memcpy(ek + 384 * k, rho, 32);

    mlkem_cleanse(g, sizeof g); mlkem_cleanse(buf, sizeof buf);
    mlkem_cleanse(s, sizeof s); mlkem_cleanse(e, sizeof e);
}

void kpke_encrypt(const mlkem_params *p, uint8_t *c, const uint8_t *ek,
                  const uint8_t m[32], const uint8_t r[32]) {                                /* Alg 14 */
    int k = p->k;
    uint8_t buf[64 * 3], N = 0;
    poly_t A[MLKEM_KMAX][MLKEM_KMAX], t[MLKEM_KMAX], y[MLKEM_KMAX], e1[MLKEM_KMAX];
    poly_t e2, u[MLKEM_KMAX], v, mu, tmp;

    for (int i = 0; i < k; i++) ByteDecode(t[i], ek + 384 * i, 12);
    gen_matrix(A, ek + 384 * k, k);

    for (int i = 0; i < k; i++) { mlkem_PRF(p->eta1, buf, r, N++); SamplePolyCBD(y[i],  buf, p->eta1); }
    for (int i = 0; i < k; i++) { mlkem_PRF(p->eta2, buf, r, N++); SamplePolyCBD(e1[i], buf, p->eta2); }
    mlkem_PRF(p->eta2, buf, r, N++); SamplePolyCBD(e2, buf, p->eta2);
    for (int i = 0; i < k; i++) NTT(y[i]);

    /* u = NTT^-1(A_hat^T o y_hat) + e1 */
    for (int i = 0; i < k; i++) {
        memset(u[i], 0, sizeof(poly_t));
        for (int j = 0; j < k; j++) {
            MultiplyNTTs(tmp, A[j][i], y[j]);
            poly_add(u[i], u[i], tmp);
        }
        NTT_inv(u[i]);
        poly_add(u[i], u[i], e1[i]);
    }
    /* mu = Decompress_1(ByteDecode_1(m)) */
    ByteDecode(mu, m, 1);
    poly_decompress(mu, 1);
    /* v = NTT^-1(t_hat^T o y_hat) + e2 + mu */
    memset(v, 0, sizeof v);
    for (int j = 0; j < k; j++) {
        MultiplyNTTs(tmp, t[j], y[j]);
        poly_add(v, v, tmp);
    }
    NTT_inv(v);
    poly_add(v, v, e2);
    poly_add(v, v, mu);

    for (int i = 0; i < k; i++) {
        poly_compress(u[i], p->du);
        ByteEncode(c + 32 * p->du * i, u[i], p->du);
    }
    poly_compress(v, p->dv);
    ByteEncode(c + 32 * p->du * k, v, p->dv);

    mlkem_cleanse(buf, sizeof buf); mlkem_cleanse(y, sizeof y);
    mlkem_cleanse(e1, sizeof e1);   mlkem_cleanse(e2, sizeof e2);
    mlkem_cleanse(mu, sizeof mu);
}

void kpke_decrypt(const mlkem_params *p, uint8_t m[32], const uint8_t *dk, const uint8_t *c) { /* Alg 15 */
    int k = p->k;
    poly_t u[MLKEM_KMAX], s[MLKEM_KMAX], v, w, tmp;

    for (int i = 0; i < k; i++) {
        ByteDecode(u[i], c + 32 * p->du * i, p->du);
        poly_decompress(u[i], p->du);
    }
    ByteDecode(v, c + 32 * p->du * k, p->dv);
    poly_decompress(v, p->dv);
    for (int i = 0; i < k; i++) ByteDecode(s[i], dk + 384 * i, 12);

    /* w = v' - NTT^-1(s_hat^T o NTT(u')) */
    memset(w, 0, sizeof w);
    for (int i = 0; i < k; i++) {
        NTT(u[i]);
        MultiplyNTTs(tmp, s[i], u[i]);
        poly_add(w, w, tmp);
    }
    NTT_inv(w);
    poly_sub(w, v, w);

    poly_compress(w, 1);
    ByteEncode(m, w, 1);

    mlkem_cleanse(s, sizeof s); mlkem_cleanse(w, sizeof w);
}
