/* ML-DSA per NIST FIPS 204. Straightforward, spec-following implementation. */
#include <stdlib.h>
#include <string.h>
#include "mldsa.h"
#include "fips202.h"

#define Q 8380417
#define N 256
#define D 13
#define MAX_K 8
#define MAX_L 7

typedef struct { int32_t c[N]; } poly;

/* zetas[i] = 1753^brv8(i) mod q (FIPS 204 Appendix B) */
static const int32_t zetas[256] = {
#include "mldsa_zetas.h"
};

/* ------------------------------------------------------------------ */
/* Parameter sets (FIPS 204 Table 1)                                   */
/* ------------------------------------------------------------------ */
typedef struct {
    int k, l, eta, tau, beta, gamma1, gamma2, omega;
    int ctilde;      /* lambda/4 bytes */
    int eta_bits, gamma1_bits, w1_bits;
    size_t pk, sk, sig;
} params;

static int get_params(int level, params *p) {
    switch (level) {
    case MLDSA_44: p->k=4; p->l=4; p->eta=2; p->tau=39; p->beta=78;  p->gamma1=1<<17; p->gamma2=(Q-1)/88; p->omega=80; p->ctilde=32; break;
    case MLDSA_65: p->k=6; p->l=5; p->eta=4; p->tau=49; p->beta=196; p->gamma1=1<<19; p->gamma2=(Q-1)/32; p->omega=55; p->ctilde=48; break;
    case MLDSA_87: p->k=8; p->l=7; p->eta=2; p->tau=60; p->beta=120; p->gamma1=1<<19; p->gamma2=(Q-1)/32; p->omega=75; p->ctilde=64; break;
    default: return MLDSA_ERR_PARAM;
    }
    p->eta_bits    = (p->eta == 2) ? 3 : 4;                 /* bitlen(2*eta) */
    p->gamma1_bits = (p->gamma1 == (1 << 17)) ? 18 : 20;    /* 1 + bitlen(gamma1-1) */
    p->w1_bits     = (p->gamma2 == (Q - 1) / 88) ? 6 : 4;   /* bitlen((q-1)/(2*gamma2) - 1) */
    p->pk  = 32 + 32 * (size_t)p->k * 10;
    p->sk  = 128 + 32 * ((size_t)(p->k + p->l) * p->eta_bits + (size_t)D * p->k);
    p->sig = (size_t)p->ctilde + 32 * (size_t)p->l * p->gamma1_bits + p->omega + p->k;
    return 0;
}

size_t mldsa_pk_bytes(int level)  { params p; return get_params(level, &p) ? 0 : p.pk; }
size_t mldsa_sk_bytes(int level)  { params p; return get_params(level, &p) ? 0 : p.sk; }
size_t mldsa_sig_bytes(int level) { params p; return get_params(level, &p) ? 0 : p.sig; }

static void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* ------------------------------------------------------------------ */
/* Modular arithmetic; "mod q" values are kept in [0, q)               */
/* ------------------------------------------------------------------ */
static inline int32_t caddq(int32_t a) { return a + ((a >> 31) & Q); }       /* a in (-q,q) -> [0,q) */
static inline int32_t addq(int32_t a, int32_t b) { int32_t r = a + b - Q; return r + ((r >> 31) & Q); }
static inline int32_t subq(int32_t a, int32_t b) { int32_t r = a - b;     return r + ((r >> 31) & Q); }
static inline int32_t mulq(int32_t a, int32_t b) { return (int32_t)(((uint64_t)(uint32_t)a * (uint32_t)b) % Q); }

/* [0,q) -> (-(q-1)/2, (q-1)/2] */
static inline int32_t center(int32_t a) { return a - ((((Q - 1) / 2) - a) >> 31 & Q); }
static inline int32_t abs_signed(int32_t a) { int32_t t = a >> 31; return (a ^ t) - t; }
static inline int32_t abs_centered(int32_t a) { return abs_signed(center(a)); }

/* FIPS 204 Alg. 41 */
static void ntt(poly *a) {
    unsigned m = 0;
    for (unsigned len = 128; len >= 1; len >>= 1)
        for (unsigned start = 0; start < N; start += 2 * len) {
            int32_t z = zetas[++m];
            for (unsigned j = start; j < start + len; j++) {
                int32_t t = mulq(z, a->c[j + len]);
                a->c[j + len] = subq(a->c[j], t);
                a->c[j]       = addq(a->c[j], t);
            }
        }
}
/* FIPS 204 Alg. 42 */
static void invntt(poly *a) {
    unsigned m = 256;
    for (unsigned len = 1; len < N; len <<= 1)
        for (unsigned start = 0; start < N; start += 2 * len) {
            int32_t z = Q - zetas[--m];
            for (unsigned j = start; j < start + len; j++) {
                int32_t t = a->c[j];
                a->c[j]       = addq(t, a->c[j + len]);
                a->c[j + len] = mulq(z, subq(t, a->c[j + len]));
            }
        }
    for (unsigned i = 0; i < N; i++) a->c[i] = mulq(a->c[i], 8347681); /* 256^-1 mod q */
}
static void poly_caddq(poly *a) { for (int i = 0; i < N; i++) a->c[i] = caddq(a->c[i]); }
static void poly_mul(poly *r, const poly *a, const poly *b) { for (int i = 0; i < N; i++) r->c[i] = mulq(a->c[i], b->c[i]); }
static void poly_muladd(poly *r, const poly *a, const poly *b) { for (int i = 0; i < N; i++) r->c[i] = addq(r->c[i], mulq(a->c[i], b->c[i])); }

/* ------------------------------------------------------------------ */
/* Rounding (FIPS 204 Alg. 35-40)                                      */
/* ------------------------------------------------------------------ */
static void power2round(int32_t a, int32_t *a1, int32_t *a0) {  /* a in [0,q) */
    int32_t r0 = a & ((1 << D) - 1);
    r0 -= (((1 << (D - 1)) - r0) >> 31) & (1 << D);             /* mods 2^d -> (-2^12, 2^12] */
    *a0 = r0;
    *a1 = (a - r0) >> D;
}

/* Decompose, a in [0,q). Returns r1, sets *r0. Branch-free on the data. */
static int32_t decompose(int32_t a, int gamma2, int32_t *r0) {
    int32_t a1 = (a + 127) >> 7;
    if (gamma2 == (Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    int32_t a0 = a - a1 * 2 * gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    *r0 = a0;
    return a1;
}
static inline int32_t highbits(int32_t a, int gamma2) { int32_t r0; return decompose(a, gamma2, &r0); }

/* UseHint, FIPS 204 Alg. 40 */
static int32_t use_hint(int h, int32_t r, int gamma2) {
    int32_t r0, r1 = decompose(r, gamma2, &r0);
    int32_t m = (gamma2 == (Q - 1) / 88) ? 44 : 16;
    if (!h) return r1;
    if (r0 > 0) return (r1 + 1 == m) ? 0 : r1 + 1;
    return (r1 == 0) ? m - 1 : r1 - 1;
}

/* ------------------------------------------------------------------ */
/* Bit packing (FIPS 204 Alg. 16-19)                                   */
/* ------------------------------------------------------------------ */
static void pack_core(uint8_t *out, const uint32_t *v, unsigned bits) {
    uint64_t acc = 0; unsigned nb = 0; size_t o = 0;
    for (int i = 0; i < N; i++) {
        acc |= (uint64_t)v[i] << nb; nb += bits;
        while (nb >= 8) { out[o++] = (uint8_t)acc; acc >>= 8; nb -= 8; }
    }
}
static void unpack_core(uint32_t *v, const uint8_t *in, unsigned bits) {
    uint64_t acc = 0; unsigned nb = 0; size_t ip = 0; uint32_t mask = (1u << bits) - 1;
    for (int i = 0; i < N; i++) {
        while (nb < bits) { acc |= (uint64_t)in[ip++] << nb; nb += 8; }
        v[i] = (uint32_t)acc & mask; acc >>= bits; nb -= bits;
    }
}
/* BitPack(w, a, b): stores b - w_i */
static void pack_off(uint8_t *out, const poly *p, unsigned bits, int32_t b) {
    uint32_t v[N]; for (int i = 0; i < N; i++) v[i] = (uint32_t)(b - p->c[i]);
    pack_core(out, v, bits);
}
static void unpack_off(poly *p, const uint8_t *in, unsigned bits, int32_t b) {
    uint32_t v[N]; unpack_core(v, in, bits);
    for (int i = 0; i < N; i++) p->c[i] = b - (int32_t)v[i];
}
/* SimpleBitPack */
static void pack_simple(uint8_t *out, const poly *p, unsigned bits) {
    uint32_t v[N]; for (int i = 0; i < N; i++) v[i] = (uint32_t)p->c[i];
    pack_core(out, v, bits);
}
static void unpack_simple(poly *p, const uint8_t *in, unsigned bits) {
    uint32_t v[N]; unpack_core(v, in, bits);
    for (int i = 0; i < N; i++) p->c[i] = (int32_t)v[i];
}

/* HintBitPack, Alg. 20. h is k x 256 of 0/1 */
static void hint_pack(uint8_t *y, const uint8_t h[][N], const params *P) {
    memset(y, 0, (size_t)P->omega + P->k);
    unsigned idx = 0;
    for (int i = 0; i < P->k; i++) {
        for (int j = 0; j < N; j++) if (h[i][j]) y[idx++] = (uint8_t)j;
        y[P->omega + i] = (uint8_t)idx;
    }
}
/* HintBitUnpack, Alg. 21. returns 0 ok, -1 malformed */
static int hint_unpack(uint8_t h[][N], const uint8_t *y, const params *P) {
    memset(h, 0, (size_t)P->k * N);
    unsigned idx = 0;
    for (int i = 0; i < P->k; i++) {
        unsigned end = y[P->omega + i];
        if (end < idx || end > (unsigned)P->omega) return -1;
        unsigned first = idx;
        while (idx < end) {
            if (idx > first && y[idx - 1] >= y[idx]) return -1;
            h[i][y[idx]] = 1;
            idx++;
        }
    }
    for (unsigned i = idx; i < (unsigned)P->omega; i++) if (y[i]) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Sampling (FIPS 204 Alg. 29-34)                                      */
/* ------------------------------------------------------------------ */
/* ExpandA entry: A[r][s] = RejNTTPoly(rho || s || r)  (already in NTT domain) */
static void sample_a_entry(poly *a, const uint8_t rho[32], uint8_t s, uint8_t r) {
    shake_ctx c; uint8_t seed[34], buf[SHAKE128_RATE];
    memcpy(seed, rho, 32); seed[32] = s; seed[33] = r;
    shake128_init(&c); shake_absorb(&c, seed, 34);
    int i = 0;
    while (i < N) {
        shake_squeeze(&c, buf, sizeof buf);
        for (unsigned j = 0; j + 3 <= sizeof buf && i < N; j += 3) {
            int32_t z = buf[j] | (buf[j + 1] << 8) | ((buf[j + 2] & 0x7f) << 16);
            if (z < Q) a->c[i++] = z;
        }
    }
    shake_clear(&c);
}

/* RejBoundedPoly(rho' || IntegerToBytes(idx, 2)); coefficients signed in [-eta, eta] */
static void rej_bounded_poly(poly *a, const uint8_t rho[64], uint16_t idx, int eta) {
    shake_ctx c; uint8_t seed[66], buf[SHAKE256_RATE];
    memcpy(seed, rho, 64); seed[64] = (uint8_t)idx; seed[65] = (uint8_t)(idx >> 8);
    shake256_init(&c); shake_absorb(&c, seed, 66);
    int i = 0;
    while (i < N) {
        shake_squeeze(&c, buf, sizeof buf);
        for (unsigned j = 0; j < sizeof buf && i < N; j++) {
            for (int h = 0; h < 2 && i < N; h++) {
                int z = h ? (buf[j] >> 4) : (buf[j] & 15);
                if (eta == 2) { if (z < 15) a->c[i++] = 2 - (z % 5); }
                else          { if (z < 9)  a->c[i++] = 4 - z; }
            }
        }
    }
    secure_zero(seed, sizeof seed);
    shake_clear(&c);
}

/* ExpandMask for one polynomial: BitUnpack(H(rho'' || (kappa+r)), gamma1-1, gamma1) */
static void expand_mask_poly(poly *y, const uint8_t rho2[64], unsigned kappa_r, const params *P) {
    uint8_t seed[66], buf[32 * 20];
    memcpy(seed, rho2, 64); seed[64] = (uint8_t)kappa_r; seed[65] = (uint8_t)(kappa_r >> 8);
    shake256(buf, 32 * (size_t)P->gamma1_bits, seed, 66);
    unpack_off(y, buf, P->gamma1_bits, P->gamma1);
    secure_zero(seed, sizeof seed); secure_zero(buf, sizeof buf);
}

/* SampleInBall, Alg. 29. c gets coefficients in {-1,0,1}. */
static void sample_in_ball(poly *c, const uint8_t *seed, size_t seedlen, int tau) {
    shake_ctx s; uint8_t sb[8], j;
    shake256_init(&s); shake_absorb(&s, seed, seedlen);
    shake_squeeze(&s, sb, 8);
    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) signs |= (uint64_t)sb[i] << (8 * i);
    memset(c, 0, sizeof *c);
    for (int i = N - tau; i < N; i++) {
        do { shake_squeeze(&s, &j, 1); } while (j > i);
        c->c[i] = c->c[j];
        c->c[j] = 1 - 2 * (int32_t)((signs >> (i + tau - N)) & 1);
    }
    shake_clear(&s);
}

/* ------------------------------------------------------------------ */
/* Key / signature encodings                                           */
/* ------------------------------------------------------------------ */
static void w1_encode(uint8_t *out, poly w1[], const params *P) {
    for (int r = 0; r < P->k; r++) pack_simple(out + (size_t)r * 32 * P->w1_bits, &w1[r], P->w1_bits);
}

/* ------------------------------------------------------------------ */
/* KeyGen_internal (Alg. 6 / 1)                                        */
/* ------------------------------------------------------------------ */
int mldsa_keygen_internal(int level, uint8_t *pk, uint8_t *sk, const uint8_t xi[32]) {
    params P; int rc = get_params(level, &P);
    if (rc) return rc;
    if (!pk || !sk || !xi) return MLDSA_ERR_PARAM;

    uint8_t seedbuf[128], in[34];
    memcpy(in, xi, 32); in[32] = (uint8_t)P.k; in[33] = (uint8_t)P.l;
    shake256(seedbuf, 128, in, 34);
    const uint8_t *rho = seedbuf, *rhop = seedbuf + 32, *K = seedbuf + 96;

    poly s1[MAX_L], s2[MAX_K], s1h[MAX_L], t1[MAX_K], t0[MAX_K], tmp, aij;
    for (int r = 0; r < P.l; r++) rej_bounded_poly(&s1[r], rhop, (uint16_t)r, P.eta);
    for (int r = 0; r < P.k; r++) rej_bounded_poly(&s2[r], rhop, (uint16_t)(r + P.l), P.eta);

    for (int r = 0; r < P.l; r++) { s1h[r] = s1[r]; poly_caddq(&s1h[r]); ntt(&s1h[r]); }

    memcpy(pk, rho, 32);
    for (int r = 0; r < P.k; r++) {
        memset(&tmp, 0, sizeof tmp);
        for (int s = 0; s < P.l; s++) {
            sample_a_entry(&aij, rho, (uint8_t)s, (uint8_t)r);
            poly_muladd(&tmp, &aij, &s1h[s]);
        }
        invntt(&tmp);
        for (int i = 0; i < N; i++) {
            int32_t t = addq(tmp.c[i], caddq(s2[r].c[i]));
            power2round(t, &t1[r].c[i], &t0[r].c[i]);
        }
        pack_simple(pk + 32 + (size_t)r * 320, &t1[r], 10);
    }

    uint8_t tr[64];
    shake256(tr, 64, pk, P.pk);

    uint8_t *o = sk;
    memcpy(o, rho, 32); o += 32;
    memcpy(o, K, 32);   o += 32;
    memcpy(o, tr, 64);  o += 64;
    for (int r = 0; r < P.l; r++) { pack_off(o, &s1[r], P.eta_bits, P.eta); o += 32 * P.eta_bits; }
    for (int r = 0; r < P.k; r++) { pack_off(o, &s2[r], P.eta_bits, P.eta); o += 32 * P.eta_bits; }
    for (int r = 0; r < P.k; r++) { pack_off(o, &t0[r], D, 1 << (D - 1));   o += 32 * D; }

    secure_zero(seedbuf, sizeof seedbuf); secure_zero(in, sizeof in);
    secure_zero(s1, sizeof s1); secure_zero(s2, sizeof s2); secure_zero(s1h, sizeof s1h);
    secure_zero(t0, sizeof t0); secure_zero(&tmp, sizeof tmp);
    return MLDSA_OK;
}

int mldsa_keygen(int level, uint8_t *pk, uint8_t *sk) {
    uint8_t xi[32];
    if (mldsa_randombytes(xi, 32)) return MLDSA_ERR_RNG;
    int rc = mldsa_keygen_internal(level, pk, sk, xi);
    secure_zero(xi, sizeof xi);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Sign_internal (Alg. 7)                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    poly A[MAX_K * MAX_L];
    poly s1h[MAX_L], s2h[MAX_K], t0h[MAX_K];
    poly y[MAX_L], z[MAX_L], w[MAX_K];
    poly c, chat, tmp, tmp2;
    uint8_t h[MAX_K][N];
} sign_state;

int mldsa_sign_internal(int level, uint8_t *sig, size_t *siglen,
                        const uint8_t *pre, size_t prelen,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *sk, const uint8_t rnd[32]) {
    params P; int rc = get_params(level, &P);
    if (rc) return rc;
    if (!sig || !siglen || !sk || !rnd || (prelen && !pre) || (msglen && !msg)) return MLDSA_ERR_PARAM;

    sign_state *S = (sign_state *)calloc(1, sizeof *S);
    if (!S) return MLDSA_ERR_MEM;

    uint8_t rho[32], K[32], tr[64], mu[64], rho2[64], ctilde[64], w1enc[MAX_K * 32 * 6];
    const uint8_t *p = sk;
    memcpy(rho, p, 32); p += 32;
    memcpy(K, p, 32);   p += 32;
    memcpy(tr, p, 64);  p += 64;
    for (int r = 0; r < P.l; r++) { unpack_off(&S->tmp, p, P.eta_bits, P.eta); p += 32 * P.eta_bits; S->s1h[r] = S->tmp; poly_caddq(&S->s1h[r]); ntt(&S->s1h[r]); }
    for (int r = 0; r < P.k; r++) { unpack_off(&S->tmp, p, P.eta_bits, P.eta); p += 32 * P.eta_bits; S->s2h[r] = S->tmp; poly_caddq(&S->s2h[r]); ntt(&S->s2h[r]); }
    for (int r = 0; r < P.k; r++) { unpack_off(&S->tmp, p, D, 1 << (D - 1));   p += 32 * D;           S->t0h[r] = S->tmp; poly_caddq(&S->t0h[r]); ntt(&S->t0h[r]); }

    for (int r = 0; r < P.k; r++)
        for (int s = 0; s < P.l; s++) sample_a_entry(&S->A[r * P.l + s], rho, (uint8_t)s, (uint8_t)r);

    /* mu = H(tr || M', 64) */
    {
        shake_ctx h; shake256_init(&h);
        shake_absorb(&h, tr, 64); shake_absorb(&h, pre, prelen); shake_absorb(&h, msg, msglen);
        shake_squeeze(&h, mu, 64); shake_clear(&h);
    }
    /* rho'' = H(K || rnd || mu, 64) */
    {
        shake_ctx h; shake256_init(&h);
        shake_absorb(&h, K, 32); shake_absorb(&h, rnd, 32); shake_absorb(&h, mu, 64);
        shake_squeeze(&h, rho2, 64); shake_clear(&h);
    }

    rc = MLDSA_ERR_SIGN;
    for (unsigned kappa = 0; kappa + P.l <= 65535u; kappa += P.l) {
        /* y = ExpandMask; w = NTT^-1(A * NTT(y)); w1 = HighBits(w) */
        for (int r = 0; r < P.l; r++) {
            expand_mask_poly(&S->y[r], rho2, kappa + r, &P);
            S->tmp = S->y[r]; poly_caddq(&S->tmp); ntt(&S->tmp);
            S->z[r] = S->tmp;                               /* z[] temporarily holds NTT(y) */
        }
        for (int r = 0; r < P.k; r++) {
            memset(&S->w[r], 0, sizeof(poly));
            for (int s = 0; s < P.l; s++) poly_muladd(&S->w[r], &S->A[r * P.l + s], &S->z[s]);
            invntt(&S->w[r]);
            for (int i = 0; i < N; i++) S->tmp.c[i] = highbits(S->w[r].c[i], P.gamma2);
            pack_simple(w1enc + (size_t)r * 32 * P.w1_bits, &S->tmp, P.w1_bits);
        }
        /* c~ = H(mu || w1Encode(w1), lambda/4); c = SampleInBall(c~) */
        {
            shake_ctx h; shake256_init(&h);
            shake_absorb(&h, mu, 64); shake_absorb(&h, w1enc, (size_t)P.k * 32 * P.w1_bits);
            shake_squeeze(&h, ctilde, P.ctilde); shake_clear(&h);
        }
        sample_in_ball(&S->c, ctilde, P.ctilde, P.tau);
        S->chat = S->c; poly_caddq(&S->chat); ntt(&S->chat);

        /* z = y + c*s1 ; reject if ||z||inf >= gamma1 - beta */
        int32_t bad = 0;
        for (int s = 0; s < P.l; s++) {
            poly_mul(&S->tmp, &S->chat, &S->s1h[s]); invntt(&S->tmp);
            for (int i = 0; i < N; i++) {
                int32_t zc = addq(caddq(S->y[s].c[i]), S->tmp.c[i]);
                S->z[s].c[i] = zc;
                bad |= (abs_centered(zc) >= P.gamma1 - P.beta);
            }
        }
        if (bad) continue;

        /* w - c*s2 ; reject if ||LowBits||inf >= gamma2 - beta */
        for (int r = 0; r < P.k; r++) {
            poly_mul(&S->tmp, &S->chat, &S->s2h[r]); invntt(&S->tmp);
            for (int i = 0; i < N; i++) {
                int32_t v = subq(S->w[r].c[i], S->tmp.c[i]), r0;
                S->w[r].c[i] = v;
                (void)decompose(v, P.gamma2, &r0);
                bad |= (abs_signed(r0) >= P.gamma2 - P.beta);
            }
        }
        if (bad) continue;

        /* ct0 ; hint = MakeHint(-ct0, w - cs2 + ct0) */
        unsigned ones = 0;
        for (int r = 0; r < P.k; r++) {
            poly_mul(&S->tmp, &S->chat, &S->t0h[r]); invntt(&S->tmp);
            for (int i = 0; i < N; i++) {
                int32_t ct0 = S->tmp.c[i];
                bad |= (abs_centered(ct0) >= P.gamma2);
                int32_t a = highbits(addq(S->w[r].c[i], ct0), P.gamma2);
                int32_t b = highbits(S->w[r].c[i], P.gamma2);
                S->h[r][i] = (uint8_t)(a != b);
                ones += S->h[r][i];
            }
        }
        if (bad || ones > (unsigned)P.omega) continue;

        /* sigma = c~ || BitPack(z mod+- q) || HintBitPack(h) */
        uint8_t *o = sig;
        memcpy(o, ctilde, P.ctilde); o += P.ctilde;
        for (int s = 0; s < P.l; s++) {
            for (int i = 0; i < N; i++) S->tmp.c[i] = center(S->z[s].c[i]);
            pack_off(o, &S->tmp, P.gamma1_bits, P.gamma1); o += 32 * P.gamma1_bits;
        }
        hint_pack(o, (const uint8_t (*)[N])S->h, &P);
        *siglen = P.sig;
        rc = MLDSA_OK;
        break;
    }

    secure_zero(S, sizeof *S); free(S);
    secure_zero(K, sizeof K); secure_zero(rho2, sizeof rho2);
    return rc;
}

int mldsa_sign(int level, uint8_t *sig, size_t *siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t *ctx, size_t ctxlen,
               const uint8_t *sk, const uint8_t rnd_in[32]) {
    if (ctxlen > 255 || (ctxlen && !ctx)) return MLDSA_ERR_PARAM;
    uint8_t rnd[32], pre[2 + 255];
    if (rnd_in) memcpy(rnd, rnd_in, 32);
    else if (mldsa_randombytes(rnd, 32)) return MLDSA_ERR_RNG;
    pre[0] = 0; pre[1] = (uint8_t)ctxlen;               /* domain sep: pure ML-DSA */
    if (ctxlen) memcpy(pre + 2, ctx, ctxlen);
    int rc = mldsa_sign_internal(level, sig, siglen, pre, 2 + ctxlen, m, mlen, sk, rnd);
    secure_zero(rnd, sizeof rnd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verify_internal (Alg. 8)                                            */
/* ------------------------------------------------------------------ */
int mldsa_verify_internal(int level, const uint8_t *sig, size_t siglen,
                          const uint8_t *pre, size_t prelen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *pk) {
    params P; int rc = get_params(level, &P);
    if (rc) return rc;
    if (!sig || !pk || (prelen && !pre) || (msglen && !msg)) return MLDSA_ERR_PARAM;
    if (siglen != P.sig) return MLDSA_ERR_VERIFY;

    poly z[MAX_L], zh[MAX_L], t1h[MAX_K], w1[MAX_K], c, chat, aij, acc, tmp;
    uint8_t h[MAX_K][N], ctilde[64], ctilde2[64], tr[64], mu[64], w1enc[MAX_K * 32 * 6];

    const uint8_t *p = sig;
    memcpy(ctilde, p, P.ctilde); p += P.ctilde;
    for (int s = 0; s < P.l; s++) { unpack_off(&z[s], p, P.gamma1_bits, P.gamma1); p += 32 * P.gamma1_bits; }
    if (hint_unpack(h, p, &P)) return MLDSA_ERR_VERIFY;
    for (int s = 0; s < P.l; s++)
        for (int i = 0; i < N; i++)
            if (abs_signed(z[s].c[i]) >= P.gamma1 - P.beta) return MLDSA_ERR_VERIFY;

    for (int r = 0; r < P.k; r++) {
        unpack_simple(&tmp, pk + 32 + (size_t)r * 320, 10);
        for (int i = 0; i < N; i++) tmp.c[i] <<= D;      /* t1 * 2^d  (< q) */
        t1h[r] = tmp; ntt(&t1h[r]);
    }
    for (int s = 0; s < P.l; s++) { zh[s] = z[s]; poly_caddq(&zh[s]); ntt(&zh[s]); }

    shake256(tr, 64, pk, P.pk);
    {
        shake_ctx hh; shake256_init(&hh);
        shake_absorb(&hh, tr, 64); shake_absorb(&hh, pre, prelen); shake_absorb(&hh, msg, msglen);
        shake_squeeze(&hh, mu, 64); shake_clear(&hh);
    }

    sample_in_ball(&c, ctilde, P.ctilde, P.tau);
    chat = c; poly_caddq(&chat); ntt(&chat);

    for (int r = 0; r < P.k; r++) {
        memset(&acc, 0, sizeof acc);
        for (int s = 0; s < P.l; s++) {
            sample_a_entry(&aij, pk, (uint8_t)s, (uint8_t)r);   /* rho = pk[0..32) */
            poly_muladd(&acc, &aij, &zh[s]);
        }
        poly_mul(&tmp, &chat, &t1h[r]);
        for (int i = 0; i < N; i++) acc.c[i] = subq(acc.c[i], tmp.c[i]);
        invntt(&acc);
        for (int i = 0; i < N; i++) w1[r].c[i] = use_hint(h[r][i], acc.c[i], P.gamma2);
    }
    w1_encode(w1enc, w1, &P);
    {
        shake_ctx hh; shake256_init(&hh);
        shake_absorb(&hh, mu, 64); shake_absorb(&hh, w1enc, (size_t)P.k * 32 * P.w1_bits);
        shake_squeeze(&hh, ctilde2, P.ctilde); shake_clear(&hh);
    }
    uint8_t diff = 0;
    for (int i = 0; i < P.ctilde; i++) diff |= ctilde[i] ^ ctilde2[i];
    return diff ? MLDSA_ERR_VERIFY : MLDSA_OK;
}

int mldsa_verify(int level, const uint8_t *sig, size_t siglen,
                 const uint8_t *m, size_t mlen,
                 const uint8_t *ctx, size_t ctxlen,
                 const uint8_t *pk) {
    if (ctxlen > 255 || (ctxlen && !ctx)) return MLDSA_ERR_PARAM;
    uint8_t pre[2 + 255];
    pre[0] = 0; pre[1] = (uint8_t)ctxlen;
    if (ctxlen) memcpy(pre + 2, ctx, ctxlen);
    return mldsa_verify_internal(level, sig, siglen, pre, 2 + ctxlen, m, mlen, pk);
}
