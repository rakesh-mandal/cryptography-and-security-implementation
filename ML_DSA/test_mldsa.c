#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mldsa.h"
#include "fips202.h"

static int fails = 0;
#define CHECK(c, ...) do { if (!(c)) { printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static void hexdigest(const char *label, const uint8_t *d, size_t n) {
    uint8_t h[16]; shake256(h, 16, d, n);
    printf("  %-4s len=%-5zu shake256[0..16]=", label, n);
    for (int i = 0; i < 16; i++) printf("%02x", h[i]);
    printf("\n");
}

static void test_level(int level, int iters) {
    size_t pkl = mldsa_pk_bytes(level), skl = mldsa_sk_bytes(level), sgl = mldsa_sig_bytes(level);
    printf("ML-DSA-%d  pk=%zu sk=%zu sig=%zu\n", level, pkl, skl, sgl);
    uint8_t *pk = malloc(pkl), *sk = malloc(skl), *sig = malloc(sgl);
    uint8_t xi[32], zero[32] = {0}, msg[300];
    for (int i = 0; i < 32; i++) xi[i] = (uint8_t)i;

    CHECK(mldsa_keygen_internal(level, pk, sk, xi) == 0, "keygen");
    hexdigest("pk", pk, pkl); hexdigest("sk", sk, skl);

    memcpy(msg, "hello ML-DSA", 12);
    size_t siglen = 0;
    CHECK(mldsa_sign(level, sig, &siglen, msg, 12, (const uint8_t *)"ctx", 3, sk, zero) == 0, "sign");
    CHECK(siglen == sgl, "siglen %zu != %zu", siglen, sgl);
    hexdigest("sig", sig, siglen);
    CHECK(mldsa_verify(level, sig, siglen, msg, 12, (const uint8_t *)"ctx", 3, pk) == 0, "verify good");

    /* deterministic */
    uint8_t *sig2 = malloc(sgl); size_t l2;
    mldsa_sign(level, sig2, &l2, msg, 12, (const uint8_t *)"ctx", 3, sk, zero);
    CHECK(memcmp(sig, sig2, sgl) == 0, "deterministic signing differs");
    /* hedged differs, still verifies */
    mldsa_sign(level, sig2, &l2, msg, 12, (const uint8_t *)"ctx", 3, sk, NULL);
    CHECK(memcmp(sig, sig2, sgl) != 0, "hedged equals deterministic?");
    CHECK(mldsa_verify(level, sig2, l2, msg, 12, (const uint8_t *)"ctx", 3, pk) == 0, "verify hedged");

    /* negatives */
    CHECK(mldsa_verify(level, sig, siglen, msg, 11, (const uint8_t *)"ctx", 3, pk) != 0, "wrong msg accepted");
    CHECK(mldsa_verify(level, sig, siglen, msg, 12, (const uint8_t *)"cty", 3, pk) != 0, "wrong ctx accepted");
    CHECK(mldsa_verify(level, sig, siglen, msg, 12, NULL, 0, pk) != 0, "missing ctx accepted");
    CHECK(mldsa_verify(level, sig, siglen - 1, msg, 12, (const uint8_t *)"ctx", 3, pk) != 0, "short sig accepted");
    int accepted = 0;
    for (size_t pos = 0; pos < siglen; pos += (siglen / 97) + 1) {   /* bit-flip sweep */
        sig[pos] ^= 0x04;
        if (mldsa_verify(level, sig, siglen, msg, 12, (const uint8_t *)"ctx", 3, pk) == 0) accepted++;
        sig[pos] ^= 0x04;
    }
    CHECK(accepted == 0, "%d tampered signatures accepted", accepted);
    pk[40] ^= 1;
    CHECK(mldsa_verify(level, sig, siglen, msg, 12, (const uint8_t *)"ctx", 3, pk) != 0, "tampered pk accepted");
    pk[40] ^= 1;
    uint8_t ctx256[256] = {0};
    CHECK(mldsa_sign(level, sig2, &l2, msg, 1, ctx256, 256, sk, zero) == MLDSA_ERR_PARAM, "ctx>255 allowed");

    /* malformed hint: first hint-count byte beyond omega */
    memcpy(sig2, sig, sgl);
    sig2[sgl - 1] = 0xFF;
    CHECK(mldsa_verify(level, sig2, sgl, msg, 12, (const uint8_t *)"ctx", 3, pk) != 0, "bad hint accepted");

    /* fuzz: random keys / lengths / messages */
    for (int it = 0; it < iters; it++) {
        uint8_t seed[32], rnd[32]; size_t ml = (size_t)(rand() % 300);
        for (int i = 0; i < 32; i++) { seed[i] = (uint8_t)rand(); rnd[i] = (uint8_t)rand(); }
        for (size_t i = 0; i < ml; i++) msg[i] = (uint8_t)rand();
        mldsa_keygen_internal(level, pk, sk, seed);
        int rc = mldsa_sign(level, sig, &siglen, msg, ml, NULL, 0, sk, rnd);
        CHECK(rc == 0, "fuzz sign rc=%d", rc);
        CHECK(mldsa_verify(level, sig, siglen, msg, ml, NULL, 0, pk) == 0, "fuzz verify (it=%d)", it);
        if (ml) { msg[0] ^= 1; CHECK(mldsa_verify(level, sig, siglen, msg, ml, NULL, 0, pk) != 0, "fuzz neg"); }
    }
    /* random RNG path */
    CHECK(mldsa_keygen(level, pk, sk) == 0, "random keygen");
    CHECK(mldsa_sign(level, sig, &siglen, msg, 5, NULL, 0, sk, NULL) == 0, "random sign");
    CHECK(mldsa_verify(level, sig, siglen, msg, 5, NULL, 0, pk) == 0, "random verify");
    free(pk); free(sk); free(sig); free(sig2);
}

int main(void) {
    srand(12345);
    test_level(MLDSA_44, 200);
    test_level(MLDSA_65, 200);
    test_level(MLDSA_87, 200);
    printf(fails ? "\n%d FAILURES\n" : "\nALL TESTS PASSED\n", fails);
    return fails != 0;
}
