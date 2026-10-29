#include <stdio.h>
#include <string.h>
#include "mlkem.h"
#include "crypto.h"
#include "general.h"
#include "ntt.h"

static void hex(const uint8_t *b, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + 2*i, "%02x", b[i]); }
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("ok:   %s\n", msg); } while (0)

static void test_sha3(void) {
    uint8_t o[64]; char h[200];
    mlkem_H(o, (const uint8_t*)"", 0); hex(o, 32, h);
    CHECK(!strcmp(h, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), "SHA3-256('')");
    mlkem_H(o, (const uint8_t*)"abc", 3); hex(o, 32, h);
    CHECK(!strcmp(h, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), "SHA3-256('abc')");
    mlkem_G(o, (const uint8_t*)"", 0); hex(o, 64, h);
    CHECK(!strcmp(h, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"), "SHA3-512('')");
    mlkem_J(o, (const uint8_t*)"", 0); hex(o, 32, h);
    CHECK(!strcmp(h, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"), "SHAKE256('')");
    xof_ctx x; xof_init(&x); xof_squeeze(&x, o, 16); hex(o, 16, h);
    CHECK(!strcmp(h, "7f9c2ba4e88f827d616045507605853e"), "SHAKE128('')");
}

static void test_ntt(void) {
    uint16_t f[256], g[256], F[256], G[256], H[256], ref[256];
    uint8_t r[512]; mlkem_randombytes(r, 512);
    for (int i = 0; i < 256; i++) { f[i] = (r[i] * 13 + r[i+256]) % MLKEM_Q; g[i] = (r[i+256] * 7 + r[i]) % MLKEM_Q; }
    /* schoolbook multiplication mod X^256+1 */
    memset(ref, 0, sizeof ref);
    for (int i = 0; i < 256; i++) for (int j = 0; j < 256; j++) {
        uint32_t v = (uint32_t)f[i] * g[j] % MLKEM_Q; int k = i + j;
        if (k >= 256) { k -= 256; v = (MLKEM_Q - v) % MLKEM_Q; }
        ref[k] = (ref[k] + v) % MLKEM_Q;
    }
    memcpy(F, f, sizeof f); memcpy(G, g, sizeof g);
    NTT(F); NTT(G); MultiplyNTTs(H, F, G); NTT_inv(H);
    CHECK(!memcmp(H, ref, sizeof ref), "NTT multiplication == schoolbook");
    memcpy(F, f, sizeof f); NTT(F); NTT_inv(F);
    CHECK(!memcmp(F, f, sizeof f), "NTT_inv(NTT(f)) == f");
}

static void test_general(void) {
    uint16_t f[256], g[256]; uint8_t B[384];
    int ok = 1;
    for (int d = 1; d <= 12; d++) {
        for (int i = 0; i < 256; i++) f[i] = (i * 31 + d) % (d < 12 ? (1 << d) : MLKEM_Q);
        ByteEncode(B, f, d); ByteDecode(g, B, d);
        if (memcmp(f, g, sizeof f)) ok = 0;
    }
    CHECK(ok, "ByteEncode/ByteDecode roundtrip d=1..12");
    ok = 1;
    for (int d = 1; d <= 11; d++) for (int x = 0; x < MLKEM_Q; x++) {
        int e = (int)Decompress(Compress(x, d), d) - x; if (e > MLKEM_Q/2) e -= MLKEM_Q; if (e < -MLKEM_Q/2) e += MLKEM_Q;
        if (e < 0) e = -e;
        if (e > (MLKEM_Q + (1 << d)) / (1 << (d + 1))) ok = 0;
    }
    CHECK(ok, "Compress/Decompress error within q/2^(d+1)");
}

static void test_kem(const mlkem_params *p) {
    uint8_t ek[MLKEM_EK_MAX], dk[MLKEM_DK_MAX], c[MLKEM_CT_MAX], K1[32], K2[32];
    char msg[128];
    int ok = 1;
    for (int it = 0; it < 100; it++) {
        if (mlkem_keygen(p, ek, dk) || mlkem_encaps(p, K1, c, ek) || mlkem_decaps(p, K2, dk, c)) { ok = 0; break; }
        if (memcmp(K1, K2, 32)) { ok = 0; break; }
    }
    snprintf(msg, sizeof msg, "%s: 100x keygen/encaps/decaps agree (ek=%zu dk=%zu ct=%zu)", p->name,
             mlkem_ek_bytes(p), mlkem_dk_bytes(p), mlkem_ct_bytes(p));
    CHECK(ok, msg);

    mlkem_keygen(p, ek, dk); mlkem_encaps(p, K1, c, ek);
    c[5] ^= 1; mlkem_decaps(p, K2, dk, c);
    snprintf(msg, sizeof msg, "%s: tampered ct -> different key (implicit rejection)", p->name);
    CHECK(memcmp(K1, K2, 32) != 0, msg);

    ek[0] = 0xFF; ek[1] = 0xFF;
    snprintf(msg, sizeof msg, "%s: malformed ek rejected", p->name);
    CHECK(mlkem_encaps(p, K1, c, ek) == -2, msg);
}

int main(void) {
    test_sha3(); test_ntt(); test_general();
    test_kem(&MLKEM_512); test_kem(&MLKEM_768); test_kem(&MLKEM_1024);
    printf(fails ? "\n%d FAILED\n" : "\nall passed\n", fails);
    return fails != 0;
}
