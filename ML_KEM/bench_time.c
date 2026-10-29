/* ML-KEM wall-clock benchmark.
 * Each sample times a batch of BATCH calls with clock_gettime(CLOCK_MONOTONIC) and divides,
 * so timer overhead (~20-50 ns) is negligible even for the small components.
 * Reports the median per-call time over SAMPLES samples, plus operations per second. */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mlkem.h"
#include "crypto.h"
#include "general.h"
#include "ntt.h"

#define WARMUP  200
#define SAMPLES 201          /* odd -> exact median */

static inline double now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static uint64_t g_sink;

#define BENCH(label, batch, stmt)                                                   \
    do {                                                                            \
        static double t[SAMPLES];                                                   \
        for (int w = 0; w < WARMUP; w++) { stmt; }                                  \
        for (int s = 0; s < SAMPLES; s++) {                                         \
            double a = now_ns();                                                    \
            for (int b = 0; b < (batch); b++) { stmt; }                             \
            t[s] = (now_ns() - a) / (batch);                                        \
        }                                                                           \
        qsort(t, SAMPLES, sizeof t[0], cmp_d);                                      \
        printf("  %-30s %10.2f us   %10.0f ops/s   (min %.2f us)\n", label,         \
               t[SAMPLES/2] / 1e3, 1e9 / t[SAMPLES/2], t[0] / 1e3);                 \
    } while (0)

static void bench_kem(const mlkem_params *p) {
    uint8_t ek[MLKEM_EK_MAX], dk[MLKEM_DK_MAX], ct[MLKEM_CT_MAX], K[32], d[32], z[32], m[32];
    mlkem_randombytes(d, 32); mlkem_randombytes(z, 32); mlkem_randombytes(m, 32);
    printf("%s\n", p->name);
    BENCH("KeyGen", 50, { mlkem_keygen_internal(p, ek, dk, d, z); g_sink += ek[0]; });
    BENCH("Encaps", 50, { mlkem_encaps_internal(p, K, ct, ek, m);  g_sink += K[0]; });
    BENCH("Decaps", 50, { mlkem_decaps_internal(p, K, dk, ct);     g_sink += K[0]; });
}

static void bench_components(void) {
    poly_t f, g, h; uint8_t B[34], buf[192], big[1184], o[64];
    for (int i = 0; i < 256; i++) { f[i] = (i * 17) % MLKEM_Q; g[i] = (i * 29 + 5) % MLKEM_Q; }
    memset(B, 7, 34); memset(buf, 0x5A, 192); memset(big, 0xA5, sizeof big);
    printf("Components\n");
    BENCH("NTT",                         500, { NTT(f);            g_sink += f[0]; });
    BENCH("NTT_inv",                     500, { NTT_inv(f);        g_sink += f[0]; });
    BENCH("MultiplyNTTs",                500, { MultiplyNTTs(h, f, g); g_sink += h[0]; });
    BENCH("SampleNTT (1 entry)",         200, { SampleNTT(h, B);   g_sink += h[0]; });
    BENCH("SamplePolyCBD eta=2",         500, { SamplePolyCBD(h, buf, 2); g_sink += h[0]; });
    BENCH("PRF eta=2",                   500, { mlkem_PRF(2, buf, B, 1); g_sink += buf[0]; });
    BENCH("ByteEncode d=12",             500, { ByteEncode(buf, f, 12); g_sink += buf[0]; });
    BENCH("poly_compress d=10",         2000, { poly_compress(h, 10); g_sink += h[0]; });
    BENCH("H = SHA3-256 of 1184 B",      200, { mlkem_H(o, big, sizeof big); g_sink += o[0]; });
    BENCH("G = SHA3-512 of 64 B",        500, { mlkem_G(o, big, 64); g_sink += o[0]; });
}

int main(void) {
    printf("Wall-clock time (CLOCK_MONOTONIC), median per call over %d samples\n\n", SAMPLES);
    bench_kem(&MLKEM_512); bench_kem(&MLKEM_768); bench_kem(&MLKEM_1024);
    printf("\n"); bench_components();
    return (int)(g_sink == 0xDEADBEEF);
}
