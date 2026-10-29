/* ML-KEM benchmark: median cycle counts for the KEM operations and the building blocks.
 * Uses the *_internal functions with fixed inputs so OS randomness (a syscall) is not timed. */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mlkem.h"
#include "crypto.h"
#include "general.h"
#include "ntt.h"

#if defined(__x86_64__) || defined(__i386__)
  #include <x86intrin.h>
  static inline uint64_t ticks(void) { _mm_lfence(); uint64_t t = __rdtsc(); _mm_lfence(); return t; }
  #define UNIT "TSC ticks (~cycles at base clock)"
#elif defined(__aarch64__)
  static inline uint64_t ticks(void) { uint64_t t; __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(t)); return t; }
  #define UNIT "generic-timer ticks (NOT core cycles; use perf/PMU for cycles)"
#else
  static inline uint64_t ticks(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000000000ULL + ts.tv_nsec; }
  #define UNIT "nanoseconds"
#endif

#define WARMUP 200
#define RUNS   5001          /* odd -> exact median */

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static uint64_t g_sink;      /* keep results alive so the compiler can't drop the work */

#define BENCH(label, stmt)                                                   \
    do {                                                                     \
        static uint64_t t[RUNS];                                             \
        for (int w = 0; w < WARMUP; w++) { stmt; }                           \
        for (int r = 0; r < RUNS; r++) { uint64_t a = ticks(); stmt; t[r] = ticks() - a; } \
        qsort(t, RUNS, sizeof t[0], cmp_u64);                                \
        printf("  %-34s median %9llu   min %9llu\n", label,                  \
               (unsigned long long)t[RUNS/2], (unsigned long long)t[0]);     \
    } while (0)

static void bench_kem(const mlkem_params *p) {
    uint8_t ek[MLKEM_EK_MAX], dk[MLKEM_DK_MAX], ct[MLKEM_CT_MAX], K[32], d[32], z[32], m[32];
    mlkem_randombytes(d, 32); mlkem_randombytes(z, 32); mlkem_randombytes(m, 32);
    printf("%s\n", p->name);
    BENCH("KeyGen", { mlkem_keygen_internal(p, ek, dk, d, z); g_sink += ek[0]; });
    BENCH("Encaps", { mlkem_encaps_internal(p, K, ct, ek, m); g_sink += K[0]; });
    BENCH("Decaps", { mlkem_decaps_internal(p, K, dk, ct); g_sink += K[0]; });
}

static void bench_components(void) {
    poly_t f, g, h; uint8_t B[34], buf[192], big[1184], o[64];
    for (int i = 0; i < 256; i++) { f[i] = (i * 17) % MLKEM_Q; g[i] = (i * 29 + 5) % MLKEM_Q; }
    memset(B, 7, 34); memset(buf, 0x5A, 192); memset(big, 0xA5, sizeof big);
    printf("Components\n");
    BENCH("NTT",                         { NTT(f);            g_sink += f[0]; });
    BENCH("NTT_inv",                     { NTT_inv(f);        g_sink += f[0]; });
    BENCH("MultiplyNTTs (128 basemuls)", { MultiplyNTTs(h, f, g); g_sink += h[0]; });
    BENCH("SampleNTT (1 matrix entry)",  { SampleNTT(h, B);   g_sink += h[0]; });
    BENCH("SamplePolyCBD eta=2",         { SamplePolyCBD(h, buf, 2); g_sink += h[0]; });
    BENCH("PRF eta=2 (SHAKE256, 128 B)", { mlkem_PRF(2, buf, B, 1); g_sink += buf[0]; });
    BENCH("ByteEncode d=12",             { ByteEncode(buf, f, 12); g_sink += buf[0]; });
    BENCH("poly_compress d=10",          { poly_compress(h, 10); g_sink += h[0]; });
    BENCH("H = SHA3-256 of 1184 B",      { mlkem_H(o, big, sizeof big); g_sink += o[0]; });
    BENCH("G = SHA3-512 of 64 B",        { mlkem_G(o, big, 64); g_sink += o[0]; });
}

int main(void) {
    printf("Unit: " UNIT "\nRuns: %d (after %d warm-up), reporting median and min\n\n", RUNS, WARMUP);
    bench_kem(&MLKEM_512); bench_kem(&MLKEM_768); bench_kem(&MLKEM_1024);
    printf("\n"); bench_components();
    return (int)(g_sink == 0xDEADBEEF);
}
