/*
 * Direct implementation of the FFT / IFFT pseudocode:
 *
 * FFT(A, n)   # A is a coefficient array of length n, with n = 2^m
 *     if n == 1: return A
 *     Ae = [a0, a2, a4, ...]
 *     Ao = [a1, a3, a5, ...]
 *     Ye = FFT(Ae, n/2)
 *     Yo = FFT(Ao, n/2)
 *     for k = 0 to n/2 - 1:
 *         w = e^(2*pi*i*k/n)
 *         Y[k]       = Ye[k] + w*Yo[k]
 *         Y[k + n/2] = Ye[k] - w*Yo[k]
 *     return Y
 *
 * IFFT(y, n):
 *     a = FFT(y, n, w = e^(-2*pi*i/n))
 *     return (aj/n for aj in a)
 *
 * Compile:  gcc -O2 -o fft fft.c -lm
 * Run:      ./fft
 */

#include <stdio.h>
#include <stdlib.h>
#include <complex.h>
#include <math.h>

/* Recursive Cooley-Tukey FFT, in place is avoided for clarity: we
 * allocate a fresh output array each call, mirroring the pseudocode's
 * Ae/Ao/Ye/Yo/Y naming directly.
 *
 * a:   input array of length n (n must be a power of 2)
 * n:   length
 * w0:  the root of unity to use for this call.
 *      Pass 0 (or cexp(2*pi*I/n)) for the forward transform.
 *      Pass cexp(-2*pi*I/n) to get the un-normalized inverse transform.
 * out: caller-provided output array of length n
 */
void fft(double complex *a, int n, double complex w, double complex *out) {
    if (n == 1) {
        out[0] = a[0];
        return;
    }

    if (w == 0) {
        w = cexp(2.0 * M_PI * I / n);
    }

    int half = n / 2;
    double complex *Ae = malloc(half * sizeof(double complex));
    double complex *Ao = malloc(half * sizeof(double complex));
    double complex *Ye = malloc(half * sizeof(double complex));
    double complex *Yo = malloc(half * sizeof(double complex));

    for (int i = 0; i < half; i++) {
        Ae[i] = a[2 * i];
        Ao[i] = a[2 * i + 1];
    }

    /* recurse with w*w: the square of the n-th root is the primitive
     * (n/2)-th root of unity needed one level down */
    fft(Ae, half, w * w, Ye);
    fft(Ao, half, w * w, Yo);

    double complex wk = 1.0;
    for (int k = 0; k < half; k++) {
        double complex t = wk * Yo[k];
        out[k]        = Ye[k] + t;
        out[k + half] = Ye[k] - t;
        wk *= w;
    }

    free(Ae);
    free(Ao);
    free(Ye);
    free(Yo);
}

/* Inverse FFT: same algorithm run with w = e^{-2*pi*i/n}, output scaled by 1/n. */
void ifft(double complex *y, int n, double complex *out) {
    double complex w = cexp(-2.0 * M_PI * I / n);
    fft(y, n, w, out);
    for (int i = 0; i < n; i++) {
        out[i] /= n;
    }
}

int next_pow2(int x) {
    int p = 1;
    while (p < x) p *= 2;
    return p;
}

/* Multiply two real polynomials (coefficient lists, a[i] = coeff of x^i) using FFT. */
void poly_multiply(double *a, int la, double *b, int lb, double *c) {
    int n = next_pow2(la + lb - 1);

    double complex *fa = calloc(n, sizeof(double complex));
    double complex *fb = calloc(n, sizeof(double complex));
    double complex *Fa = malloc(n * sizeof(double complex));
    double complex *Fb = malloc(n * sizeof(double complex));
    double complex *Fc = malloc(n * sizeof(double complex));
    double complex *res = malloc(n * sizeof(double complex));

    for (int i = 0; i < la; i++) fa[i] = a[i];
    for (int i = 0; i < lb; i++) fb[i] = b[i];

    fft(fa, n, 0, Fa);
    fft(fb, n, 0, Fb);

    for (int i = 0; i < n; i++) Fc[i] = Fa[i] * Fb[i];

    ifft(Fc, n, res);

    int deg = la + lb - 1;
    for (int i = 0; i < deg; i++) c[i] = creal(res[i]);

    free(fa); free(fb); free(Fa); free(Fb); free(Fc); free(res);
}

/* --- cycle counting (x86 rdtsc) --- */
#if defined(__x86_64__) || defined(__i386__)
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}
#define HAVE_RDTSC 1
#else
#define HAVE_RDTSC 0
#endif

void poly_multiply_timed(double *a, int la, double *b, int lb, double *c) {
#if HAVE_RDTSC
    int n = next_pow2(la + lb - 1);

    double complex *fa = calloc(n, sizeof(double complex));
    double complex *fb = calloc(n, sizeof(double complex));
    double complex *Fa = malloc(n * sizeof(double complex));
    double complex *Fb = malloc(n * sizeof(double complex));
    double complex *Fc = malloc(n * sizeof(double complex));
    double complex *res = malloc(n * sizeof(double complex));

    for (int i = 0; i < la; i++) fa[i] = a[i];
    for (int i = 0; i < lb; i++) fb[i] = b[i];

    unsigned long long t0, t1;

    t0 = rdtsc();
    fft(fa, n, 0, Fa);
    t1 = rdtsc();
    printf("  fft(A)      n=%-4d cycles=%llu\n", n, t1 - t0);

    t0 = rdtsc();
    fft(fb, n, 0, Fb);
    t1 = rdtsc();
    printf("  fft(B)      n=%-4d cycles=%llu\n", n, t1 - t0);

    t0 = rdtsc();
    for (int i = 0; i < n; i++) Fc[i] = Fa[i] * Fb[i];
    t1 = rdtsc();
    printf("  pointwise   n=%-4d cycles=%llu\n", n, t1 - t0);

    t0 = rdtsc();
    ifft(Fc, n, res);
    t1 = rdtsc();
    printf("  ifft(C)     n=%-4d cycles=%llu\n", n, t1 - t0);

    int deg = la + lb - 1;
    for (int i = 0; i < deg; i++) c[i] = creal(res[i]);

    free(fa); free(fb); free(Fa); free(Fb); free(Fc); free(res);
#else
    printf("  rdtsc not available on this architecture; falling back to poly_multiply()\n");
    poly_multiply(a, la, b, lb, c);
#endif
}

int main(void) {
    /* --- sanity check: FFT then IFFT should return the original array --- */
    double complex a[8], Y[8], back[8];
    for (int i = 0; i < 8; i++) a[i] = i + 1;   /* [1,2,3,4,5,6,7,8] */

    fft(a, 8, 0, Y);
    ifft(Y, 8, back);

    printf("original:  ");
    for (int i = 0; i < 8; i++) printf("%.0f ", creal(a[i]));
    printf("\n");

    printf("FFT:       ");
    for (int i = 0; i < 8; i++)
        printf("(%.4f%+.4fi) ", creal(Y[i]), cimag(Y[i]));
    printf("\n");

    printf("IFFT back: ");
    for (int i = 0; i < 8; i++) printf("%.4f ", creal(back[i]));
    printf("\n\n");

    /* --- polynomial multiplication demo ---
     * A(x) = 1 + 2x + 3x^2        coeffs [1,2,3]
     * B(x) = 4 + 5x               coeffs [4,5]
     * A(x)*B(x) = 4 + 13x + 22x^2 + 15x^3
     */
    double A[] = {1, 2, 3};
    double B[] = {4, 5};
    double C[3 + 2 - 1];

    poly_multiply(A, 3, B, 2, C);

    printf("A = [1, 2, 3], B = [4, 5]\n");
    printf("A*B = [");
    for (int i = 0; i < 4; i++) printf("%.4f%s", C[i], i < 3 ? ", " : "");
    printf("]  (expected [4, 13, 22, 15])\n\n");

    /* --- cycle-count benchmark on a bigger example --- */
    printf("cycle benchmark (larger polynomials):\n");
    int la = 300, lb = 300;
    double *Abig = malloc(la * sizeof(double));
    double *Bbig = malloc(lb * sizeof(double));
    double *Cbig = malloc((la + lb - 1) * sizeof(double));
    for (int i = 0; i < la; i++) Abig[i] = (i % 7) + 1;
    for (int i = 0; i < lb; i++) Bbig[i] = (i % 5) + 1;

    poly_multiply_timed(Abig, la, Bbig, lb, Cbig);

    free(Abig); free(Bbig); free(Cbig);

    return 0;
}


/*
rakesh@rakesh-IdeaPad-3-15ALC6-Ub:~/Desktop$ gcc -O2 -o fft fft.c -lm
rakesh@rakesh-IdeaPad-3-15ALC6-Ub:~/Desktop$ ./fft
original:  1 2 3 4 5 6 7 8 
FFT:       (36.0000+0.0000i) (-4.0000-9.6569i) (-4.0000-4.0000i) (-4.0000-1.6569i) (-4.0000+0.0000i) (-4.0000+1.6569i) (-4.0000+4.0000i) (-4.0000+9.6569i) 
IFFT back: 1.0000 2.0000 3.0000 4.0000 5.0000 6.0000 7.0000 8.0000 

A = [1, 2, 3], B = [4, 5]
A*B = [4.0000, 13.0000, 22.0000, 15.0000]  (expected [4, 13, 22, 15])

cycle benchmark (larger polynomials):
  fft(A)      n=1024 cycles=466620
  fft(B)      n=1024 cycles=377559
  pointwise   n=1024 cycles=20811
  ifft(C)     n=1024 cycles=392448


*/

