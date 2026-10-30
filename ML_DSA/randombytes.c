#define _POSIX_C_SOURCE 200809L
#include "mldsa.h"
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
int mldsa_randombytes(uint8_t *out, size_t len) {
    return BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : MLDSA_ERR_RNG;
}
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
int mldsa_randombytes(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return MLDSA_ERR_RNG;
    while (len) {
        ssize_t n = read(fd, out, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return MLDSA_ERR_RNG; }
        out += n; len -= (size_t)n;
    }
    close(fd);
    return 0;
}
#endif
