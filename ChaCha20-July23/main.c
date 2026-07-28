

#include <stdio.h>
#include <string.h>
#include "chacha20.h"
#include<stdlib.h>
#include <x86intrin.h>

/* Print data in hexadecimal */
void print_hex(const char *label, const uint8_t *data, size_t length)
{
    size_t i;

    printf("%s\n", label);

    for (i = 0; i < length; i++)
    {
        printf("%02X ", data[i]);

        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    printf("\n\n");
}

int main(void)
{
    
    /* 256-bit Key (32 bytes)*/
    
    uint8_t key[CHACHA20_KEY_SIZE] =
    {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,
        0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,
        0x1C,0x1D,0x1E,0x1F
    };

    /* 96-bit Nonce (12 bytes) */
    uint8_t nonce[CHACHA20_NONCE_SIZE] =
    {
        0x00,0x00,0x00,0x09,
        0x00,0x00,0x00,0x4A,
        0x00,0x00,0x00,0x00
    };

    /* Initial block counter */
    uint32_t counter = 1;

    /* Plaintext */
    const char *message =
        "Hello, this is a ChaCha20 implementation in C. My name is Rakesh Mandal. I hate programming.";

    size_t length = strlen(message);
    uint8_t *ciphertext = malloc(length);
    uint8_t *decrypted = malloc(length + 1);

    if (!ciphertext || !decrypted) {
        printf("Memory allocation failed.\n");
        free(ciphertext);
        free(decrypted);
        return 1;
    }
    //uint8_t ciphertext[256];
    //uint8_t decrypted[256];
    unsigned long long start, end;

    start = __rdtsc();
    /* Encrypt */
    chacha20_encrypt(
        ciphertext,
        (const uint8_t *)message,
        length,
        key,
        counter,
        nonce
    );
    end = __rdtsc();
    /* Decrypt*/
    chacha20_encrypt(
        decrypted,
        ciphertext,
        length,
        key,
        counter,
        nonce
    );

    /* Add string terminator */
    decrypted[length] = '\0';

    /* Display Results*/
    printf("========== ChaCha20 Demo ==========\n\n");

    printf("Plaintext:\n");
    printf("%s\n\n", message);
    printf("Message Length = %zu bytes\n", length);
    
    print_hex(
        "Ciphertext (Hex):",
        ciphertext,
        length
    );
    
    unsigned long long cycles = end - start;
    printf("CPU Cycles = %llu\n", cycles);
    double cpb = (double)cycles / length;
    printf("Cycles/Byte = %.2f\n", cpb);

    printf("Decrypted Text:\n");
    printf("%s\n", decrypted);

    return 0;
}
