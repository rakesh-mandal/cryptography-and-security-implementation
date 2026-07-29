#include "chacha20.h"
#include <string.h>

// ChaCha20 Constants
static const u32 CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574    
};

// Rotate Left (32-bit) Macro
#define ROTL32(x, n) (((u32)(x) << (n)) | ((u32)(x) >> (32 - (n))))

// Read 4 bytes (Little Endian)
static inline u32 load32(const u8 *src)
{
    return ((u32)src[0])       |
           ((u32)src[1] << 8)  |
           ((u32)src[2] << 16) |
           ((u32)src[3] << 24);
}

// Write 4 bytes (Little Endian)
static inline void store32(u8 *dst, u32 value)
{
    dst[0] = (u8)(value);
    dst[1] = (u8)(value >> 8);
    dst[2] = (u8)(value >> 16);
    dst[3] = (u8)(value >> 24);
}

// ChaCha20 Quarter Round using ROTL32 macro
#define QUARTER_ROUND(s, a, b, c, d) {                       \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 16);     \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 12);     \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 8);      \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 7);      \
}

// ChaCha20 Block Function
void chacha20_block(
    u8 output[CHACHA20_BLOCK_SIZE],
    const u8 key[CHACHA20_KEY_SIZE],
    u32 counter,
    const u8 nonce[CHACHA20_NONCE_SIZE]
)
{
    u32 state[16];
    u32 x[16];

    /* Constants */
    memcpy(state, CONSTANTS, sizeof(CONSTANTS));

    /* Key */
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32(key + (i * 4));
    }

    /* Block Counter */
    state[12] = counter;

    /* Nonce */
    state[13] = load32(nonce + 0);
    state[14] = load32(nonce + 4);
    state[15] = load32(nonce + 8);

    /* Copy initial state to working state */
    memcpy(x, state, sizeof(state));

    for (int i = 0; i < CHACHA20_ROUNDS; i += 2) {
        /* Column Round */
        QUARTER_ROUND(x, 0, 4,  8, 12);
        QUARTER_ROUND(x, 1, 5,  9, 13);
        QUARTER_ROUND(x, 2, 6, 10, 14);
        QUARTER_ROUND(x, 3, 7, 11, 15);

        /* Diagonal Round */
        QUARTER_ROUND(x, 0, 5, 10, 15);
        QUARTER_ROUND(x, 1, 6, 11, 12);
        QUARTER_ROUND(x, 2, 7,  8, 13);
        QUARTER_ROUND(x, 3, 4,  9, 14);
    }

    /* Add initial state and serialize */
    for (int i = 0; i < 16; i++) {
        store32(output + (4 * i), x[i] + state[i]);
    }
}


// ChaCha20 Encryption / Decryption
void chacha20_encrypt(
    u8 *ciphertext,
    const u8 *plaintext,
    size_t length,
    const u8 key[CHACHA20_KEY_SIZE],
    u32 counter,
    const u8 nonce[CHACHA20_NONCE_SIZE]
)
{
    u8 keystream[CHACHA20_BLOCK_SIZE];

    while (length > 0)
    {
        /* Generate 64-byte pseudorandom keystream block */
        chacha20_block(keystream, key, counter, nonce);

        /* Process remaining bytes (up to a full block of 64 bytes) */
        size_t bytes_to_process = (length < CHACHA20_BLOCK_SIZE) 
                                  ? length 
                                  : CHACHA20_BLOCK_SIZE;

        /* Encrypt/Decrypt via XOR operator */
        for (size_t i = 0; i < bytes_to_process; i++)
        {
            ciphertext[i] = plaintext[i] ^ keystream[i];
        }

        /* Advance pointers and decrease remaining length */
        ciphertext += bytes_to_process;
        plaintext  += bytes_to_process;
        length     -= bytes_to_process;

        /* Increment counter for the next 64-byte block */
        counter++;
    }
}
