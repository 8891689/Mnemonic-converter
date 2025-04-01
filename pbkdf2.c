/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#include "pbkdf2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ======================= SHA-512 实现 ======================= */

/* SHA-512 上下文结构体 */
typedef struct {
    uint64_t state[8];
    /* 记录原始消息长度，单位为比特（128 位） */
    uint64_t bitcount[2]; 
    uint8_t buffer[128];
} SHA512_CTX;

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x,1) ^ ROTR(x,8) ^ ((x) >> 7))
#define sigma1(x) (ROTR(x,19) ^ ROTR(x,61) ^ ((x) >> 6))

/* 80 个轮常量 */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* SHA-512 块处理函数 */
static void sha512_transform(SHA512_CTX *ctx, const uint8_t block[128]) {
    uint64_t W[80];
    int i;
    for (i = 0; i < 16; i++) {
        W[i] = ((uint64_t)block[i * 8    ] << 56) |
               ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) |
               ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) |
               ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8)  |
               ((uint64_t)block[i * 8 + 7]);
    }
    for (i = 16; i < 80; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }
    uint64_t a = ctx->state[0];
    uint64_t b = ctx->state[1];
    uint64_t c = ctx->state[2];
    uint64_t d = ctx->state[3];
    uint64_t e = ctx->state[4];
    uint64_t f = ctx->state[5];
    uint64_t g = ctx->state[6];
    uint64_t h = ctx->state[7];
    for (i = 0; i < 80; i++) {
        uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha512_init(SHA512_CTX *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bitcount[0] = 0;
    ctx->bitcount[1] = 0;
}

/* 注意：本实现的 sha512_update 与许多标准实现类似，先更新 bitcount，再处理数据块 */
static void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t len) {
    size_t index = (ctx->bitcount[1] / 8) % 128;
    uint64_t bits = ((uint64_t)len) * 8;
    ctx->bitcount[1] += bits;
    if (ctx->bitcount[1] < bits) {
        ctx->bitcount[0]++;
    }
    size_t partLen = 128 - index;
    size_t i = 0;
    if (len >= partLen) {
        memcpy(ctx->buffer + index, data, partLen);
        sha512_transform(ctx, ctx->buffer);
        for (i = partLen; i + 127 < len; i += 128) {
            sha512_transform(ctx, data + i);
        }
        index = 0;
    }
    memcpy(ctx->buffer + index, data + i, len - i);
}

/* ----------------- 修正后的 sha512_final -----------------
   为保证附加的消息长度是真正的原始消息长度（单位比特），
   本实现在 final 阶段不再调用 sha512_update，
   而是手工拼接 padding 和 16 字节长度后再调用 sha512_transform。 */
static void sha512_final(SHA512_CTX *ctx, uint8_t digest[64]) {
    uint8_t finalBlock[256];
    unsigned int index = (ctx->bitcount[1] / 8) % 128;
    unsigned int padLen = (index < 112) ? (112 - index) : (240 - index);
    
    /* 将原始缓冲区拷贝到 finalBlock 开头 */
    memcpy(finalBlock, ctx->buffer, index);
    
    /* 添加 0x80 与后续 0 填充 */
    finalBlock[index] = 0x80;
    memset(finalBlock + index + 1, 0, padLen - 1);
    
    /* 将原始消息长度（128 位，大端）附加到 padding 后 */
    uint8_t lenBlock[16];
    /* 注意：ctx->bitcount 中已累计了所有输入数据的比特数 */
    for (int i = 0; i < 8; i++) {
        lenBlock[i]   = (uint8_t)(ctx->bitcount[0] >> (56 - 8 * i));
        lenBlock[i+8] = (uint8_t)(ctx->bitcount[1] >> (56 - 8 * i));
    }
    memcpy(finalBlock + index + padLen, lenBlock, 16);
    
    unsigned int total = index + padLen + 16;
    /* 处理 finalBlock 中的每 128 字节 */
    for (unsigned int i = 0; i < total; i += 128) {
        sha512_transform(ctx, finalBlock + i);
    }
    
    /* 输出最终摘要，转换为大端字节序 */
    for (int i = 0; i < 8; i++) {
        digest[i * 8    ] = (uint8_t)(ctx->state[i] >> 56);
        digest[i * 8 + 1] = (uint8_t)(ctx->state[i] >> 48);
        digest[i * 8 + 2] = (uint8_t)(ctx->state[i] >> 40);
        digest[i * 8 + 3] = (uint8_t)(ctx->state[i] >> 32);
        digest[i * 8 + 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 8 + 5] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 8 + 6] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 8 + 7] = (uint8_t)(ctx->state[i]);
    }
}

/* ==================== HMAC-SHA512 实现 ==================== */

/**
 * @brief 计算 HMAC-SHA512 值
 *
 * @param key      密钥
 * @param key_len  密钥长度（字节数）
 * @param data     输入数据
 * @param data_len 数据长度
 * @param out      输出 64 字节的 HMAC 值
 */
void hmac_sha512(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out) {
    uint8_t key_block[128];
    uint8_t o_key_pad[128];
    uint8_t i_key_pad[128];
    if (key_len > 128) {
        SHA512_CTX ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, key, key_len);
        sha512_final(&ctx, key_block);
        /* 补零至 128 字节 */
        memset(key_block + 64, 0, 128 - 64);
    } else {
        memcpy(key_block, key, key_len);
        memset(key_block + key_len, 0, 128 - key_len);
    }
    for (int i = 0; i < 128; i++) {
        i_key_pad[i] = key_block[i] ^ 0x36;
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }
    uint8_t inner_hash[64];
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, i_key_pad, 128);
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, inner_hash);
    
    sha512_init(&ctx);
    sha512_update(&ctx, o_key_pad, 128);
    sha512_update(&ctx, inner_hash, 64);
    sha512_final(&ctx, out);
}

/* ==================== PBKDF2-HMAC-SHA512 实现 ==================== */

void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *output, size_t dkLen) {
    const size_t hLen = 64; // SHA512 输出长度（字节）
    uint32_t block_count = (dkLen + hLen - 1) / hLen;
    uint8_t U[64];
    uint8_t T[64];
    /* 为 salt 添加 4 字节的块编号（大端） */
    uint8_t *salt_block = (uint8_t *)alloca(salt_len + 4);
    for (uint32_t i = 1; i <= block_count; i++) {
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len + 0] = (uint8_t)((i >> 24) & 0xff);
        salt_block[salt_len + 1] = (uint8_t)((i >> 16) & 0xff);
        salt_block[salt_len + 2] = (uint8_t)((i >> 8)  & 0xff);
        salt_block[salt_len + 3] = (uint8_t)(i & 0xff);
        
        hmac_sha512(password, password_len, salt_block, salt_len + 4, U);
        memcpy(T, U, hLen);
        
        for (uint32_t j = 1; j < iterations; j++) {
            hmac_sha512(password, password_len, U, hLen, U);
            for (size_t k = 0; k < hLen; k++) {
                T[k] ^= U[k];
            }
        }
        size_t offset = (i - 1) * hLen;
        size_t copy_len = ((dkLen - offset) > hLen) ? hLen : (dkLen - offset);
        memcpy(output + offset, T, copy_len);
    }
}

