/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#include "sha512.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* --- 内部数据结构与宏定义 --- */
typedef struct {
    uint64_t state[8];   // 哈希状态
    uint64_t bitlen[2];  // 累计输入比特数 (128位)
    uint8_t data[128];   // 数据缓冲区
    size_t datalen;      // 当前缓冲区中数据的字节数
} SHA512_CTX;

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x,1)  ^ ROTR(x,8)  ^ ((x) >> 7))
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

/* --- 内部函数：SHA-512 块处理 --- */
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
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
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

/* --- 初始化 SHA-512 上下文 --- */
static void sha512_init_ctx(SHA512_CTX *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->datalen = 0;
}

/* --- 更新 SHA-512 上下文，处理输入数据 --- */
static void sha512_update_ctx(SHA512_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 128) {
            sha512_transform(ctx, ctx->data);
            /* 累计比特数 */
            ctx->bitlen[1] += 1024;
            if (ctx->bitlen[1] < 1024)
                ctx->bitlen[0]++;
            ctx->datalen = 0;
        }
    }
}

/* --- 最终处理：填充并输出摘要 --- */
static void sha512_final_ctx(SHA512_CTX *ctx, uint8_t digest[64]) {
    size_t i = ctx->datalen;
    
    /* 在数据末尾添加 0x80 */
    ctx->data[i++] = 0x80;
    
    /* 如果数据长度超过 112 字节，则填充至 128 字节后再处理一次 */
    if (i > 112) {
        while (i < 128)
            ctx->data[i++] = 0x00;
        sha512_transform(ctx, ctx->data);
        i = 0;
    }
    
    /* 填充到 112 字节 */
    while (i < 112)
        ctx->data[i++] = 0x00;
    
    /* 添加 128 位（16 字节）的消息长度，大端编码 */
    uint64_t high = ctx->bitlen[0];
    uint64_t low  = ctx->bitlen[1] + (ctx->datalen * 8);
    /* 注意：这里 low 可能有溢出，但本实现足够处理大多数用例 */
    ctx->data[112] = (uint8_t)(high >> 56);
    ctx->data[113] = (uint8_t)(high >> 48);
    ctx->data[114] = (uint8_t)(high >> 40);
    ctx->data[115] = (uint8_t)(high >> 32);
    ctx->data[116] = (uint8_t)(high >> 24);
    ctx->data[117] = (uint8_t)(high >> 16);
    ctx->data[118] = (uint8_t)(high >> 8);
    ctx->data[119] = (uint8_t)(high);
    ctx->data[120] = (uint8_t)(low >> 56);
    ctx->data[121] = (uint8_t)(low >> 48);
    ctx->data[122] = (uint8_t)(low >> 40);
    ctx->data[123] = (uint8_t)(low >> 32);
    ctx->data[124] = (uint8_t)(low >> 24);
    ctx->data[125] = (uint8_t)(low >> 16);
    ctx->data[126] = (uint8_t)(low >> 8);
    ctx->data[127] = (uint8_t)(low);
    
    sha512_transform(ctx, ctx->data);
    
    /* 将状态转为大端输出 */
    for (i = 0; i < 8; i++) {
        digest[i*8 + 0] = (uint8_t)(ctx->state[i] >> 56);
        digest[i*8 + 1] = (uint8_t)(ctx->state[i] >> 48);
        digest[i*8 + 2] = (uint8_t)(ctx->state[i] >> 40);
        digest[i*8 + 3] = (uint8_t)(ctx->state[i] >> 32);
        digest[i*8 + 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i*8 + 5] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*8 + 6] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*8 + 7] = (uint8_t)(ctx->state[i]);
    }
}

/* --- 对外接口：计算 SHA-512 --- */
void sha512(const uint8_t *data, size_t len, uint8_t digest[64]) {
    SHA512_CTX ctx;
    sha512_init_ctx(&ctx);
    sha512_update_ctx(&ctx, data, len);
    sha512_final_ctx(&ctx, digest);
}

