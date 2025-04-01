/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#include <stdint.h>
#include <string.h>

#include "sha3256.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// 24 轮 Keccak-f[1600] 的轮常量
static const uint64_t round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rho 旋转偏移量
static const int rotation_offsets[24] = {
    1, 3, 6, 10, 15, 21, 28, 36,
    45, 55, 2, 14, 27, 41, 56, 8,
    25, 43, 62, 18, 39, 61, 20, 44
};

// Pi 步骤中的置换索引
static const int pi_indices[24] = {
    10, 7, 11, 17, 18, 3, 5, 16,
    8, 21, 24, 4, 15, 23, 19, 13,
    12, 2, 20, 14, 22, 9, 6, 1
};

/**
 * @brief Keccak-f[1600] 置换函数，共 24 轮
 *
 * @param state 状态数组，包含 25 个 uint64_t 数据
 */
static void keccakf(uint64_t state[25]) {
    int round, i, j;
    uint64_t temp, t[5];

    for (round = 0; round < 24; round++) {
        /* Theta 步骤：计算每列的奇偶校验 */
        for (i = 0; i < 5; i++) {
            t[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (i = 0; i < 5; i++) {
            temp = t[(i + 4) % 5] ^ ROTL(t[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= temp;
            }
        }

        /* Rho 和 Pi 步骤：位旋转与重排 */
        temp = state[1];
        for (i = 0; i < 24; i++) {
            j = pi_indices[i];
            uint64_t temp2 = state[j];
            state[j] = ROTL(temp, rotation_offsets[i]);
            temp = temp2;
        }

        /* Chi 步骤：非线性置换 */
        for (j = 0; j < 25; j += 5) {
            uint64_t a0 = state[j];
            uint64_t a1 = state[j + 1];
            uint64_t a2 = state[j + 2];
            uint64_t a3 = state[j + 3];
            uint64_t a4 = state[j + 4];
            state[j]     ^= (~a1) & a2;
            state[j + 1] ^= (~a2) & a3;
            state[j + 2] ^= (~a3) & a4;
            state[j + 3] ^= (~a4) & a0;
            state[j + 4] ^= (~a0) & a1;
        }

        /* Iota 步骤：加入轮常量 */
        state[0] ^= round_constants[round];
    }
}

/**
 * @brief 计算 SHA3-256 哈希值
 *
 * 根据 FIPS 202 标准，SHA3-256 的参数为：
 * - 速率 rate = 1088 bits (136 字节)
 * - 容量 capacity = 512 bits
 * - Padding 使用 0x06 作为分隔字节，并在最后一个字节设置最高位（0x80）
 *
 * @param data    输入数据指针
 * @param datalen 输入数据的字节长度
 * @param hash    输出缓冲区（至少 32 字节，存放 256 位哈希）
 */
void sha3_256(const uint8_t *data, size_t datalen, uint8_t *hash) {
    const size_t rate = 136;
    uint64_t state[25] = {0};

    /* 吸收阶段：处理完整的 rate 块 */
    while (datalen >= rate) {
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t t = 0;
            for (int j = 0; j < 8; j++) {
                t |= ((uint64_t)data[i * 8 + j]) << (8 * j);
            }
            state[i] ^= t;
        }
        keccakf(state);
        data   += rate;
        datalen -= rate;
    }

    /* 填充阶段：处理剩余数据 */
    uint8_t block[rate];
    memset(block, 0, rate);
    memcpy(block, data, datalen);
    block[datalen] = 0x06;      // SHA-3 的域分离字节
    block[rate - 1] |= 0x80;    // 最后一个字节置最高位

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t t = 0;
        for (int j = 0; j < 8; j++) {
            t |= ((uint64_t)block[i * 8 + j]) << (8 * j);
        }
        state[i] ^= t;
    }
    keccakf(state);

    /* 挤出阶段：输出前 256 位（32 字节） */
    for (size_t i = 0; i < 4; i++) {
        uint64_t t = state[i];
        for (int j = 0; j < 8; j++) {
            hash[i * 8 + j] = (uint8_t)(t & 0xFF);
            t >>= 8;
        }
    }
}

