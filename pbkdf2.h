/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#ifndef PBKDF2_H
#define PBKDF2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief 计算输入数据的 SHA-512 哈希值
 *
 * @param data   输入数据指针
 * @param len    输入数据长度（字节）
 * @param digest 输出缓冲区，至少 64 字节用于存放 512 位哈希值
 */
void sha512(const uint8_t *data, size_t len, uint8_t digest[64]);

/**
 * @brief 计算 HMAC-SHA512 值
 *
 * @param key      密钥指针
 * @param key_len  密钥长度（字节数）
 * @param data     数据指针
 * @param data_len 数据长度（字节数）
 * @param digest   输出缓冲区，至少 64 字节存放 HMAC 结果
 */
void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t digest[64]);
/**
 * @brief 使用 PBKDF2-HMAC-SHA512 算法生成派生密钥
 *
 * @param password      密码
 * @param password_len  密码长度（字节数）
 * @param salt          盐值
 * @param salt_len      盐值长度（字节数）
 * @param iterations    迭代次数（对于助记词建议使用 2048 次或更多，此处测试向量采用 1）
 * @param output        输出缓冲区，至少 dkLen 字节
 * @param dkLen         期望输出密钥的字节长度
 */
void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *output, size_t dkLen);

#ifdef __cplusplus
}
#endif

#endif // PBKDF2_H

