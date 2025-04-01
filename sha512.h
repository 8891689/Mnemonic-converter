#ifndef SHA512_H
#define SHA512_H

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

#ifdef __cplusplus
}
#endif

#endif // SHA512_H

