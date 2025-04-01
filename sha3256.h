/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#ifndef SHA3256_H
#define SHA3256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 计算 SHA3-256 哈希值
 *
 * @param data   输入数据指针
 * @param datalen 输入数据的字节长度
 * @param hash   输出缓冲区（至少 32 字节，存放 256 位哈希）
 */
void sha3_256(const uint8_t *data, size_t datalen, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif // SHA3256_H

