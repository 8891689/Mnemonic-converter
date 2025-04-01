/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#ifndef RANDOM_H
#define RANDOM_H

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * generateRandomBinary
 * 生成随机二进制字符串，每一位模拟一次“抛硬币”得到 0 或 1。
 * 参数：
 *   bin  - 用于存放生成的二进制字符串（长度至少为 bits+1 个字符）
 *   bits - 需要生成的位数，取值范围 0～512
 * 返回：
 *   0 成功，非 0 表示出错
 */
int generateRandomBinary(char *bin, int bits);

/*
 * convertBinaryToHex
 * 将二进制字符串转换为16进制字符串，要求二进制位数为4的倍数。
 * 参数：
 *   bin  - 输入的二进制字符串（长度为 bits 位）
 *   hex  - 输出的16进制字符串（预留 bits/4 + 1 个字符空间）
 *   bits - 二进制位数（必须是4的倍数）
 */
void convertBinaryToHex(const char *bin, char *hex, int bits);

#ifdef __cplusplus
}
#endif

#endif // RANDOM_H

