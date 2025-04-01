/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#include <stdio.h>

#include "random.h"

#ifdef _WIN32
    #include <stdlib.h>  // 提供 rand_s
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
#endif

int generateRandomBinary(char *bin, int bits) {
    if (bits < 0 || bits > 512) {
        return -1;  // 参数错误
    }

#ifdef _WIN32
    unsigned int randomValue;
    for (int i = 0; i < bits; i++) {
        if (rand_s(&randomValue) != 0) {
            return -1;
        }
        // 利用最低位来决定输出 '1' 或 '0'
        bin[i] = (randomValue & 1) ? '1' : '0';
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("无法打开 /dev/urandom");
        return -1;
    }
    unsigned char byte;
    for (int i = 0; i < bits; i++) {
        if (read(fd, &byte, 1) != 1) {
            perror("读取 /dev/urandom 失败");
            close(fd);
            return -1;
        }
        bin[i] = (byte & 1) ? '1' : '0';
    }
    close(fd);
#endif

    bin[bits] = '\0';
    return 0;
}

void convertBinaryToHex(const char *bin, char *hex, int bits) {
    int hexDigits = bits / 4;
    for (int i = 0; i < hexDigits; i++) {
        int value = 0;
        // 每4位二进制转换为一个0～15的数值
        for (int j = 0; j < 4; j++) {
            value = value * 2 + (bin[i * 4 + j] - '0');
        }
        // 转换为16进制字符
        hex[i] = (value < 10) ? ('0' + value) : ('A' + (value - 10));
    }
    hex[hexDigits] = '\0';
}

