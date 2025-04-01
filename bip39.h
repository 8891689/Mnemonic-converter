#ifndef BIP39_H
#define BIP39_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// BIP39 wordlist declaration
extern const char *bip39_wordlist[];

// Function declarations
const char* get_bip39_word(int index);
int get_bip39_index(const char *word);

#endif

