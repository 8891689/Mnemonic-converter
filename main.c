/*Author: 8891689
 * Assist in creation ：gemini
 */
//  gcc -o bip32_test bip32.c main.c secp256k1.c base58.c ripemd160.c sha256.c sha512.c pbkdf2.c random.c bip39.c keccak256.c cashaddr.c bech32.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <math.h> // For ceil

// --- Include all necessary headers ---
#include "random.h"
#include "bip39.h"
#include "sha256.h"
#include "pbkdf2.h" // Requires sha512 implicitly
#include "bip32.h"  // Requires base58, ripemd160, secp256k1 etc.
#include "ripemd160.h" // Explicit include for RIPEMD160_DIGEST_LENGTH if not in bip32.h
#include "base58.h"    // Explicit include for base58_encode_check if needed directly

// --- Include NEW headers ---
#include "keccak256.h" // For ETH, TRX
#include "cashaddr.h"  // For BCH
#include "bech32.h"    // For BTC Native SegWit (bc1)
// #include "sha3256.h" // Include if you have it, but likely unused for these coins

// --- Configuration ---
#define NUM_WORDS 12       // 12 or 24
#define PASSPHRASE ""      // Optional passphrase

// --- Constants ---
#if NUM_WORDS == 12
    #define ENTROPY_BITS 128
    #define CHECKSUM_BITS 4
#elif NUM_WORDS == 24
    #define ENTROPY_BITS 256
    #define CHECKSUM_BITS 8
#else
    #error "NUM_WORDS must be 12 or 24."
#endif
#define ENTROPY_BYTES (ENTROPY_BITS / 8)
#define SEED_BYTES 64

// BIP44 Coin Types (Hardened)
#define COIN_TYPE_BTC   (0 | BIP32_HARDENED)
#define COIN_TYPE_DOGE  (3 | BIP32_HARDENED)
#define COIN_TYPE_ETH   (60 | BIP32_HARDENED)
#define COIN_TYPE_BCH   (145 | BIP32_HARDENED)
#define COIN_TYPE_TRX   (195 | BIP32_HARDENED)

// BIP Purpose Constants (Hardened)
#define PURPOSE_BIP44   (44 | BIP32_HARDENED)
#define PURPOSE_BIP49   (49 | BIP32_HARDENED) // P2SH-SegWit
#define PURPOSE_BIP84   (84 | BIP32_HARDENED) // Native SegWit (Bech32)

#define ACCOUNT_0       (0 | BIP32_HARDENED)
#define CHANGE_EXTERNAL 0
#define ADDRESS_INDEX_0 0

// --- Helper Function Prototypes ---
int binary_string_to_bytes(const char *bin_str, uint8_t *bytes, size_t max_bytes);
uint16_t extract_11_bits(const uint8_t *entropy, uint8_t checksum_byte, int bit_offset);
char* generate_mnemonic_phrase(int num_words);
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed_out[SEED_BYTES]);
int public_key_to_hash160(const uint8_t public_key[33], uint8_t hash160_out[RIPEMD160_DIGEST_LENGTH]);
int hash160_to_p2pkh_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], uint8_t version_byte, char *addr_out, size_t addr_out_len);
int hash160_to_p2sh_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], uint8_t version_byte, char *addr_out, size_t addr_out_len);
int hash160_to_bech32_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], const char *hrp, int witver, char *addr_out, size_t addr_out_len);
int uncompressed_pubkey_to_eth_addr(const uint8_t pubkey_uncompressed[65], char *addr_out, size_t addr_out_len);
int uncompressed_pubkey_to_trx_addr(const uint8_t pubkey_uncompressed[65], char *addr_out, size_t addr_out_len);
int hash160_to_cashaddr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], const char *prefix, char *addr_out, size_t addr_out_len);
int private_key_to_wif(const uint8_t private_key[32], bool compressed, char *wif_out, size_t wif_out_len);
void print_hex(const char* label, const uint8_t* data, size_t len);

// --- Helper Function Implementations ---

// binary_string_to_bytes, extract_11_bits, generate_mnemonic_phrase, mnemonic_to_seed
// (Keep implementations from previous version, ensure generate_mnemonic_phrase doesn't print entropy)
int binary_string_to_bytes(const char *bin_str, uint8_t *bytes, size_t max_bytes) {
    size_t len = strlen(bin_str);
    if (len % 8 != 0) return -1;
    size_t num_bytes = len / 8;
    if (num_bytes > max_bytes) return -1;
    memset(bytes, 0, num_bytes);
    for (size_t i = 0; i < num_bytes; ++i) {
        for (int j = 0; j < 8; ++j) {
            char bit_char = bin_str[i * 8 + j];
            if (bit_char != '0' && bit_char != '1') return -1;
            if (bit_char == '1') bytes[i] |= (1 << (7 - j));
        }
    }
    return (int)num_bytes;
}
uint16_t extract_11_bits(const uint8_t *entropy, uint8_t checksum_byte, int bit_offset) {
    uint16_t index = 0;
    for (int i = 0; i < 11; ++i) {
        int current_total_bit = bit_offset + i;
        uint8_t current_byte; int bit_in_byte;
        if (current_total_bit < ENTROPY_BITS) {
            int byte_index = current_total_bit / 8; bit_in_byte = 7 - (current_total_bit % 8); current_byte = entropy[byte_index];
        } else {
            int checksum_bit_index = current_total_bit - ENTROPY_BITS; if (checksum_bit_index >= CHECKSUM_BITS) return 0xFFFF;
            bit_in_byte = 7 - checksum_bit_index; current_byte = checksum_byte;
        }
        index = (index << 1) | ((current_byte >> bit_in_byte) & 1);
    }
    return index;
}
char* generate_mnemonic_phrase(int num_words) {
    char binary_entropy_str[ENTROPY_BITS + 1];
    if (generateRandomBinary(binary_entropy_str, ENTROPY_BITS) != 0) return NULL;
    uint8_t entropy[ENTROPY_BYTES];
    if (binary_string_to_bytes(binary_entropy_str, entropy, sizeof(entropy)) != ENTROPY_BYTES) return NULL;
    uint8_t sha256_hash[SHA256_BLOCK_SIZE]; sha256(entropy, ENTROPY_BYTES, sha256_hash); uint8_t checksum_byte = sha256_hash[0];
    char *mnemonic_str = (char*)malloc(num_words * 10 + 1); if (mnemonic_str == NULL) return NULL; mnemonic_str[0] = '\0';
    for (int i = 0; i < num_words; ++i) {
        uint16_t index = extract_11_bits(entropy, checksum_byte, i * 11); if (index == 0xFFFF) { free(mnemonic_str); return NULL; }
        const char *word = get_bip39_word(index); if (word == NULL) { free(mnemonic_str); return NULL; }
        if (i > 0) strcat(mnemonic_str, " "); strcat(mnemonic_str, word);
    }
    return mnemonic_str;
}
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed_out[SEED_BYTES]) {
    char salt[128] = "mnemonic"; strncat(salt, passphrase, sizeof(salt) - strlen(salt) - 1);
    pbkdf2_hmac_sha512((const uint8_t*)mnemonic, strlen(mnemonic), (const uint8_t*)salt, strlen(salt), 2048, seed_out, SEED_BYTES);
}

// Calculates RIPEMD160(SHA256(pubkey))
int public_key_to_hash160(const uint8_t public_key[33], uint8_t hash160_out[RIPEMD160_DIGEST_LENGTH]) {
    if (public_key[0] != 0x02 && public_key[0] != 0x03) return 1; // Only compressed
    uint8_t sha256_hash[SHA256_BLOCK_SIZE];
    sha256(public_key, 33, sha256_hash);
    ripemd160(sha256_hash, SHA256_BLOCK_SIZE, hash160_out);
    return 0;
}

// Generic Base58Check address generation from HASH160
int hash160_to_base58_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], uint8_t version_byte, char *addr_out, size_t addr_out_len) {
    uint8_t versioned_hash160[1 + RIPEMD160_DIGEST_LENGTH];
    versioned_hash160[0] = version_byte;
    memcpy(versioned_hash160 + 1, hash160, RIPEMD160_DIGEST_LENGTH);

    char *encoded_ptr = base58_encode_check(versioned_hash160, sizeof(versioned_hash160));
    if (encoded_ptr == NULL) return 1;

    size_t encoded_len = strlen(encoded_ptr);
    if (encoded_len >= addr_out_len) { free(encoded_ptr); return 2; } // Buffer too small

    strcpy(addr_out, encoded_ptr);
    free(encoded_ptr);
    return 0;
}

// Specific wrappers for P2PKH and P2SH
int hash160_to_p2pkh_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], uint8_t version_byte, char *addr_out, size_t addr_out_len) {
    return hash160_to_base58_addr(hash160, version_byte, addr_out, addr_out_len);
}
int hash160_to_p2sh_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], uint8_t version_byte, char *addr_out, size_t addr_out_len) {
    return hash160_to_base58_addr(hash160, version_byte, addr_out, addr_out_len);
}


// Generates Bech32 address (SegWit v0 P2WPKH)
int hash160_to_bech32_addr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], const char *hrp, int witver, char *addr_out, size_t addr_out_len) {
    // segwit_addr_encode expects the output buffer size, let's estimate generously
    // Max Bech32 length is 90.
    if (addr_out_len < 91) return 1; // Ensure buffer is large enough

    if (segwit_addr_encode(addr_out, hrp, witver, hash160, RIPEMD160_DIGEST_LENGTH) == 1) {
        return 0; // Success
    } else {
        addr_out[0] = '\0'; // Clear output on failure
        return 2; // Encoding failed
    }
}

// Generates Ethereum address
int uncompressed_pubkey_to_eth_addr(const uint8_t pubkey_uncompressed[65], char *addr_out, size_t addr_out_len) {
    if (pubkey_uncompressed[0] != 0x04) return 1; // Expect uncompressed format
    if (addr_out_len < 43) return 2; // Need space for "0x" + 40 hex chars + null

    uint8_t keccak_hash[32];
    // Hash the X and Y coordinates (64 bytes), skipping the 0x04 prefix
    keccak_256(pubkey_uncompressed + 1, 64, keccak_hash);

    // Ethereum address is the last 20 bytes of the hash
    strcpy(addr_out, "0x");
    bytes_to_hex(keccak_hash + 12, 20, addr_out + 2); // Convert last 20 bytes to hex

    return 0;
}

// Generates Tron address
int uncompressed_pubkey_to_trx_addr(const uint8_t pubkey_uncompressed[65], char *addr_out, size_t addr_out_len) {
     if (pubkey_uncompressed[0] != 0x04) return 1; // Expect uncompressed format

    uint8_t keccak_hash[32];
    // Hash the X and Y coordinates (64 bytes)
    keccak_256(pubkey_uncompressed + 1, 64, keccak_hash);

    // Tron address raw format: 0x41 (prefix) + last 20 bytes of Keccak hash
    uint8_t raw_addr[1 + 20];
    raw_addr[0] = 0x41; // Tron address prefix
    memcpy(raw_addr + 1, keccak_hash + 12, 20);

    // Base58Check encode the raw address (requires double SHA256 checksum)
    // Reuse the generic Base58Check function
    char *encoded_ptr = base58_encode_check(raw_addr, sizeof(raw_addr));
     if (encoded_ptr == NULL) return 2;

    size_t encoded_len = strlen(encoded_ptr);
    if (encoded_len >= addr_out_len) { free(encoded_ptr); return 3; } // Buffer too small

    strcpy(addr_out, encoded_ptr);
    free(encoded_ptr);
    return 0;
}

// Generates Bitcoin Cash address (CashAddr format)
// Generates Bitcoin Cash address (CashAddr format)
int hash160_to_cashaddr(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], const char *prefix, char *addr_out, size_t addr_out_len) {
    char hash160_hex[41];
    bytes_to_hex(hash160, RIPEMD160_DIGEST_LENGTH, hash160_hex); // Convert HASH160 to hex
    //printf("Debug: HASH160 for CashAddr (hex): %s\n", hash160_hex);
    // Use version 0 and type P2PKH for standard addresses from pubkey
    // Call the actual encoding function from cashaddr.c
    if (encode_cashaddr(prefix, 0, "P2PKH", hash160_hex, addr_out, addr_out_len) == 0) {
        return 0; // Success
    } else {
        addr_out[0] = '\0';
        return 1; // Encoding failed
    }
}


// private_key_to_wif, print_hex
// (Keep implementations from previous version)
int private_key_to_wif(const uint8_t private_key[32], bool compressed, char *wif_out, size_t wif_out_len) {
    size_t data_size = 1 + 32 + (compressed ? 1 : 0); uint8_t wif_data[34];
    wif_data[0] = 0x80; memcpy(wif_data + 1, private_key, 32); if (compressed) wif_data[1 + 32] = 0x01;
    char *encoded_ptr = base58_encode_check(wif_data, data_size); if (encoded_ptr == NULL) return 1;
    size_t encoded_len = strlen(encoded_ptr); if (encoded_len >= wif_out_len) { free(encoded_ptr); return 2; }
    strcpy(wif_out, encoded_ptr); free(encoded_ptr); return 0;
}
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s", label); for (size_t i = 0; i < len; ++i) printf("%02x", data[i]); printf("\n");
}

// --- Main Program ---
int main() {
    // 1. Generate Mnemonic
    char *mnemonic = generate_mnemonic_phrase(NUM_WORDS);
    if (mnemonic == NULL) return 1;
    printf("--- Wallet Details ---\n");
    printf("Generated Mnemonic (%d words): %s\n", NUM_WORDS, mnemonic);
    printf("Passphrase Used: \"%s\"\n\n", PASSPHRASE);

    // 2. Mnemonic to Seed
    uint8_t seed[SEED_BYTES];
    mnemonic_to_seed(mnemonic, PASSPHRASE, seed);
    print_hex("BIP32 Root Seed (hex): ", seed, SEED_BYTES);
    printf("\n");

    // --- BIP32 Derivations ---
    bip32_extended_key_t root_key, purpose_key, coin_key, account_key, change_key, address_key;
    char xpub_str[120], xprv_str[120];
    char wif_str[60];
    uint8_t pubkey_compressed[33];
    uint8_t pubkey_uncompressed[65]; // For ETH/TRX
    uint8_t hash160[RIPEMD160_DIGEST_LENGTH];
    char address_str[100]; // General purpose address buffer

    // Derive Root Key
    if (!seed_to_bip32_root_key(&root_key, seed, SEED_BYTES, true)) { free(mnemonic); return 1; }

    // --- Bitcoin (BTC) ---
    printf("--- Bitcoin (BTC) ---\n");
    // BIP84 (Native SegWit - bc1q) Path: m/84'/0'/0'/0/0
    printf("-> BIP84 Native SegWit (P2WPKH)\n");
    printf("   Path: m/84'/0'/0'/0/0\n");
    if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP84, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_BTC, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            if (hash160_to_bech32_addr(hash160, "bc", 0, address_str, sizeof(address_str)) == 0) {
                printf("   Address (Bech32): %s\n", address_str);
            } else { printf("   Error generating Bech32 address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving BIP84 key.\n"); }

    // BIP49 (P2SH-SegWit - 3...) Path: m/49'/0'/0'/0/0
    printf("-> BIP49 Wrapped SegWit (P2SH-P2WPKH)\n");
    printf("   Path: m/49'/0'/0'/0/0\n");
    if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP49, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_BTC, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
                // P2SH-P2WPKH: HASH160(0x00 0x14 HASH160(pubkey))
    if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
        uint8_t witness_script[22]; // 00 14 <20_byte_hash>
        witness_script[0] = 0x00; // Witness version 0
        witness_script[1] = 0x14; // Push 20 bytes
        memcpy(witness_script + 2, hash160, 20);
        // Now HASH160 the script itself for P2SH
        // --- USE THE NEW FUNCTION ---
        if (data_to_hash160(witness_script, sizeof(witness_script), hash160) == 0) { // Re-use hash160 var
        // --- END FIX ---
             if (hash160_to_p2sh_addr(hash160, 0x05, address_str, sizeof(address_str)) == 0) { // 0x05 = P2SH Mainnet version
                 printf("   Address (P2SH-SegWit): %s\n", address_str);
             } else { printf("   Error generating P2SH-SegWit address.\n"); }
        } else { printf("   Error generating script HASH160.\n"); }
    } else { printf("   Error generating public key HASH160.\n"); }
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving BIP49 key.\n"); }

    // BIP44 (Legacy - 1...) Path: m/44'/0'/0'/0/0
    printf("-> BIP44 Legacy (P2PKH)\n");
    printf("   Path: m/44'/0'/0'/0/0\n");
    if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_BTC, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        // Print Account 0 xpub/xprv for BIP44 BTC
        if (serialize_xpub(&account_key, xpub_str, sizeof(xpub_str)) > 0) printf("   Account xpub: %s\n", xpub_str);
        if (serialize_xprv(&account_key, xprv_str, sizeof(xprv_str)) > 0) printf("   Account xprv: %s\n", xprv_str);

        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            if (hash160_to_p2pkh_addr(hash160, 0x00, address_str, sizeof(address_str)) == 0) { // 0x00 = P2PKH Mainnet version
                printf("   Address (Legacy): %s\n", address_str);
            } else { printf("   Error generating Legacy address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving BIP44 key.\n"); }
    printf("\n");


    // --- Ethereum (ETH) ---
    printf("--- Ethereum (ETH) ---\n");
    printf("   Path: m/44'/60'/0'/0/0\n");
    if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_ETH, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        if (address_key.has_private_key) {
            print_hex("   Private Key (hex): ", address_key.priv.key, 32); // ETH uses raw hex private key
            if (bip32_private_to_uncompressed_public(&address_key.priv, pubkey_uncompressed)) {
                 print_hex("   Public Key (uncompressed hex): ", pubkey_uncompressed, 65);
                 if (uncompressed_pubkey_to_eth_addr(pubkey_uncompressed, address_str, sizeof(address_str)) == 0) {
                     printf("   Address: %s\n", address_str);
                 } else { printf("   Error generating ETH address.\n"); }
            } else { printf("   Error deriving uncompressed public key.\n"); }
        } else { printf("   Private key not available for ETH derivation.\n"); }
    } else { printf("   Error deriving ETH key.\n"); }
    printf("\n");

    // --- Tron (TRX) ---
    printf("--- Tron (TRX) ---\n");
    printf("   Path: m/44'/195'/0'/0/0\n");
    if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_TRX, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
         if (address_key.has_private_key) {
            print_hex("   Private Key (hex): ", address_key.priv.key, 32);
             if (bip32_private_to_uncompressed_public(&address_key.priv, pubkey_uncompressed)) {
                 print_hex("   Public Key (uncompressed hex): ", pubkey_uncompressed, 65);
                 if (uncompressed_pubkey_to_trx_addr(pubkey_uncompressed, address_str, sizeof(address_str)) == 0) {
                     printf("   Address: %s\n", address_str);
                 } else { printf("   Error generating TRX address.\n"); }
            } else { printf("   Error deriving uncompressed public key.\n"); }
        } else { printf("   Private key not available for TRX derivation.\n"); }
    } else { printf("   Error deriving TRX key.\n"); }
    printf("\n");


    // --- Dogecoin (DOGE) ---
    printf("--- Dogecoin (DOGE) ---\n");
    printf("   Path: m/44'/3'/0'/0/0\n");
     if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_DOGE, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            if (hash160_to_p2pkh_addr(hash160, 0x1E, address_str, sizeof(address_str)) == 0) { // 0x1E = DOGE P2PKH version
                printf("   Address: %s\n", address_str);
            } else { printf("   Error generating DOGE address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        // Doge WIF uses different version byte (0x9E), need to adjust private_key_to_wif or add specific func if needed
        // For now, just showing the raw private key if available
         if (address_key.has_private_key) print_hex("   Private Key (raw hex): ", address_key.priv.key, 32);
    } else { printf("   Error deriving DOGE key.\n"); }
    printf("\n");

    // --- Bitcoin Cash (BCH) ---
    printf("--- Bitcoin Cash (BCH) ---\n");
    printf("   Path: m/44'/145'/0'/0/0\n");
     if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_BCH, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            // Use CashAddr format with "bitcoincash:" prefix (library might add it or expect it)
            if (hash160_to_cashaddr(hash160, "bitcoincash", address_str, sizeof(address_str)) == 0) {
                printf("   Address (CashAddr): %s\n", address_str);
            } else { printf("   Error generating CashAddr address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str); // BCH uses same WIF as BTC
        }
    } else { printf("   Error deriving BCH key.\n"); }
    printf("\n");


    // Clean up
    free(mnemonic);

    return 0;
}
