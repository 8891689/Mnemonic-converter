/*Author: 8891689
 * Assist in creation ：gemini
 */
//  gcc -o m bip32.c mnemonics.c secp256k1.c base58.c ripemd160.c sha256.c sha512.c pbkdf2.c random.c bip39.c keccak256.c cashaddr.c bech32.c
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

// BIP44 Coin Types (Hardened) - Existing
#define COIN_TYPE_BTC   (0 | BIP32_HARDENED)
#define COIN_TYPE_DOGE  (3 | BIP32_HARDENED)
#define COIN_TYPE_ETH   (60 | BIP32_HARDENED)
#define COIN_TYPE_BCH   (145 | BIP32_HARDENED)
#define COIN_TYPE_TRX   (195 | BIP32_HARDENED)

// BIP44 Coin Types (Hardened) - NEW
#define COIN_TYPE_LTC   (2 | BIP32_HARDENED)   // Litecoin
#define COIN_TYPE_DASH  (5 | BIP32_HARDENED)   // Dash
#define COIN_TYPE_ZEC   (133 | BIP32_HARDENED) // Zcash (t-addr)
#define COIN_TYPE_BTG   (156 | BIP32_HARDENED) // Bitcoin Gold

// Address Version Bytes (Examples - Verify these are correct for mainnet)
#define BITCOIN_P2PKH_VERSION  0x00
#define BITCOIN_P2SH_VERSION   0x05
#define BITCOIN_WIF_VERSION    0x80

#define LITECOIN_P2PKH_VERSION 0x30 // 'L' addresses
#define LITECOIN_P2SH_VERSION  0x32 // 'M' addresses (newer) or 0x05 ('3' legacy) - Using 0x30 for P2PKH example
#define LITECOIN_WIF_VERSION   0xB0

#define DOGECOIN_P2PKH_VERSION 0x1E // 'D' addresses
#define DOGECOIN_WIF_VERSION   0x9E

#define DASH_P2PKH_VERSION     0x4C // 'X' addresses
#define DASH_WIF_VERSION       0xCC

#define ZCASH_T_P2PKH_PREFIX1  0x1C // t1... addresses (need 2 bytes)
#define ZCASH_T_P2PKH_PREFIX2  0xB8
#define ZCASH_T_P2SH_PREFIX1   0x1C // t3... addresses (need 2 bytes)
#define ZCASH_T_P2SH_PREFIX2   0xBD
#define ZCASH_WIF_VERSION      0x80 // Same as Bitcoin

#define BITCOIN_GOLD_P2PKH_VERSION 0x26 // 'G' addresses
#define BITCOIN_GOLD_P2SH_VERSION  0x17 // 'A' addresses
#define BITCOIN_GOLD_WIF_VERSION   0x80 // Same as Bitcoin

#define BITCOIN_CASH_PREFIX "bitcoincash" // Already used
#define BITCOIN_CASH_WIF_VERSION 0x80 // Same as Bitcoin

// Note: Zcash t-addr prefixes are two bytes. Our current base58 function might only handle one.
// We will calculate the HASH160 for Zcash but might skip full address generation for simplicity unless base58 function is modified.

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
int private_key_to_wif(const uint8_t private_key[32], uint8_t wif_version_byte, bool compressed, char *wif_out, size_t wif_out_len);
void print_hex(const char* label, const uint8_t* data, size_t len);
int prefix2_hash160_to_base58_addr(uint8_t prefix1, uint8_t prefix2, const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], char *addr_out, size_t addr_out_len);

// --- Helper Function Implementations ---
// Generates Base58Check address from HASH160 using a two-byte prefix
// Specifically for formats like Zcash t-addresses.
int prefix2_hash160_to_base58_addr(
    uint8_t prefix1,
    uint8_t prefix2,
    const uint8_t hash160[RIPEMD160_DIGEST_LENGTH],
    char *addr_out,
    size_t addr_out_len)
{
    // 1. Prepare the data buffer: [prefix1][prefix2][hash160]
    const size_t data_len = 2 + RIPEMD160_DIGEST_LENGTH;
    uint8_t versioned_hash160[data_len]; // Use VLA (C99+) or malloc if needed

    versioned_hash160[0] = prefix1;
    versioned_hash160[1] = prefix2;
    memcpy(versioned_hash160 + 2, hash160, RIPEMD160_DIGEST_LENGTH);

    // 2. Call the existing base58_encode_check (which allocates memory)
    char *encoded_ptr = base58_encode_check(versioned_hash160, data_len);
    if (encoded_ptr == NULL) {
        // fprintf(stderr, "Error: base58_encode_check failed for 2-byte prefix.\n"); // Optional error message
         if (addr_out_len > 0) addr_out[0] = '\0'; // Clear output buffer on failure
        return 1; // Indicate failure: encoding failed
    }

    // 3. Copy the result to the output buffer (check length)
    size_t encoded_len = strlen(encoded_ptr);
    if (encoded_len >= addr_out_len) {
        // fprintf(stderr, "Error: Output buffer too small for Base58Check string (need %zu, have %zu).\n", encoded_len + 1, addr_out_len); // Optional
        free(encoded_ptr); // IMPORTANT: Free the allocated memory even on error
         if (addr_out_len > 0) addr_out[0] = '\0'; // Clear output buffer
        return 2; // Indicate failure: buffer too small
    }

    strcpy(addr_out, encoded_ptr);

    // 4. Free the allocated memory from base58_encode_check
    free(encoded_ptr);

    return 0; // Indicate success
}

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

// Modified implementation (Accepts wif_version_byte):
int private_key_to_wif(const uint8_t private_key[32], uint8_t wif_version_byte, bool compressed, char *wif_out, size_t wif_out_len) {
    size_t data_size = 1 + 32 + (compressed ? 1 : 0);
    uint8_t wif_data[34]; // Max size: 1 (version) + 32 (key) + 1 (compression flag)

    wif_data[0] = wif_version_byte; // Use the provided version byte
    memcpy(wif_data + 1, private_key, 32);
    if (compressed) {
        wif_data[1 + 32] = 0x01; // Append compression flag if needed
    }
    // Note: data_size must be correct based on whether compressed is true

    char *encoded_ptr = base58_encode_check(wif_data, data_size);
    if (encoded_ptr == NULL) {
        if (wif_out_len > 0) wif_out[0] = '\0';
        return 1; // Encoding failed
    }

    size_t encoded_len = strlen(encoded_ptr);
    if (encoded_len >= wif_out_len) {
        free(encoded_ptr);
        if (wif_out_len > 0) wif_out[0] = '\0';
        return 2; // Output buffer too small
    }

    strcpy(wif_out, encoded_ptr);
    free(encoded_ptr);
    return 0; // Success
}

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s", label); for (size_t i = 0; i < len; ++i) printf("%02x", data[i]); printf("\n");
}

// --- Main Program ---
int main(int argc, char *argv[]) { // Add argc, argv
    char *mnemonic = NULL;
    bool free_mnemonic = false; // Flag to know if we allocated mnemonic

    printf("--- Wallet Details ---\n");

    // Check command line arguments for mnemonic
    if (argc > 1) {
        // Concatenate arguments into a single mnemonic string
        size_t total_len = 0;
        for (int i = 1; i < argc; i++) {
            total_len += strlen(argv[i]) + 1; // +1 for space or null terminator
        }

        mnemonic = (char *)malloc(total_len);
        if (mnemonic == NULL) {
            fprintf(stderr, "Error: Could not allocate memory for mnemonic string.\n");
            return 1;
        }
        mnemonic[0] = '\0'; // Start with an empty string

        for (int i = 1; i < argc; i++) {
            strcat(mnemonic, argv[i]);
            if (i < argc - 1) {
                strcat(mnemonic, " "); // Add space between words
            }
        }
        printf("Using Mnemonic from arguments: %s\n", mnemonic);

                // --- VALIDATION (Optional - Block Commented Out) ---
        /*
        // Count words (simple space count)
        int word_count = 1;
        for(char *p = mnemonic; *p; p++) if (*p == ' ') word_count++;

        if (word_count != 12 && word_count != 24) {
             fprintf(stderr, "Error: Invalid number of words (%d) in provided mnemonic. Must be 12 or 24.\n", word_count);
             free(mnemonic);
             return 1;
        }
        // Use bip39 check if available
        #ifdef BIP39_H // Check if bip39.h defines a macro (adapt if needed)
        // Requires mnemonic_check function in bip39 library
        if (!mnemonic_check(mnemonic)) {
             fprintf(stderr, "Error: Invalid mnemonic phrase provided (checksum or word mismatch).\n");
             free(mnemonic);
             return 1;
        }
        printf("Mnemonic provided is valid.\n");
        #else
        printf("Warning: Mnemonic validation function (mnemonic_check) not detected. Skipping validation.\n");
        #endif
        */
        // --- END VALIDATION ---

    } else {
        // Generate random mnemonic if no arguments provided
        printf("No mnemonic provided via arguments. Generating a random one...\n");
        mnemonic = generate_mnemonic_phrase(NUM_WORDS);
        if (mnemonic == NULL) {
             fprintf(stderr, "Error: Failed to generate random mnemonic.\n");
            return 1;
        }
        free_mnemonic = true; // Mark that we need to free this later
        printf("Generated Mnemonic (%d words): %s\n", NUM_WORDS, mnemonic);
    }

    printf("Passphrase Used: \"%s\"\n\n", PASSPHRASE);

    // 2. Mnemonic to Seed (Rest of the code remains the same initially)
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
    if (!seed_to_bip32_root_key(&root_key, seed, SEED_BYTES, true)) { // Assuming mainnet
        if (free_mnemonic) free(mnemonic);
        return 1;
    }


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
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, BITCOIN_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
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
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, BITCOIN_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
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
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, BITCOIN_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
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
            // Use DOGECOIN_P2PKH_VERSION defined earlier
            if (hash160_to_p2pkh_addr(hash160, DOGECOIN_P2PKH_VERSION, address_str, sizeof(address_str)) == 0) {
                printf("   Address: %s\n", address_str);
            } else { printf("   Error generating DOGE address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        // Use the modified WIF function with DOGECOIN_WIF_VERSION
         if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, DOGECOIN_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving DOGE key.\n"); }
    printf("\n");


    // --- Litecoin (LTC) --- NEW SECTION ---
    printf("--- Litecoin (LTC) ---\n");
    printf("   Path: m/44'/2'/0'/0/0\n"); // BIP44 P2PKH path
     if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_LTC, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            // Use LITECOIN_P2PKH_VERSION
            if (hash160_to_p2pkh_addr(hash160, LITECOIN_P2PKH_VERSION, address_str, sizeof(address_str)) == 0) {
                printf("   Address (P2PKH): %s\n", address_str);
            } else { printf("   Error generating LTC address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        // Use the modified WIF function with LITECOIN_WIF_VERSION
         if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, LITECOIN_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving LTC key.\n"); }
    printf("\n");

    // --- Dash (DASH) --- NEW SECTION ---
    printf("--- Dash (DASH) ---\n");
    printf("   Path: m/44'/5'/0'/0/0\n"); // BIP44 P2PKH path
     if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_DASH, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            // Use DASH_P2PKH_VERSION
            if (hash160_to_p2pkh_addr(hash160, DASH_P2PKH_VERSION, address_str, sizeof(address_str)) == 0) {
                printf("   Address (P2PKH): %s\n", address_str);
            } else { printf("   Error generating DASH address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        // Use the modified WIF function with DASH_WIF_VERSION
         if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, DASH_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving DASH key.\n"); }
    printf("\n");

   // --- Zcash (ZEC) --- NEW SECTION ---
printf("--- Zcash (ZEC) Transparent ---\n");
printf("   Path: m/44'/133'/0'/0/0\n"); // BIP44 t-addr path
 if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
    bip32_derive_child_hardened(&purpose_key, COIN_TYPE_ZEC, &coin_key) &&
    bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
    bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
    bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
{
    print_hex("   Public Key (hex): ", address_key.pub.key, 33);
    if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
        // --- USE THE NEW FUNCTION for ZEC t-addr P2PKH ---
        if (prefix2_hash160_to_base58_addr(ZCASH_T_P2PKH_PREFIX1, ZCASH_T_P2PKH_PREFIX2, hash160, address_str, sizeof(address_str)) == 0) {
             printf("   Address (t-addr P2PKH): %s\n", address_str); // <<< Now generates the address
        } else {
             printf("   Error generating ZEC t-addr address.\n");
             // Optional: Print HASH160 if address generation failed
             // print_hex("   Address HASH160 (hex): ", hash160, RIPEMD160_DIGEST_LENGTH);
        }
        // --- END ZEC ADDRESS GENERATION ---
    } else { printf("   Error generating HASH160.\n"); }
    // Use the modified WIF function with ZCASH_WIF_VERSION
     if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, ZCASH_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
        printf("   Private Key (WIF): %s\n", wif_str);
    }
} else { printf("   Error deriving ZEC key.\n"); }
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
            if (hash160_to_cashaddr(hash160, BITCOIN_CASH_PREFIX, address_str, sizeof(address_str)) == 0) {
                printf("   Address (CashAddr): %s\n", address_str);
            } else { printf("   Error generating CashAddr address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        // Use BITCOIN_CASH_WIF_VERSION (same as BTC)
        if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, BITCOIN_CASH_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving BCH key.\n"); }
    printf("\n");


    // --- Bitcoin Gold (BTG) --- NEW SECTION ---
    printf("--- Bitcoin Gold (BTG) ---\n");
    printf("   Path: m/44'/156'/0'/0/0\n"); // BIP44 P2PKH path
     if (bip32_derive_child_hardened(&root_key, PURPOSE_BIP44, &purpose_key) &&
        bip32_derive_child_hardened(&purpose_key, COIN_TYPE_BTG, &coin_key) &&
        bip32_derive_child_hardened(&coin_key, ACCOUNT_0, &account_key) &&
        bip32_derive_child_normal(&account_key, CHANGE_EXTERNAL, &change_key) &&
        bip32_derive_child_normal(&change_key, ADDRESS_INDEX_0, &address_key))
    {
        print_hex("   Public Key (hex): ", address_key.pub.key, 33);
        if (public_key_to_hash160(address_key.pub.key, hash160) == 0) {
            // Use BITCOIN_GOLD_P2PKH_VERSION
            if (hash160_to_p2pkh_addr(hash160, BITCOIN_GOLD_P2PKH_VERSION, address_str, sizeof(address_str)) == 0) {
                printf("   Address (P2PKH): %s\n", address_str);
            } else { printf("   Error generating BTG address.\n"); }
        } else { printf("   Error generating HASH160.\n"); }
        // Use BITCOIN_GOLD_WIF_VERSION (same as BTC)
         if (address_key.has_private_key && private_key_to_wif(address_key.priv.key, BITCOIN_GOLD_WIF_VERSION, true, wif_str, sizeof(wif_str)) == 0) {
            printf("   Private Key (WIF): %s\n", wif_str);
        }
    } else { printf("   Error deriving BTG key.\n"); }
    printf("\n");


    // Clean up
    if (free_mnemonic) { // Only free if we allocated it
         free(mnemonic);
    }

    return 0;
}
