/*Author: 8891689
 * Assist in creation ：gemini
 */
#ifndef BIP32_H
#define BIP32_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// --- Include required dependencies based on the provided headers ---
#include "sha256.h"   // Provides SHA256_BLOCK_SIZE (as 32), sha256 functions
#include "ripemd160.h" // Provides RIPEMD160_DIGEST_LENGTH, ripemd160 functions
#include "pbkdf2.h"   // Provides hmac_sha512 prototype (and indirectly sha512)
#include "secp256k1.h" // Provides BigInt, ECPoint, secp256k1 functions
#include "base58.h"   // Provides base58_encode_check (allocating version)

// --- Constants ---
#define BIP32_HARDENED 0x80000000
#define BIP32_SERIALIZED_SIZE 78 // 4 version + 1 depth + 4 fp + 4 index + 32 chain + 33 key
#define XPRV_MAINNET_VERSION 0x0488ADE4
#define XPUB_MAINNET_VERSION 0x0488B21E
#define XPRV_TESTNET_VERSION 0x04358394
#define XPUB_TESTNET_VERSION 0x043587CF
// Define SHA512 digest length based on function prototypes in pbkdf2.h/sha512.h
#define SHA512_DIGEST_LENGTH 64
// SHA256 digest length is named SHA256_BLOCK_SIZE in sha256.h
// RIPEMD160 digest length should be defined in ripemd160.h, assume 20
// #define RIPEMD160_DIGEST_LENGTH 20 // Ensure this is in ripemd160.h

// --- Data Structures ---
// (bip32_private_key_t, bip32_public_key_t, bip32_extended_key_t remain the same)
typedef struct {
    uint8_t key[32];
} bip32_private_key_t;

typedef struct {
    uint8_t key[33];
} bip32_public_key_t;

// BIP32 Extended Key
typedef struct {
    uint32_t version; // Version bytes (determines xprv/xpub prefix)
    uint8_t depth;
    uint32_t fingerprint; // Fingerprint of the parent key
    uint32_t index;
    uint8_t chain_code[32];
    bip32_private_key_t priv; // Private key (if available)
    bip32_public_key_t pub;   // Corresponding public key
    bool has_private_key; // Flag to indicate if this structure holds a private key
} bip32_extended_key_t;

// Add this new helper function prototype near the others
int data_to_hash160(const uint8_t *data, size_t data_len, uint8_t hash160_out[RIPEMD160_DIGEST_LENGTH]);

// --- Function Prototypes ---
// Utility Functions
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len);
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_string); // Useful for debugging

// Byte/BigInt Conversion (Non-static, ensure compatibility with secp256k1.c)
void bytes_to_bigint(const uint8_t *bytes, size_t len, BigInt *result);
void bigint_to_bytes(const BigInt *num, uint8_t *bytes, size_t len);

// Core BIP32 Functions
bool seed_to_bip32_root_key(bip32_extended_key_t *key, const uint8_t *seed, size_t seed_len, bool use_mainnet_version);
bool bip32_derive_child_hardened(const bip32_extended_key_t *parent, uint32_t index, bip32_extended_key_t *child);
bool bip32_derive_child_normal(const bip32_extended_key_t *parent, uint32_t index, bip32_extended_key_t *child);

// Key Retrieval
void bip32_get_public_key(const bip32_extended_key_t *key, bip32_public_key_t *pub_key);
bool bip32_get_private_key(const bip32_extended_key_t *key, bip32_private_key_t *priv_key); // Return bool indicating success

// secp256k1 interaction
bool bip32_private_to_public(const bip32_private_key_t *priv_key, bip32_public_key_t *pub_key);
bool bip32_private_to_uncompressed_public(const bip32_private_key_t *priv_key, uint8_t pub_key_uncompressed[65]);
// Fingerprint Calculation
uint32_t calculate_fingerprint(const bip32_public_key_t *pub_key);

// Serialization
// Returns the number of bytes written to out_str (INCLUDING null terminator), or 0 on error.
// The underlying base58_encode_check allocates memory, which this function handles.
size_t serialize_xprv(const bip32_extended_key_t *key, char *out_str, size_t out_len);
size_t serialize_xpub(const bip32_extended_key_t *key, char *out_str, size_t out_len);

#endif // BIP32_H
