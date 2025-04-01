/*Author: 8891689
 * Assist in creation ：gemini
 */
#include "bip32.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Note: Includes for sha256, sha512, ripemd160, secp256k1, base58
// are handled by including bip32.h above.


// Add this new helper function implementation
int data_to_hash160(const uint8_t *data, size_t data_len, uint8_t hash160_out[RIPEMD160_DIGEST_LENGTH]) {
    uint8_t sha256_hash[SHA256_BLOCK_SIZE];
    sha256(data, data_len, sha256_hash); // Hash the input data of length data_len
    ripemd160(sha256_hash, SHA256_BLOCK_SIZE, hash160_out); // RIPEMD160 the SHA256 hash
    return 0; // Assume success for simplicity here
}

// --- Utility Functions ---

// Convert hex character to integer value (static helper)
static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Convert hex string to byte array
// Returns the number of bytes converted, or -1 on error.
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        //fprintf(stderr, "Error: Hex string must have an even number of characters.\n");
        return -1; // Invalid hex length
    }
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) {
         //fprintf(stderr, "Error: Output buffer too small for hex string (%zu bytes needed, %zu available).\n", byte_len, max_len);
        return -1; // Output buffer too small
    }

    for (size_t i = 0; i < byte_len; i++) {
        int high = hex_val(hex[i * 2]);
        int low = hex_val(hex[i * 2 + 1]);
        if (high == -1 || low == -1) {
             //fprintf(stderr, "Error: Invalid character in hex string.\n");
            return -1; // Invalid hex character
        }
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    return (int)byte_len;
}

// Convert byte array to hex string
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_string) {
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_string[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_string[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_string[len * 2] = '\0'; // Null-terminate the string
}


// --- Byte/BigInt Conversion ---
// Assuming Big-Endian bytes to internal BigInt representation
void bytes_to_bigint(const uint8_t *bytes, size_t len, BigInt *result) {
    memset(result, 0, sizeof(BigInt));
    for (int i = 0; i < len; i++) {
        int word_index = (len - 1 - i) / 4;
        int byte_in_word = (len - 1 - i) % 4;
        if (word_index >= BIGINT_WORDS) continue;
        result->data[word_index] |= (uint32_t)bytes[i] << (8 * byte_in_word);
    }
}

void bigint_to_bytes(const BigInt *num, uint8_t *bytes, size_t len) {
    memset(bytes, 0, len);
    for (int i = 0; i < len; i++) {
        int word_index = (len - 1 - i) / 4;
        int byte_in_word = (len - 1 - i) % 4;
        if (word_index >= BIGINT_WORDS) continue;
        bytes[i] = (num->data[word_index] >> (8 * byte_in_word)) & 0xFF;
    }
}


// --- Core BIP32 Functions ---

// Initializes the root extended key from a seed.
bool seed_to_bip32_root_key(bip32_extended_key_t *key, const uint8_t *seed, size_t seed_len, bool use_mainnet_version) {
    uint8_t hmac_out[SHA512_DIGEST_LENGTH]; // 64 bytes
    const char *key_str = "Bitcoin seed";

    hmac_sha512((const uint8_t *)key_str, strlen(key_str), seed, seed_len, hmac_out);

    memset(key, 0, sizeof(bip32_extended_key_t));
    key->depth = 0;
    key->index = 0;
    key->fingerprint = 0x00000000;
    key->version = use_mainnet_version ? XPRV_MAINNET_VERSION : XPRV_TESTNET_VERSION;
    key->has_private_key = true;

    BigInt k_bi;
    bytes_to_bigint(hmac_out, 32, &k_bi);

    // Check if the generated private key is valid (not 0 and < N)
    if (is_zero(&k_bi) || compare_bigint(&k_bi, &secp256k1_n) >= 0) {
        //fprintf(stderr, "Warning: Invalid master private key generated (>= N or == 0).\n");
        // Returning false, as a valid key couldn't be guaranteed.
        // A production library might retry or handle this differently.
        return false;
    }

    memcpy(key->priv.key, hmac_out, 32);
    memcpy(key->chain_code, hmac_out + 32, 32);

    if (!bip32_private_to_public(&key->priv, &key->pub)) {
        //fprintf(stderr, "Error: Failed to derive public key from master private key.\n");
        return false;
    }

    return true;
}

// Calculate the fingerprint of a public key
uint32_t calculate_fingerprint(const bip32_public_key_t *pub_key) {
    uint8_t sha256_hash[SHA256_BLOCK_SIZE];
    uint8_t ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

    // 1. SHA256
    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, pub_key->key, 33);
    sha256_final(&sha_ctx, sha256_hash);

    // 2. RIPEMD160
    RIPEMD160_CTX rip_ctx;
    ripemd160_init(&rip_ctx);
    ripemd160_update(&rip_ctx, sha256_hash, SHA256_BLOCK_SIZE);
    ripemd160_final(&rip_ctx, ripemd160_hash);

    // 3. First 4 bytes in big-endian order
    return ((uint32_t)ripemd160_hash[0] << 24) |
           ((uint32_t)ripemd160_hash[1] << 16) |
           ((uint32_t)ripemd160_hash[2] << 8)  |
           ((uint32_t)ripemd160_hash[3]);
}


// Internal key derivation logic (helper function)
static bool bip32_derive_key_internal(const bip32_extended_key_t *parent, uint32_t index, bip32_extended_key_t *child) {
    uint8_t data[37]; // Data buffer for HMAC input
    uint8_t hmac_out[SHA512_DIGEST_LENGTH]; // HMAC output
    bool hardened = (index & BIP32_HARDENED);

    // Prepare data for HMAC-SHA512
    if (hardened) {
        if (!parent->has_private_key) {
            //fprintf(stderr, "Error: Parent private key required for hardened derivation.\n");
            return false; // Cannot derive hardened without private key
        }
        data[0] = 0x00; // Prefix for private key
        memcpy(data + 1, parent->priv.key, 32); // Parent private key
    } else {
        // Check parent public key format
        if (parent->pub.key[0] != 0x02 && parent->pub.key[0] != 0x03) {
            //fprintf(stderr, "Invalid parent public key format for normal derivation.\n");
            return false;
        }
        memcpy(data, parent->pub.key, 33); // Parent public key
    }

    // Append index in big-endian format to the data buffer
    data[hardened ? 33 : 33] = (index >> 24) & 0xFF;
    data[hardened ? 34 : 34] = (index >> 16) & 0xFF;
    data[hardened ? 35 : 35] = (index >> 8) & 0xFF;
    data[hardened ? 36 : 36] = index & 0xFF;

    // --- REMOVED DEBUG PRINTS ---
    // printf("\n--- bip32_derive_key_internal ---\n");
    // printf("Parent Depth: %u, Index: 0x%08X, Hardened: %s\n", parent->depth, index, hardened ? "YES" : "NO");
    // printf("Parent Chain Code (hex): "); for (int i = 0; i < 32; ++i) printf("%02x", parent->chain_code[i]); printf("\n");
    // printf("Data Input to HMAC-SHA512 (hex): "); for (int i = 0; i < 37; ++i) printf("%02x", data[i]); printf("\n");
    // --- END REMOVED DEBUG PRINTS ---

    // Calculate HMAC-SHA512
    hmac_sha512(parent->chain_code, 32, data, 37, hmac_out);

    // --- REMOVED DEBUG PRINTS ---
    // printf("HMAC-SHA512 Output (hex): "); for (int i = 0; i < 64; ++i) printf("%02x", hmac_out[i]); printf("\n");
    // --- END REMOVED DEBUG PRINTS ---

    // Split HMAC output: Left 32 bytes (I_L), Right 32 bytes (I_R)
    const uint8_t *il = hmac_out;
    const uint8_t *ir = hmac_out + 32;

    // Calculate Child Private Key
    BigInt parent_private_key_bi, child_private_key_bi, il_bi;

    // Parent private key is required for child private key calculation
    if (!parent->has_private_key) {
         //fprintf(stderr, "Error: Cannot derive child private key without parent private key.\n");
         return false;
    }

    bytes_to_bigint(parent->priv.key, 32, &parent_private_key_bi);
    bytes_to_bigint(il, 32, &il_bi);

    // --- REMOVED DEBUG PRINTS ---
    // printf("Parent Private Key (BigInt):\n"); print_bigint(&parent_private_key_bi);
    // printf("I_L (BigInt):\n"); print_bigint(&il_bi);
    // --- END REMOVED DEBUG PRINTS ---

    // Check if parse256(I_L) >= N (invalid intermediate key)
    if (compare_bigint(&il_bi, &secp256k1_n) >= 0) {
        //fprintf(stderr, "Error: Intermediate key (I_L) is invalid (>= N).\n");
        return false; // Indicate failure, suggests retrying with next index
    }

    // child_priv_key = (parse256(I_L) + parent_priv_key) mod N
    add_mod(&child_private_key_bi, &parent_private_key_bi, &il_bi, &secp256k1_n);

    // --- REMOVED DEBUG PRINTS ---
    // printf("Child Private Key (BigInt) after add_mod:\n"); print_bigint(&child_private_key_bi);
    // --- END REMOVED DEBUG PRINTS ---

    // Check if child_priv_key is 0 (invalid derived key)
    if (is_zero(&child_private_key_bi)) {
        //fprintf(stderr, "Error: Derived child private key is invalid (== 0).\n");
        return false; // Indicate failure, suggests retrying with next index
    }

    // --- Setup Child Key Structure ---
    memset(child, 0, sizeof(bip32_extended_key_t));
    child->depth = parent->depth + 1;
    child->index = index;
    child->fingerprint = calculate_fingerprint(&parent->pub); // Use parent's public key fingerprint
    child->version = parent->version; // Inherit version (determines xprv/xpub prefix)
    child->has_private_key = true; // We successfully derived a private key

    // Copy child private key and chain code
    bigint_to_bytes(&child_private_key_bi, child->priv.key, 32);
    memcpy(child->chain_code, ir, 32); // Child chain code = I_R (right 32 bytes of HMAC)

    // --- REMOVED DEBUG PRINTS ---
    // printf("Child Private Key (bytes - first 16 hex): "); for (int i = 0; i < 16; ++i) printf("%02x", child->priv.key[i]); printf("\n");
    // printf("Child Chain Code (bytes - first 16 hex): "); for (int i = 0; i < 16; ++i) printf("%02x", child->chain_code[i]); printf("\n");
    // --- END REMOVED DEBUG PRINTS ---

    // Derive child public key from the newly derived child private key
    if (!bip32_private_to_public(&child->priv, &child->pub)) {
        //fprintf(stderr, "Error: Failed to derive public key for child.\n");
        return false;
    }

    return true; // Derivation successful
}


// Wrapper for hardened derivation
bool bip32_derive_child_hardened(const bip32_extended_key_t *parent, uint32_t index, bip32_extended_key_t *child) {
    if (!(index & BIP32_HARDENED)) {
        //fprintf(stderr, "Error: Index 0x%08X is not hardened. Use bip32_derive_child_normal or add 0x%08X.\n", index, BIP32_HARDENED);
        return false;
    }
     if (!parent->has_private_key) {
        //fprintf(stderr, "Error: Parent private key required for hardened derivation.\n");
        return false;
    }
    return bip32_derive_key_internal(parent, index, child);
}

// Wrapper for normal derivation
bool bip32_derive_child_normal(const bip32_extended_key_t *parent, uint32_t index, bip32_extended_key_t *child) {
    if (index & BIP32_HARDENED) {
        //fprintf(stderr, "Error: Index 0x%08X is hardened. Use bip32_derive_child_hardened.\n", index);
        return false;
    }
    // This implementation derives private key first, so parent private key is needed.
    // A public-key only derivation would be more complex (point addition).
    if (!parent->has_private_key) {
         //fprintf(stderr, "Error: Parent private key required for normal derivation (in this implementation).\n");
         return false;
    }
    return bip32_derive_key_internal(parent, index, child);
}


// --- Key Retrieval ---

void bip32_get_public_key(const bip32_extended_key_t *key, bip32_public_key_t *pub_key) {
     memcpy(pub_key->key, key->pub.key, 33);
}

bool bip32_get_private_key(const bip32_extended_key_t *key, bip32_private_key_t *priv_key) {
    if (!key->has_private_key) {
        return false;
    }
    memcpy(priv_key->key, key->priv.key, 32);
    return true;
}

// --- secp256k1 Interaction ---

// Derives the compressed public key from a private key.
bool bip32_private_to_public(const bip32_private_key_t *priv_key, bip32_public_key_t *pub_key) {
    BigInt private_key_bi;
    ECPointJac result_jac;
    ECPoint result_affine;

    bytes_to_bigint(priv_key->key, 32, &private_key_bi);

    // Check if private key is valid (0 < priv < N)
    if (is_zero(&private_key_bi) || compare_bigint(&private_key_bi, &secp256k1_n) >= 0) {
        //fprintf(stderr, "Error: Invalid private key for public key derivation (zero or >= N).\n");
        return false;
    }

    // --- START FIX: Define G locally in Jacobian coordinates ---
    BigInt gx, gy;
    ECPointJac G_jac; // Define G_jac locally

    // Standard secp256k1 generator point G (affine coordinates) in hex
    const char *gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    const char *gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    // Convert hex coordinates to BigInt (assuming hex_to_bigint exists or use bytes_to_bigint after hex_to_bytes)
    // If hex_to_bigint doesn't exist, you might need:
    uint8_t gx_bytes[32], gy_bytes[32];
    if (hex_to_bytes(gx_hex, gx_bytes, 32) != 32 || hex_to_bytes(gy_hex, gy_bytes, 32) != 32) {
         //fprintf(stderr, "Error converting G coordinates from hex.\n");
         return false;
    }
    bytes_to_bigint(gx_bytes, 32, &gx);
    bytes_to_bigint(gy_bytes, 32, &gy);

    // Convert G affine coordinates to Jacobian (X=gx, Y=gy, Z=1)
    copy_bigint(&G_jac.X, &gx);
    copy_bigint(&G_jac.Y, &gy);
    init_bigint(&G_jac.Z, 1); // Z = 1 for affine point
    G_jac.infinity = false;
    // --- END FIX ---

    // Use the locally defined G_jac for scalar multiplication
    // scalar_multiply_jac(ECPointJac *result, const ECPointJac *point, const BigInt *scalar, const BigInt *modulus);
    scalar_multiply_jac(&result_jac, &G_jac, &private_key_bi, &secp256k1_p); // Use local G_jac here

    // Convert result from Jacobian to Affine coordinates
    jacobian_to_affine(&result_affine, &result_jac, &secp256k1_p);

    // Convert affine point to 33-byte compressed public key format
    if (result_affine.infinity) {
        //fprintf(stderr, "Error: Result of scalar multiplication is point at infinity.\n");
        return false;
    }

    // Set prefix based on Y coordinate parity
    pub_key->key[0] = get_bit(&result_affine.y, 0) ? 0x03 : 0x02;
    // Copy X coordinate
    bigint_to_bytes(&result_affine.x, pub_key->key + 1, 32);

    return true;
}


// Derives the 65-byte uncompressed public key from a private key.
// Returns true on success, false on failure.
bool bip32_private_to_uncompressed_public(const bip32_private_key_t *priv_key, uint8_t pub_key_uncompressed[65]) {
    BigInt private_key_bi;
    ECPointJac result_jac;
    ECPoint result_affine;

    bytes_to_bigint(priv_key->key, 32, &private_key_bi);

    // Check if private key is valid (0 < priv < N)
    if (is_zero(&private_key_bi) || compare_bigint(&private_key_bi, &secp256k1_n) >= 0) {
        //fprintf(stderr, "Error: Invalid private key for public key derivation.\n");
        return false;
    }

    // Define G locally in Jacobian coordinates (as done in the fix for compressed pubkey)
    BigInt gx, gy;
    ECPointJac G_jac;
    const char *gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    const char *gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    uint8_t gx_bytes[32], gy_bytes[32];
    if (hex_to_bytes(gx_hex, gx_bytes, 32) != 32 || hex_to_bytes(gy_hex, gy_bytes, 32) != 32) {
         return false; // Error converting G hex
    }
    bytes_to_bigint(gx_bytes, 32, &gx);
    bytes_to_bigint(gy_bytes, 32, &gy);
    copy_bigint(&G_jac.X, &gx);
    copy_bigint(&G_jac.Y, &gy);
    init_bigint(&G_jac.Z, 1);
    G_jac.infinity = false;

    // Perform scalar multiplication: P = k * G mod p
    scalar_multiply_jac(&result_jac, &G_jac, &private_key_bi, &secp256k1_p);

    // Convert result from Jacobian to Affine coordinates
    jacobian_to_affine(&result_affine, &result_jac, &secp256k1_p);

    // Check if result is point at infinity
    if (result_affine.infinity) {
        //fprintf(stderr, "Error: Result of scalar multiplication is point at infinity.\n");
        return false;
    }

    // Construct the 65-byte uncompressed public key: 0x04 || X || Y
    pub_key_uncompressed[0] = 0x04; // Uncompressed prefix
    bigint_to_bytes(&result_affine.x, pub_key_uncompressed + 1, 32);  // X coordinate (32 bytes)
    bigint_to_bytes(&result_affine.y, pub_key_uncompressed + 33, 32); // Y coordinate (32 bytes)

    return true;
}

// --- Serialization ---

// Helper to write uint32_t in big-endian order
static void write_u32_be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

// Serialize an extended private key to Base58Check format
size_t serialize_xprv(const bip32_extended_key_t *key, char *out_str, size_t out_len) {
    if (!key->has_private_key) {
        //fprintf(stderr, "Error: Cannot serialize xprv, missing private key.\n");
        if (out_len > 0) out_str[0] = '\0';
        return 0;
    }
    if (out_str == NULL || out_len == 0) return 0;

    uint8_t data[BIP32_SERIALIZED_SIZE];

    write_u32_be(data, key->version);
    data[4] = key->depth;
    write_u32_be(data + 5, key->fingerprint);
    write_u32_be(data + 9, key->index);
    memcpy(data + 13, key->chain_code, 32);
    data[45] = 0x00; // Private key marker
    memcpy(data + 46, key->priv.key, 32);

    // Use the allocating base58_encode_check
    char *encoded_ptr = base58_encode_check(data, BIP32_SERIALIZED_SIZE);
    if (encoded_ptr == NULL) {
        //fprintf(stderr, "Error: Base58Check encoding failed for xprv.\n");
        out_str[0] = '\0';
        return 0;
    }

    size_t encoded_len = strlen(encoded_ptr);
    size_t copy_len = (encoded_len < out_len - 1) ? encoded_len : (out_len - 1);

    memcpy(out_str, encoded_ptr, copy_len);
    out_str[copy_len] = '\0';

    free(encoded_ptr); // Free the allocated memory

    // Return number of bytes written (including null terminator)
    return copy_len + 1;
}

// Serialize an extended public key to Base58Check format
size_t serialize_xpub(const bip32_extended_key_t *key, char *out_str, size_t out_len) {
    if (out_str == NULL || out_len == 0) return 0;

    uint8_t data[BIP32_SERIALIZED_SIZE];

    // Determine public version based on private version
    uint32_t pub_version;
    if (key->version == XPRV_MAINNET_VERSION) pub_version = XPUB_MAINNET_VERSION;
    else if (key->version == XPRV_TESTNET_VERSION) pub_version = XPUB_TESTNET_VERSION;
    else pub_version = XPUB_MAINNET_VERSION; // Default or error

    write_u32_be(data, pub_version);
    data[4] = key->depth;
    write_u32_be(data + 5, key->fingerprint);
    write_u32_be(data + 9, key->index);
    memcpy(data + 13, key->chain_code, 32);
    memcpy(data + 45, key->pub.key, 33); // Public key data

    // Use the allocating base58_encode_check
    char *encoded_ptr = base58_encode_check(data, BIP32_SERIALIZED_SIZE);
    if (encoded_ptr == NULL) {
        //fprintf(stderr, "Error: Base58Check encoding failed for xpub.\n");
        out_str[0] = '\0';
        return 0;
    }

    size_t encoded_len = strlen(encoded_ptr);
    size_t copy_len = (encoded_len < out_len - 1) ? encoded_len : (out_len - 1);

    memcpy(out_str, encoded_ptr, copy_len);
    out_str[copy_len] = '\0';

    free(encoded_ptr); // Free the allocated memory

    // Return number of bytes written (including null terminator)
    return copy_len + 1;
}
