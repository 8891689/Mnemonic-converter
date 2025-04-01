# Mnemonic converter
# Multi-Coin BIP39/BIP32 Wallet Generator (C Implementation)

This is a command-line tool written in C to demonstrate the process of generating wallets for multiple cryptocurrencies based on a BIP39 mnemonic phrase. It follows the BIP32 (HD Wallets), BIP44, BIP49, and BIP84 standards for deriving keys and addresses.


## Features

*   Generate a 12 or 24-word BIP39 mnemonic phrase.
*   Generate a BIP32 root seed from the mnemonic and an optional passphrase (using PBKDF2-HMAC-SHA512).
*   Derive Hierarchical Deterministic (HD) wallet keys according to standard derivation paths.
*   Support for generating addresses and private keys for the following cryptocurrencies:
    *   **Bitcoin (BTC):**
        *   Legacy (P2PKH, BIP44: `m/44'/0'/0'/0/0`)
        *   Wrapped SegWit (P2SH-P2WPKH, BIP49: `m/49'/0'/0'/0/0`)
        *   Native SegWit (P2WPKH/Bech32, BIP84: `m/84'/0'/0'/0/0`)
    *   **Ethereum (ETH):** (BIP44: `m/44'/60'/0'/0/0`)
    *   **Tron (TRX):** (BIP44: `m/44'/195'/0'/0/0`)
    *   **Dogecoin (DOGE):** (P2PKH, BIP44: `m/44'/3'/0'/0/0`)
    *   **Bitcoin Cash (BCH):** (CashAddr P2PKH, BIP44: `m/44'/145'/0'/0/0`)
*   Display the generated mnemonic, seed, public keys (hex), addresses, and private keys (WIF or hex).

## Dependencies

*   A C compiler (e.g., GCC).
*   All `.c` and `.h` files included in the project (providing implementations for BIP39, BIP32, SHA256, SHA512, PBKDF2, secp256k1, Base58, RIPEMD160, Keccak256, CashAddr, Bech32, etc.).

## Compilation

Ensure all `.c` files (`main.c`, `bip32.c`, `bip39.c`, `secp256k1.c`, `base58.c`, `ripemd160.c`, `sha256.c`, `sha512.c`, `pbkdf2.c`, `random.c`, `keccak256.c`, `cashaddr.c`, `bech32.c`) and their corresponding `.h` files are in the same directory. Then, compile using GCC:

```bash
gcc -o bip32_test bip32.c main.c secp256k1.c base58.c ripemd160.c sha256.c sha512.c pbkdf2.c random.c bip39.c keccak256.c cashaddr.c bech32.c
```
or
```
make
```
Clean and recompile
```
make clean
```
Usage
Run the compiled executable directly:
```
./bip32_test
```

The program will output the generated mnemonic phrase, root seed, and detailed information (public key, address, private key) for each coin at the default derivation path.

Configuration

You can modify the following macro definitions at the top of the main.c file to adjust the behavior:
```
#define NUM_WORDS 12: Change to 24 to generate a 24-word mnemonic phrase.

#define PASSPHRASE "": Enter your BIP39 passphrase within the quotes. Leave empty to use no passphrase.
```
You need to recompile the program after making changes.

# Example Output

```
./bip32_test
--- Wallet Details ---
Generated Mnemonic (12 words): control vessel radio make clinic spatial slogan include disease luggage rate clump
Passphrase Used: ""

BIP32 Root Seed (hex): 06446bc5e37843e194074eb3b28d18926ec5df427e2b8c56fa2e75c0b438425daff682d48d1b94764e1b262fc62af626eac8ad34550c0717f2ca0f1171784f5b

--- Bitcoin (BTC) ---
-> BIP84 Native SegWit (P2WPKH)
   Path: m/84'/0'/0'/0/0
   Public Key (hex): 0341f837650ea37caff3b74b044a350abd1de3b9e74c2d51feabfaf82b55ec0eab
   Address (Bech32): bc1q4qd4l4jhmq42c3sqdt42lml2fee3dszazw88rk
   Private Key (WIF): L5FasiwESjWjWftPW35G4UBHUM2uM4oPopifyGHRNVfNnnQ7KpFp
-> BIP49 Wrapped SegWit (P2SH-P2WPKH)
   Path: m/49'/0'/0'/0/0
   Public Key (hex): 0390733e756c2619198cd355a87596fd49925cbb14ddd8e1593ac728183084acad
   Address (P2SH-SegWit): 3DJCCamWQkh7AP9cDBhEq4iXbVQZGN9zhC
   Private Key (WIF): L5Ep9KUW4WhhbUtSYJa3bFE9FXiYsVxSoF9HX2kAAi5mFkEoxbg5
-> BIP44 Legacy (P2PKH)
   Path: m/44'/0'/0'/0/0
   Account xpub: xpub6CnfqzcthpdddSHuuBcha5ar3S8yrHJzoz9WwnfJx5EzrL5gzo9PNjSLqKPkBmqMFQEpEq1TcLUbhqrMWLmt273CEjokvh6FB7sHgoZP2zU
   Account xprv: xprv9yoKSV5zsT5LQxDSoA5hCwe7VQJVSpb9SmDv9QFhPji1yXkYTFq8pw7rz13jYC7KCcq5hGghviho5z86HhZY4uvfPJVFBKHi7FhSRLMhdah
   Public Key (hex): 028c928b3b8b6a1d1b25be2efe710afc239056546d5064440fcb4754528d33783c
   Address (Legacy): 14h63PEQ5LWS3fX7QdMSZ6a4sdcH2pBofn
   Private Key (WIF): Kz2C4GVDijXBR6ukuhd4qdSyLywyu41WyuDnD9Trkdy3o4VRVwhF

--- Ethereum (ETH) ---
   Path: m/44'/60'/0'/0/0
   Private Key (hex): 1d43369e0c0fb6faa997a72d8634df7c07d849d071bf45309221ed61cee0a0ba
   Public Key (uncompressed hex): 046cd0859bc2a3fcce661ef0b71d546f21d7175692c907884a9fb81990eb01b8f24b1e614aa9077ac8ed68048bbd2284f6a2a49a694fb8b0a2f509478299a00963
   Address: 0xefa0b814fc95b45f81a95d33b042bec6becd91a6

--- Tron (TRX) ---
   Path: m/44'/195'/0'/0/0
   Private Key (hex): 9b60d4f6ab911fee716dfbe6fc84da082d6604df195e86e4b1aad108078f968d
   Public Key (uncompressed hex): 041530855bb24346d924f13c629c5acb18221536efdfe25f38fae0f13b7bfeeb5268dae350f673c6237a2601bd1a2356910536d0ac13f8bb4ce7bc2a5c9efead27
   Address: TQtNeyDMEKa1MdJGrYqoBxceXDijege9eS

--- Dogecoin (DOGE) ---
   Path: m/44'/3'/0'/0/0
   Public Key (hex): 026e0450e1b5889662e4d1c6d088f64a55ba280c7898ad7b90ade2cbb5d897079d
   Address: DGrj7JxZUVyY82YVRQw62TugNUXyQWvZcC
   Private Key (raw hex): 7f5a38e2f774425a7c58aa3a924dacc4e2903b33ff3a40763043e59c0eebdafd

--- Bitcoin Cash (BCH) ---
   Path: m/44'/145'/0'/0/0
   Public Key (hex): 02d286cdcc484897d3a7b57ba9a846c3a131303673b978d793c4eacde0cdcfead4
   Address (CashAddr): bitcoincash:qpha9ndx6clh2qur866632jgfu9ca9767sqqjyh5ax
   Private Key (WIF): L5NZPBUuJMtp7Lk7mNUEsWtru9Dw95KuE6qYMMqC4DPxhMY26yS3

```

# ⚙️ Dependencies
 No dependencies are required. This program is all hand-crafted by me, using AI to assist in creation.

 Thanks: gemini, ChatGPT, deepseek
# Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# 📜 Disclaimer
⚠️ Reminder: Do not input real private keys on connected devices!
To reiterate, this code is intended solely for learning and understanding how standards like BIP32/BIP39/BIP44 work. The security of the random number generator has not been rigorously audited. Do not use keys generated by this program to store actual, valuable cryptocurrency assets. The developers are not responsible for any loss of funds resulting from the use of this code.


