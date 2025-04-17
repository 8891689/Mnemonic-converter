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
gcc -o m bip32.c mnemonics.c secp256k1.c base58.c ripemd160.c sha256.c sha512.c pbkdf2.c random.c bip39.c keccak256.c cashaddr.c bech32.c
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
./m
```
Or you already have a mnemonic phrase and need to view the seed private key address and other information
```
./m echo earn pink table vehicle awful true shop hazard latin useful admit
```
Configuration

You can modify the following macro definitions at the top of the mnemonics.c file to adjust the behavior:
```
#define NUM_WORDS 12: Change to 24 to generate a 24-word mnemonic phrase.

#define PASSPHRASE "": Enter your BIP39 passphrase within the quotes. Leave empty to use no passphrase.
```
You need to recompile the program after making changes.

# Example Output

```
./m
--- Wallet Details ---
No mnemonic provided via arguments. Generating a random one...
Generated Mnemonic (12 words): echo earn pink table vehicle awful true shop hazard latin useful admit
Passphrase Used: ""

BIP32 Root Seed (hex): c5868acb3649f8bdc0d511de39fd9669ff17a51d8eab5d818a30f3b165183873e6418fa76f9fdd63cd24349bb540cef46f7f356c07aa396e88cd17493bbb4584

--- Bitcoin (BTC) ---
-> BIP84 Native SegWit (P2WPKH)
   Path: m/84'/0'/0'/0/0
   Public Key (hex): 027397c2e951b1587820c9e6eecceeaa31c1d4d3e04aa7a3bb4b81fb8f46abf6ed
   Address (Bech32): bc1qglrv4e5za0uar4kdpaxqcpyjf0yq95keqxfe3k
   Private Key (WIF): L1MFzV4BjqC2sqShZfMwTKPTKCE3ASfWJTUvbUWagzeEMgkcctDq
-> BIP49 Wrapped SegWit (P2SH-P2WPKH)
   Path: m/49'/0'/0'/0/0
   Public Key (hex): 020f9a2bf484a3d8a29a05ea02bca5f8cf8b86f36fe4a1bf9b59f9a0ee0aad714c
   Address (P2SH-SegWit): 34fHczsmL2uF864rrSWDXKdCDzC56JQjVR
   Private Key (WIF): L17s6Rpmu7VMmNXbTekxrCtM7n12LeDZNmmq6GVQxiart1fr9uzG
-> BIP44 Legacy (P2PKH)
   Path: m/44'/0'/0'/0/0
   Account xpub: xpub6DJGeV8143BfMXRJdjkrGht5GzkTxL8Qov5rGh5XGXMSFVgK2J4P8tnDrJWRKiSdhQGzsimxRtSCrLzfihPUmRopJ29ECUXY9n1c6mHw2Ps
   Account xprv: xprv9zJvEyb7DfdN93LqXiDquZwLixuyYsQZShAFUJfuiBpTNhMAUkk8b6Tk11XbbK9NM71EJDQimmbG14sbUMA3qa1E6EFJXYej4i2mD7NRRyx
   Public Key (hex): 029614b2ade98fd69654fb4a983827f266d43640e82ec1951d6c3a93ef9dd9b194
   Address (Legacy): 1ATusFfGDREyWbj5J2Ti2nuYFV4hmH3t67
   Private Key (WIF): L3DfMm9mxiKNAjpg2geM18mT5aGqsTMhWxaEFXaDidQHpXGXkgBp

--- Ethereum (ETH) ---
   Path: m/44'/60'/0'/0/0
   Private Key (hex): 86f672ab1ecedd420c8e12af3e0dd130037173dbb3cc73cc5475d2b5335def20
   Public Key (uncompressed hex): 042ddcf2e1c64ced63514c72e0a91a34709820de7eea84c030669efec154eaf6c7f261077242847153fe509ec26f022109a431133594a4010a634cfddd48459c6d
   Address: 0x822bf5eb121b2d35454a43cb748a6128e61b9db3

--- Tron (TRX) ---
   Path: m/44'/195'/0'/0/0
   Private Key (hex): aede8ae7dabb418f76e2f8a5c2fb142889c8c0051efbe7534f1e8ab03f9c8b1f
   Public Key (uncompressed hex): 040384aae86a01bed9c466b983924f87ab0fec847b3c9c4efaf6f12cf2f8eeb3ba82c220d15e3f483e16227e1b8c7b5f854ae0ea8e1dc6ec50980539a0c4462395
   Address: TYeVsFupZKnKs9XCqjJrCTjhDFeQ7ySYBa

--- Dogecoin (DOGE) ---
   Path: m/44'/3'/0'/0/0
   Public Key (hex): 036d814c0f92d20117d7e2ce6f8f8c119c2dd857da2d97d8230c7e44abcd5ff303
   Address: DGxqvPTGiDFzcHjzoQhNjyrkAXvvHieery
   Private Key (WIF): QRp1bZwGdmLvAGmmF7KDdnuYNozh17ew1tFqJFjUHw2tcNtij2A5

--- Litecoin (LTC) ---
   Path: m/44'/2'/0'/0/0
   Public Key (hex): 02d4f100d0500084d9a1dbbbf28447f3f551d400777d4be3a4d007e764b252009f
   Address (P2PKH): LWuNYd19sC7ReGM176AgaTJMWAzxAnrLS4
   Private Key (WIF): T58P4SYovX3TxmHgiXr8jaFWGxBmwTQPurbRg1i2XVRwis93wUxs

--- Dash (DASH) ---
   Path: m/44'/5'/0'/0/0
   Public Key (hex): 025c129fef4a518fdcbbf356835e9f50917e1b2fa40bc54eca4b7efd742e704f67
   Address (P2PKH): Xo3Zm6zUQb3FzQsyVfwM8kFNDBqZqW9fCt
   Private Key (WIF): XHNMi4j6s7zoGGwnorgQYUgfwGS3xdjzhTAWhb9U7HHmDH9H2542

--- Zcash (ZEC) Transparent ---
   Path: m/44'/133'/0'/0/0
   Public Key (hex): 0208b91a797ae243538eb334e82bbd177cb423f5ee21e48b3f435021a8625e8491
   Address (t-addr P2PKH): t1NdciUewTiNDg9A6Xau44NJDbx4vzLzBSb
   Private Key (WIF): L2n8zhnotshTf4ZmMhEMuiVPgZJZ8Fg9DNKVc7Jy7znpC1488EPt

--- Bitcoin Cash (BCH) ---
   Path: m/44'/145'/0'/0/0
   Public Key (hex): 02f00702920463fe1b3e8852d8ac7371c7417aeaa8200e256ecee4434ab88f24c6
   Address (CashAddr): bitcoincash:qzlj9z8z4t0gfskxmzej7qfjq9waxenae5cq3zvuz4
   Private Key (WIF): L16t2RUBV1g48M7sFmnw8gVXCg3TPfnuceH79QBXp3wjH4RfkkK7

--- Bitcoin Gold (BTG) ---
   Path: m/44'/156'/0'/0/0
   Public Key (hex): 02c308ecfa035f1d9ed915ee4915bd91098ee25608ba058582745fd85ec0c9d5a6
   Address (P2PKH): Gh5kQ5PCJoDSimie2v5PRBfX1C5Aq5HWzS
   Private Key (WIF): Kz5sK16wd8hvmH81SMZTaEnvQ57orpHUp5KCFuiGvgCRFk3CFhwg

----------------------------------------------------------------------------------------------------

or

./m echo earn pink table vehicle awful true shop hazard latin useful admit
--- Wallet Details ---
Using Mnemonic from arguments: echo earn pink table vehicle awful true shop hazard latin useful admit
Passphrase Used: ""

BIP32 Root Seed (hex): c5868acb3649f8bdc0d511de39fd9669ff17a51d8eab5d818a30f3b165183873e6418fa76f9fdd63cd24349bb540cef46f7f356c07aa396e88cd17493bbb4584

--- Bitcoin (BTC) ---
-> BIP84 Native SegWit (P2WPKH)
   Path: m/84'/0'/0'/0/0
   Public Key (hex): 027397c2e951b1587820c9e6eecceeaa31c1d4d3e04aa7a3bb4b81fb8f46abf6ed
   Address (Bech32): bc1qglrv4e5za0uar4kdpaxqcpyjf0yq95keqxfe3k
   Private Key (WIF): L1MFzV4BjqC2sqShZfMwTKPTKCE3ASfWJTUvbUWagzeEMgkcctDq
-> BIP49 Wrapped SegWit (P2SH-P2WPKH)
   Path: m/49'/0'/0'/0/0
   Public Key (hex): 020f9a2bf484a3d8a29a05ea02bca5f8cf8b86f36fe4a1bf9b59f9a0ee0aad714c
   Address (P2SH-SegWit): 34fHczsmL2uF864rrSWDXKdCDzC56JQjVR
   Private Key (WIF): L17s6Rpmu7VMmNXbTekxrCtM7n12LeDZNmmq6GVQxiart1fr9uzG
-> BIP44 Legacy (P2PKH)
   Path: m/44'/0'/0'/0/0
   Account xpub: xpub6DJGeV8143BfMXRJdjkrGht5GzkTxL8Qov5rGh5XGXMSFVgK2J4P8tnDrJWRKiSdhQGzsimxRtSCrLzfihPUmRopJ29ECUXY9n1c6mHw2Ps
   Account xprv: xprv9zJvEyb7DfdN93LqXiDquZwLixuyYsQZShAFUJfuiBpTNhMAUkk8b6Tk11XbbK9NM71EJDQimmbG14sbUMA3qa1E6EFJXYej4i2mD7NRRyx
   Public Key (hex): 029614b2ade98fd69654fb4a983827f266d43640e82ec1951d6c3a93ef9dd9b194
   Address (Legacy): 1ATusFfGDREyWbj5J2Ti2nuYFV4hmH3t67
   Private Key (WIF): L3DfMm9mxiKNAjpg2geM18mT5aGqsTMhWxaEFXaDidQHpXGXkgBp

--- Ethereum (ETH) ---
   Path: m/44'/60'/0'/0/0
   Private Key (hex): 86f672ab1ecedd420c8e12af3e0dd130037173dbb3cc73cc5475d2b5335def20
   Public Key (uncompressed hex): 042ddcf2e1c64ced63514c72e0a91a34709820de7eea84c030669efec154eaf6c7f261077242847153fe509ec26f022109a431133594a4010a634cfddd48459c6d
   Address: 0x822bf5eb121b2d35454a43cb748a6128e61b9db3

--- Tron (TRX) ---
   Path: m/44'/195'/0'/0/0
   Private Key (hex): aede8ae7dabb418f76e2f8a5c2fb142889c8c0051efbe7534f1e8ab03f9c8b1f
   Public Key (uncompressed hex): 040384aae86a01bed9c466b983924f87ab0fec847b3c9c4efaf6f12cf2f8eeb3ba82c220d15e3f483e16227e1b8c7b5f854ae0ea8e1dc6ec50980539a0c4462395
   Address: TYeVsFupZKnKs9XCqjJrCTjhDFeQ7ySYBa

--- Dogecoin (DOGE) ---
   Path: m/44'/3'/0'/0/0
   Public Key (hex): 036d814c0f92d20117d7e2ce6f8f8c119c2dd857da2d97d8230c7e44abcd5ff303
   Address: DGxqvPTGiDFzcHjzoQhNjyrkAXvvHieery
   Private Key (WIF): QRp1bZwGdmLvAGmmF7KDdnuYNozh17ew1tFqJFjUHw2tcNtij2A5

--- Litecoin (LTC) ---
   Path: m/44'/2'/0'/0/0
   Public Key (hex): 02d4f100d0500084d9a1dbbbf28447f3f551d400777d4be3a4d007e764b252009f
   Address (P2PKH): LWuNYd19sC7ReGM176AgaTJMWAzxAnrLS4
   Private Key (WIF): T58P4SYovX3TxmHgiXr8jaFWGxBmwTQPurbRg1i2XVRwis93wUxs

--- Dash (DASH) ---
   Path: m/44'/5'/0'/0/0
   Public Key (hex): 025c129fef4a518fdcbbf356835e9f50917e1b2fa40bc54eca4b7efd742e704f67
   Address (P2PKH): Xo3Zm6zUQb3FzQsyVfwM8kFNDBqZqW9fCt
   Private Key (WIF): XHNMi4j6s7zoGGwnorgQYUgfwGS3xdjzhTAWhb9U7HHmDH9H2542

--- Zcash (ZEC) Transparent ---
   Path: m/44'/133'/0'/0/0
   Public Key (hex): 0208b91a797ae243538eb334e82bbd177cb423f5ee21e48b3f435021a8625e8491
   Address (t-addr P2PKH): t1NdciUewTiNDg9A6Xau44NJDbx4vzLzBSb
   Private Key (WIF): L2n8zhnotshTf4ZmMhEMuiVPgZJZ8Fg9DNKVc7Jy7znpC1488EPt

--- Bitcoin Cash (BCH) ---
   Path: m/44'/145'/0'/0/0
   Public Key (hex): 02f00702920463fe1b3e8852d8ac7371c7417aeaa8200e256ecee4434ab88f24c6
   Address (CashAddr): bitcoincash:qzlj9z8z4t0gfskxmzej7qfjq9waxenae5cq3zvuz4
   Private Key (WIF): L16t2RUBV1g48M7sFmnw8gVXCg3TPfnuceH79QBXp3wjH4RfkkK7

--- Bitcoin Gold (BTG) ---
   Path: m/44'/156'/0'/0/0
   Public Key (hex): 02c308ecfa035f1d9ed915ee4915bd91098ee25608ba058582745fd85ec0c9d5a6
   Address (P2PKH): Gh5kQ5PCJoDSimie2v5PRBfX1C5Aq5HWzS
   Private Key (WIF): Kz5sK16wd8hvmH81SMZTaEnvQ57orpHUp5KCFuiGvgCRFk3CFhwg


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
This code is only used to learn and understand the working principles of standards such as BIP32/BIP39/BIP44. The random number generator uses highly random numbers and complies with encryption industry standards.

⚠️ Reminder: Do not enter the real private key on a device connected to the network! Especially when the VPN proxy is connected, the information is intercepted and intercepted, which has a high security risk, or it is infected by viruses and trojans, etc. This project is completely open source and there is no risk of backdoors or interception of information. Please confirm that it is safe before using this program. The developer is not responsible for any financial losses caused by the use of this code.


