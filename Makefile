default:
	gcc -o bip32_test bip32.c main.c secp256k1.c base58.c ripemd160.c sha256.c sha512.c pbkdf2.c random.c bip39.c keccak256.c cashaddr.c bech32.c

clean:
	rm -f bip32_test

