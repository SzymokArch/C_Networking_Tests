#include <sodium.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define KEY_SIZE crypto_secretbox_KEYBYTES
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define MAC_SIZE crypto_secretbox_MACBYTES

void display_hex(uint8_t *str, int len)
{
	for (int i = 0; i < len; i++) {
		printf("0x%X ", str[i]);
	}
	printf("\n");
}

int main(void)
{
	if (sodium_init() < 0) {
		perror("Sodium couldn't be initialized");
		return 1;
	}
	char message[] = "Hello World!";
	int mlen = strlen(message);

	uint8_t key[KEY_SIZE];
	crypto_secretbox_keygen(key);
	printf("Key:\t\t\t");
	display_hex((uint8_t *)key, KEY_SIZE);

	uint8_t nonce[NONCE_SIZE];
	randombytes_buf(nonce, NONCE_SIZE);
	printf("Nonce:\t\t\t");
	display_hex((uint8_t *)nonce, NONCE_SIZE);

	uint8_t ciphertext[MAC_SIZE + mlen];
	crypto_secretbox_easy(ciphertext, (uint8_t *)message, mlen, nonce, key);
	printf("Encrypted:\t\t");
	display_hex(ciphertext, MAC_SIZE + mlen);

	char decrypted[mlen + 1];
	memset(decrypted, 0, mlen + 1);
	int n = crypto_secretbox_open_easy((uint8_t *)decrypted, ciphertext,
					   MAC_SIZE + mlen, nonce, key);

	printf("Original message:\t");
	display_hex((uint8_t *)message, mlen + 1);
	printf("Decrypted:\t\t");
	display_hex((uint8_t *)decrypted, mlen + 1);

	return 0;
}
