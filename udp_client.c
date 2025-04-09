#include <arpa/inet.h>
#include <sodium.h>
#include <sodium/crypto_kx.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

typedef struct packet {
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	uint8_t encrypted[BUFFER_SIZE + crypto_secretbox_MACBYTES];
} packet_t;

void display_hex(uint8_t *str, int len)
{
	for (int i = 0; i < len; i++) {
		printf("%X", str[i]);
	}
	printf("\n");
}

int main()
{
	// Initialize sodium for encryption
	if (sodium_init() < 0) {
		perror("Sodium initialization failed");
		exit(EXIT_FAILURE);
	}

	// Create UDP socket
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	// Set server info
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(SERVER_PORT);
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);

	// Set up key pairs for encryption
	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t client_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t client_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t client_tx[crypto_kx_SESSIONKEYBYTES];

	// Generate the client's key pair
	crypto_kx_keypair(client_pk, client_sk);

	// Send the client's public key to server
	sendto(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES, 0,
	       (const struct sockaddr *)&servaddr, sizeof(servaddr));

	// Recieve server's public key
	socklen_t len = sizeof(servaddr);
	recvfrom(sockfd, server_pk, crypto_kx_PUBLICKEYBYTES, 0,
		 (struct sockaddr *)&servaddr, &len);

	// Compute two shared keys using the server's public key and the
	// client's secret key. client_rx will be used by the client to receive
	// data from the server, client_tx will be used by the client to send
	// data to the server.

	if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk,
					  client_sk, server_pk) != 0) {
		perror("Suspicious server public key, bail out");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	// Initialize a message
	char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE);
	strcat(buffer, "Secret message from client");

	// Encrypt a message inside the packet structure
	packet_t pack = {0};
	randombytes_buf(pack.nonce, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(pack.encrypted, (uint8_t *)buffer, BUFFER_SIZE,
			      pack.nonce, client_tx);

	// Send the packet
	sendto(sockfd, &pack, sizeof(packet_t), 0,
	       (const struct sockaddr *)&servaddr, sizeof(servaddr));

	close(sockfd);

	return 0;
}
