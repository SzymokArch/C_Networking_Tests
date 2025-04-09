#include <arpa/inet.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 8080
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

	char buffer[BUFFER_SIZE];

	// Create UDP socket
	int sockfd;
	struct sockaddr_in servaddr, cliaddr;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	// Zero out the server address structure
	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	// Set server info
	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

	// Bind the socket with the server address
	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
	    0) {
		perror("Bind failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	socklen_t len = sizeof(cliaddr);

	// Set up key pairs for encryption
	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t server_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t server_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t server_tx[crypto_kx_SESSIONKEYBYTES];

	// Generate the client's key pair
	crypto_kx_keypair(server_pk, server_sk);

	printf("UDP Server is running on port %d...\n", PORT);

	// Recieve client's public key
	recvfrom(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES, 0,
		 (struct sockaddr *)&cliaddr, &len);
	// Send server's public key
	sendto(sockfd, server_pk, crypto_kx_PUBLICKEYBYTES, 0,
	       (const struct sockaddr *)&cliaddr, len);

	// Compute two shared keys using the client's public key and the
	// server's secret key. server_rx will be used by the server to receive
	// data from the client, server_tx will be used by the server to send
	// data to the client.
	if (crypto_kx_server_session_keys(server_rx, server_tx, server_pk,
					  server_sk, client_pk) != 0) {
		perror("client public key, bail out");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	packet_t pack = {0};
	// Recieve the packet sent by the client
	recvfrom(sockfd, &pack, sizeof(packet_t), 0,
		 (struct sockaddr *)&cliaddr, &len);
	char decrypted[BUFFER_SIZE];
	memset(decrypted, 0, BUFFER_SIZE);

	// Decrypt the message
	int n = crypto_secretbox_open_easy(
	    (uint8_t *)decrypted, pack.encrypted,
	    BUFFER_SIZE + crypto_secretbox_MACBYTES, pack.nonce, server_rx);

	close(sockfd);

	printf("%s\n", decrypted);

	return 0;
}
