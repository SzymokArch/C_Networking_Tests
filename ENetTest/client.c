#include <enet/enet.h>
#include <sodium.h>
#include <sodium/crypto_secretbox.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct Keys {
	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t client_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t client_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t client_tx[crypto_kx_SESSIONKEYBYTES];
} Keys;

void display_hex(uint8_t *str, int len)
{
	for (int i = 0; i < len; i++) {
		printf("%X", str[i]);
	}
	printf("\n");
}

void display_keys(uint8_t client_pk[crypto_kx_PUBLICKEYBYTES],
		  uint8_t client_sk[crypto_kx_SECRETKEYBYTES],
		  uint8_t server_pk[crypto_kx_PUBLICKEYBYTES],
		  uint8_t client_rx[crypto_kx_SESSIONKEYBYTES],
		  uint8_t client_tx[crypto_kx_SESSIONKEYBYTES])
{
	printf("client_pk:\t");
	display_hex(client_pk, crypto_kx_PUBLICKEYBYTES);
	printf("client_sk:\t");
	display_hex(client_pk, crypto_kx_SECRETKEYBYTES);
	printf("server_pk:\t");
	display_hex(server_pk, crypto_kx_PUBLICKEYBYTES);
	printf("client_rx:\t");
	display_hex(client_rx, crypto_kx_SESSIONKEYBYTES);
	printf("client_tx:\t");
	display_hex(client_tx, crypto_kx_SESSIONKEYBYTES);
}

int main(int argc, char *argv[])
{
	if (enet_initialize() != 0) {
		fprintf(stderr, "An error occurred while initializing ENet!\n");
		return EXIT_FAILURE;
	}
	atexit(enet_deinitialize);

	ENetHost *client;
	client = enet_host_create(NULL, 1, 1, 0, 0);

	if (client == NULL) {
		fprintf(stderr, "An error occurred while trying to create an "
				"ENet client host!\n");
		return EXIT_FAILURE;
	}

	ENetAddress address;
	ENetEvent event;
	ENetPeer *peer;

	enet_address_set_host(&address, "127.0.0.1");
	address.port = 7777;

	peer = enet_host_connect(client, &address, 1, 0);
	if (peer == NULL) {
		fprintf(
		    stderr,
		    "No available peers for initiating an ENet connection!\n");
		return EXIT_FAILURE;
	}
	if (enet_host_service(client, &event, 5000) > 0 &&
	    event.type == ENET_EVENT_TYPE_CONNECT) {
		puts("Connection to 127.0.0.1:7777 succeeded.");
	}
	else {
		enet_peer_reset(peer);
		puts("Connection to 127.0.0.1:7777 failed.");
		return EXIT_SUCCESS;
	}

	// Set up key pairs for encryption
	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t client_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t client_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t client_tx[crypto_kx_SESSIONKEYBYTES];

	crypto_kx_keypair(client_pk, client_sk);

	ENetPacket *packet = enet_packet_create(
	    client_pk, crypto_kx_PUBLICKEYBYTES, ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);

	// [...Game Loop...]
	char msg[1024];
	while (strcmp(msg, "exit") != 0) {
		while (enet_host_service(client, &event, 1000) > 0) {
			switch (event.type) {
			case ENET_EVENT_TYPE_RECEIVE:
				if (event.packet->dataLength ==
				    crypto_kx_PUBLICKEYBYTES) {
					printf("Key exchange\n");
					memcpy(server_pk, event.packet->data,
					       crypto_kx_PUBLICKEYBYTES);
					if (crypto_kx_client_session_keys(
						client_rx, client_tx, client_pk,
						client_sk, server_pk) != 0) {
						perror("Suspicious server "
						       "public key, bail out");
						exit(EXIT_FAILURE);
					}
					display_keys(client_pk, client_sk,
						     server_pk, client_rx,
						     client_tx);
				}
				break;
			default:
				break;
			}
		}
		fgets(msg, 1024, stdin);
		msg[strcspn(msg, "\n")] = '\0';

		uint8_t encrypted[1024];
		randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
		int encrypted_size = strlen(msg) + crypto_secretbox_NONCEBYTES +
				     crypto_secretbox_MACBYTES;
		crypto_secretbox_easy(&encrypted[crypto_secretbox_NONCEBYTES],
				      (uint8_t *)msg, strlen(msg), encrypted,
				      client_tx);

		printf("Nonce:\t");
		display_hex(encrypted, crypto_secretbox_NONCEBYTES);
		printf("Crypt:\t");
		display_hex(&encrypted[crypto_secretbox_NONCEBYTES],
			    encrypted_size - crypto_secretbox_NONCEBYTES);

		ENetPacket *packet = enet_packet_create(
		    encrypted, encrypted_size, ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
	}
	enet_peer_disconnect(peer, 0);

	while (enet_host_service(client, &event, 3000) > 0) {
		switch (event.type) {
		case ENET_EVENT_TYPE_RECEIVE:
			enet_packet_destroy(event.packet);
			break;
		case ENET_EVENT_TYPE_DISCONNECT:
			puts("Disconnection succeeded.");
			break;
		default:
			break;
		}
	}

	return EXIT_SUCCESS;
}
