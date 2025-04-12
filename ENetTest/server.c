#include <enet/enet.h>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_secretbox.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char zero_buf[crypto_kx_SESSIONKEYBYTES] = {0};

typedef struct Keys {
	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t server_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t server_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t server_tx[crypto_kx_SESSIONKEYBYTES];
} Keys;

void display_hex(uint8_t *str, int len)
{
	for (int i = 0; i < len; i++) {
		printf("%X", str[i]);
	}
	printf("\n");
}

void display_keys(Keys *keys)
{
	printf("server_pk:\t");
	display_hex(keys->server_pk, crypto_kx_PUBLICKEYBYTES);
	printf("server_sk:\t");
	display_hex(keys->server_pk, crypto_kx_SECRETKEYBYTES);
	printf("client_pk:\t");
	display_hex(keys->client_pk, crypto_kx_PUBLICKEYBYTES);
	printf("server_rx:\t");
	display_hex(keys->server_rx, crypto_kx_SESSIONKEYBYTES);
	printf("server_tx:\t");
	display_hex(keys->server_tx, crypto_kx_SESSIONKEYBYTES);
}

void handle_connect(ENetEvent *event)
{
	printf("A new client connected from %x:%u.\n",
	       event->peer->address.host, event->peer->address.port);
}

void handle_disconnect(ENetEvent *event)
{
	printf("%s disconnected.\n", (char *)event->peer->data);
	// Reset the peer's client information.
	event->peer->data = NULL;
}

void send_pubkey(Keys *keys, ENetPeer *peer)
{
	ENetPacket *packet =
	    enet_packet_create(keys->server_pk, crypto_kx_PUBLICKEYBYTES,
			       ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
}

int decrypt_message(ENetPacket *pack, Keys *keys, void *dataout)
{
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	uint8_t encrypted[pack->dataLength - crypto_secretbox_NONCEBYTES];
	memcpy(nonce, pack->data, crypto_secretbox_NONCEBYTES);
	memcpy(encrypted, &pack->data[crypto_secretbox_NONCEBYTES],
	       pack->dataLength - crypto_secretbox_NONCEBYTES);
	return crypto_secretbox_open_easy(
	    dataout, encrypted, pack->dataLength - crypto_secretbox_NONCEBYTES,
	    nonce, keys->server_rx);
}

void handle_recieve(ENetEvent *event, Keys *keys)
{
	printf("A packet of length %lu was received from %s on channel %u.\n",
	       event->packet->dataLength, (char *)event->peer->data,
	       event->channelID);

	if (event->packet->dataLength == crypto_kx_PUBLICKEYBYTES) {
		printf("Key exchange\n");
		memcpy(keys->client_pk, event->packet->data,
		       crypto_kx_PUBLICKEYBYTES);
		send_pubkey(keys, event->peer);

		if (crypto_kx_server_session_keys(
			keys->server_rx, keys->server_tx, keys->server_pk,
			keys->server_sk, keys->client_pk) != 0) {

			printf(
			    "Key exchange failed, wrong client public key\n");
		}
		display_keys(keys);
	}
	else if (event->packet->dataLength >
		 crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {

		printf("Encrypted message\n");

		bool rx_zero = !memcmp(keys->server_rx, zero_buf,
				       crypto_kx_SESSIONKEYBYTES);
		bool tx_zero = !memcmp(keys->server_tx, zero_buf,
				       crypto_kx_SESSIONKEYBYTES);

		if (rx_zero || tx_zero) {
			printf("Keys weren't exchanged yet!\n");
			enet_packet_destroy(event->packet);
			return;
		}

		int mlen = event->packet->dataLength -
			   crypto_secretbox_NONCEBYTES -
			   crypto_secretbox_MACBYTES + 1;

		printf("Nonce:\t");
		display_hex(event->packet->data, crypto_secretbox_NONCEBYTES);
		printf("Crypt:\t");
		display_hex(&event->packet->data[crypto_secretbox_NONCEBYTES],
			    event->packet->dataLength -
				crypto_secretbox_NONCEBYTES);

		char *decrypted = calloc(mlen, sizeof(char));
		int n = crypto_secretbox_open_easy(
		    (uint8_t *)decrypted,
		    &event->packet->data[crypto_secretbox_NONCEBYTES],
		    event->packet->dataLength - crypto_secretbox_NONCEBYTES,
		    event->packet->data, keys->server_rx);
		if (decrypt_message(event->packet, keys, decrypted) != 0) {
			printf("Decryption failed\n");
		}
		else {
			printf("Decrypted message: %s\n", decrypted);
		}
		free(decrypted);
	}
	// Clean up the packet now that we're done using
	// it.
	enet_packet_destroy(event->packet);
	// char msg[] = "Recieved";
	// ENetPacket *packet =
	//     enet_packet_create(msg, sizeof(msg) + 1,
	//     ENET_PACKET_FLAG_RELIABLE);
	// enet_peer_send(event->peer, 0, packet);
}

void handle_event(ENetHost *server, Keys *keys)
{
	ENetEvent event;
	while (enet_host_service(server, &event, 1000) > 0) {
		switch (event.type) {

		case ENET_EVENT_TYPE_CONNECT:
			handle_connect(&event);
			break;

		case ENET_EVENT_TYPE_RECEIVE:
			handle_recieve(&event, keys);
			break;

		case ENET_EVENT_TYPE_DISCONNECT:
			handle_disconnect(&event);
			break;

		default:
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	if (sodium_init() < 0) {
		fprintf(stderr,
			"An error occurred while initializing sodium.\n");
		return EXIT_FAILURE;
	}
	if (enet_initialize() != 0) {
		fprintf(stderr, "An error occurred while initializing ENet.\n");
		return EXIT_FAILURE;
	}
	atexit(enet_deinitialize);

	Keys keys;
	crypto_kx_keypair(keys.server_pk, keys.server_sk);

	ENetAddress address;
	ENetHost *server;

	// Bind the server to the default localhost.
	// A specific host address can be specified by
	// enet_address_set_host (& address, "x.x.x.x");
	address.host = ENET_HOST_ANY;
	// Bind the server to port 7777.
	address.port = 7777;

	server = enet_host_create(
	    &address /* the address to bind the server host to */,
	    32 /* allow up to 32 clients and/or outgoing connections */,
	    1 /* allow up to 1 channel to be used, 0. */,
	    0 /* assume any amount of incoming bandwidth */,
	    0 /* assume any amount of outgoing bandwidth */);

	if (server == NULL) {
		printf("An error occurred while trying to create an ENet "
		       "server host.");
		return 1;
	}

	// gameloop
	while (true) {
		handle_event(server, &keys);
	}

	enet_host_destroy(server);

	return 0;
}
