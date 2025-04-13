#include <enet/enet.h>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_secretbox.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum channels { KEY_CHAN, UPDATE_CHAN, CHAT_CHAN, PING_CHAN };

static const int CHAN_COUNT = 4;

static const char zero_buf[crypto_kx_SESSIONKEYBYTES] = {0};

typedef struct Keys {
	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t server_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t server_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t server_tx[crypto_kx_SESSIONKEYBYTES];
} Keys;

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
	enet_peer_send(peer, KEY_CHAN, packet);
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

void handle_key_channel(ENetEvent *event, Keys *keys)
{
	printf("Key exchange\n");
	if (event->packet->dataLength != crypto_kx_PUBLICKEYBYTES) {
		perror("Suspicious client public key (wrong size), bail out");
		exit(EXIT_FAILURE);
	}
	memcpy(keys->client_pk, event->packet->data, crypto_kx_PUBLICKEYBYTES);
	send_pubkey(keys, event->peer);

	if (crypto_kx_server_session_keys(keys->server_rx, keys->server_tx,
					  keys->server_pk, keys->server_sk,
					  keys->client_pk) != 0) {

		printf("Key exchange failed, wrong server public key\n");
	}
}

void handle_chat_channel(ENetEvent *event, Keys *keys)
{
	bool rx_zero =
	    !memcmp(keys->server_rx, zero_buf, crypto_kx_SESSIONKEYBYTES);
	bool tx_zero =
	    !memcmp(keys->server_tx, zero_buf, crypto_kx_SESSIONKEYBYTES);

	if (rx_zero || tx_zero) {
		printf("Keys weren't exchanged yet!\n");
		return;
	}

	int mlen = event->packet->dataLength - crypto_secretbox_NONCEBYTES -
		   crypto_secretbox_MACBYTES + 1;

	if (event->channelID == CHAT_CHAN || event->channelID == PING_CHAN) {

		char *decrypted = calloc(mlen, sizeof(char));
		if (decrypt_message(event->packet, keys, decrypted) != 0) {
			printf("Decryption failed\n");
		}
		else {
			printf("Received message: %s\n", decrypted);
		}
		free(decrypted);
	}
}

void handle_receive(ENetEvent *event, Keys *keys)
{
	switch (event->channelID) {

	case KEY_CHAN:
		handle_key_channel(event, keys);
		break;
	case UPDATE_CHAN:
		break;
	case CHAT_CHAN:
		handle_chat_channel(event, keys);
		break;
	case PING_CHAN:
		break;
	}
	// Clean up the packet now that we're done using
	// it.
	enet_packet_destroy(event->packet);
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
			handle_receive(&event, keys);
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

	Keys keys = {0};
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
	    CHAN_COUNT /* allow up to 4 channels to be used. */,
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
