#include <enet/enet.h>
#include <sodium.h>
#include <sodium/crypto_secretbox.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum channels { KEY_CHAN, UPDATE_CHAN, CHAT_CHAN, PING_CHAN };

static const int CHAN_COUNT = 4;

typedef struct Keys {
	uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
	uint8_t client_sk[crypto_kx_SECRETKEYBYTES];

	uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];

	uint8_t client_rx[crypto_kx_SESSIONKEYBYTES];
	uint8_t client_tx[crypto_kx_SESSIONKEYBYTES];
} Keys;

ENetPeer *handle_connect(ENetHost *client, ENetAddress *address)
{
	ENetPeer *peer;
	peer = enet_host_connect(client, address, CHAN_COUNT, 0);
	if (peer == NULL) {
		perror("No available peers for initiating an ENet connection!");
		exit(EXIT_FAILURE);
	}
	ENetEvent event;
	if (enet_host_service(client, &event, 5000) > 0 &&
	    event.type == ENET_EVENT_TYPE_CONNECT) {
		printf("Connection to 127.0.0.1:7777 succeeded.\n");
	}
	else {
		enet_peer_reset(peer);
		printf("Connection to 127.0.0.1:7777 failed.");
		exit(EXIT_SUCCESS);
	}
	return peer;
}

void handle_disconnect(ENetHost *client)
{
	ENetEvent event;
	while (enet_host_service(client, &event, 3000) > 0) {
		switch (event.type) {

		case ENET_EVENT_TYPE_RECEIVE:
			enet_packet_destroy(event.packet);
			break;
		case ENET_EVENT_TYPE_DISCONNECT:
			printf("Disconnection succeeded.");
			break;
		default:
			break;
		}
	}
}

void send_pubkey(Keys *keys, ENetPeer *peer)
{
	ENetPacket *packet =
	    enet_packet_create(keys->client_pk, crypto_kx_PUBLICKEYBYTES,
			       ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, KEY_CHAN, packet);
}

void send_ping(Keys *keys, ENetPeer *peer)
{
	char ping[] = "ping";
	uint8_t encrypted[1024];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	int encrypted_size = sizeof(ping) + crypto_secretbox_NONCEBYTES +
			     crypto_secretbox_MACBYTES;
	crypto_secretbox_easy(&encrypted[crypto_secretbox_NONCEBYTES],
			      (uint8_t *)ping, sizeof(ping), encrypted,
			      keys->client_tx);

	ENetPacket *packet = enet_packet_create(encrypted, encrypted_size,
						ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, PING_CHAN, packet);
}

void handle_receive(ENetEvent *event, Keys *keys)
{
	// Packet not on the key exchange channel
	if (event->channelID != KEY_CHAN) {
		// TODO implement logic for different channels
		return;
	}

	// Key exchange logic
	if (event->packet->dataLength != crypto_kx_PUBLICKEYBYTES) {
		perror("Suspicious server public key (wrong size), bail out");
		exit(EXIT_FAILURE);
	}

	printf("Key exchange\n");
	memcpy(keys->server_pk, event->packet->data, crypto_kx_PUBLICKEYBYTES);

	if (crypto_kx_client_session_keys(keys->client_rx, keys->client_tx,
					  keys->client_pk, keys->client_sk,
					  keys->server_pk) != 0) {
		perror("Suspicious server public key (couldn't establish "
		       "session keys), bail out");
		exit(EXIT_FAILURE);
	}
}

void handle_event(ENetHost *client, Keys *keys)
{
	ENetEvent event;
	while (enet_host_service(client, &event, 1000) > 0) {
		switch (event.type) {
		case ENET_EVENT_TYPE_RECEIVE:
			handle_receive(&event, keys);
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
		fprintf(stderr, "An error occurred while initializing ENet!\n");
		return EXIT_FAILURE;
	}
	atexit(enet_deinitialize);

	Keys keys = {0};
	crypto_kx_keypair(keys.client_pk, keys.client_sk);

	ENetHost *client;
	client = enet_host_create(NULL, 1, CHAN_COUNT, 0, 0);

	if (client == NULL) {
		fprintf(stderr, "An error occurred while trying to create an "
				"ENet client host!\n");
		return EXIT_FAILURE;
	}

	ENetAddress address;
	enet_address_set_host(&address, "127.0.0.1");
	address.port = 7777;

	ENetPeer *peer = handle_connect(client, &address);
	send_pubkey(&keys, peer);

	// [...Game Loop...]
	char msg[1024] = {0};
	while (strcmp(msg, "exit") != 0) {
		handle_event(client, &keys);
		send_ping(&keys, peer);
	}
	enet_peer_disconnect(peer, 0);

	handle_disconnect(client);

	return EXIT_SUCCESS;
}
