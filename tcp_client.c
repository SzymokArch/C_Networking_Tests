#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 8080
#define MAX_BUF 1024

typedef struct message_t {
	char username[32];
	char text[MAX_BUF];
} message_t;

int main()
{
	message_t current;
	char ip_addr[16];

	printf("Enter your username: ");
	fgets(current.username, 32, stdin);
	current.username[strcspn(current.username, "\n")] = '\0';

	printf("Enter the address (127.0.0.1 for localhost): ");
	fgets(ip_addr, 16, stdin);
	ip_addr[strcspn(ip_addr, "\n")] = '\0';

	int sock = 0;
	struct sockaddr_in server_address;
	char message[MAX_BUF];

	// Create socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket failed");
		exit(EXIT_FAILURE);
	}

	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, ip_addr, &server_address.sin_addr) <= 0) {
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}

	// Connect to the server
	if (connect(sock, (struct sockaddr *)&server_address,
		    sizeof(server_address)) < 0) {
		perror("Connection failed");
		exit(EXIT_FAILURE);
	}

	printf("Connected to server\n");

	// Send messages to the server
	while (1) {
		printf("Enter message: ");
		fgets(current.text, MAX_BUF, stdin);
		current.text[strcspn(current.text, "\n")] = '\0';
		send(sock, &current, sizeof(current), 0);

		if (strncmp(current.text, "exit", 4) == 0) {
			printf("Exiting...\n");
			break;
		}
	}

	close(sock);
	return 0;
}
