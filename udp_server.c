#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main()
{
	int sockfd;
	char buffer[BUFFER_SIZE];
	struct sockaddr_in servaddr, cliaddr;

	// Create UDP socket
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

	printf("UDP Server is running on port %d...\n", PORT);

	while (1) {
		int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
				 (struct sockaddr *)&cliaddr, &len);
		buffer[n] = '\0'; // Null-terminate received string
		printf("Client: %s\n", buffer);

		// Echo back the message
		sendto(sockfd, buffer, strlen(buffer), 0,
		       (const struct sockaddr *)&cliaddr, len);
	}

	close(sockfd);
	return 0;
}
