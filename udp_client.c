#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

int main()
{
	int sockfd;
	char buffer[BUFFER_SIZE];
	struct sockaddr_in servaddr;

	// Create UDP socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));

	// Set server info
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(SERVER_PORT);
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);

	printf("Enter message: ");
	fgets(buffer, BUFFER_SIZE, stdin);

	// Send message to server
	sendto(sockfd, buffer, strlen(buffer), 0,
	       (const struct sockaddr *)&servaddr, sizeof(servaddr));

	// Receive echoed message from server
	socklen_t len = sizeof(servaddr);
	int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
			 (struct sockaddr *)&servaddr, &len);
	buffer[n] = '\0';

	printf("Server: %s\n", buffer);

	close(sockfd);
	return 0;
}
