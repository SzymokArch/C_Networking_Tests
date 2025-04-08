#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 8080
#define MAX_BUF 1024

typedef struct message_t {
	char username[32];
	char text[MAX_BUF];
} message_t;

void handle_client(int new_socket)
{
	message_t msg;
	// char buffer[MAX_BUF] = {0};

	// Read data from the client and print
	while (1) {
		memset(&msg, 0, sizeof(msg));
		int valread = read(new_socket, &msg, sizeof(msg));
		if (valread <= 0) {
			printf("Client disconnected or error occurred\n");
			break;
		}
		printf("%s: %s\n", msg.username, msg.text);
	}

	close(new_socket);
}

int main()
{
	int server_fd, new_socket;
	struct sockaddr_in address;
	int addr_len = sizeof(address);

	// Create socket
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("Socket failed");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

	// Bind the socket to the address and port
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

	// Listen for incoming connections
	if (listen(server_fd, 3) < 0) {
		perror("Listen failed");
		exit(EXIT_FAILURE);
	}

	printf("Waiting for connections...\n");

	// Accept and handle multiple clients
	while (1) {
		new_socket = accept(server_fd, (struct sockaddr *)&address,
				    (socklen_t *)&addr_len);
		if (new_socket < 0) {
			perror("Accept failed");
			continue;
		}

		printf("Connected to client\n");

		// Create a new process for each client
		pid_t pid = fork();
		if (pid == 0) {		  // Child process
			close(server_fd); // Close the server socket in the
					  // child process
			handle_client(
			    new_socket); // Handle client communication
			exit(0); // Exit the child process after handling the
				 // client
		}
		else if (pid > 0) {
			close(new_socket); // Close the new socket in the parent
					   // process
		}
		else {
			perror("Fork failed");
			exit(EXIT_FAILURE);
		}
	}

	close(server_fd);
	return 0;
}
