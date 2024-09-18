#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <list>

#define BUFFER_SIZE 512
#define TIMEOUT_SEC 0
#define TIMEOUT_USEC 500000  // 0.5 seconds in microseconds
#define RETRY_COUNT 5

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target-ip> <start-port> <end-port>" << std::endl;
        return 1;
    }

    const char* target_ip = argv[1];
    int start_port = std::atoi(argv[2]);
    int end_port = std::atoi(argv[3]);

    std::list<int> openPorts;

    for (int port = start_port; port <= end_port; ++port) {
        bool is_listening = false;

        // Create a UDP socket using SOCK_DGRAM
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            std::cerr << "socket creation failed:" << strerror(errno) << std::endl;
            return 1;
        }

        // Set a receive timeout of 0.5 seconds
        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = TIMEOUT_USEC;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            std::cerr << "failed to set socket timeout:" << strerror(errno) << std::endl;
            close(sock);
            continue;
        }

        // Define the server address
        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0) {
            std::cerr << "given IP address is weird" << std::endl;
            close(sock);
            continue;
        }

        for (int attempt = 0; attempt < RETRY_COUNT; ++attempt) {
            std::cerr << "sending packet to port " << port << ", attempt " << attempt + 1 << std::endl;
            
            const char* message = "Hello";
            if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                std::cerr << "failed to send packet to port " << port << ":" << strerror(errno) << std::endl;
                break;
            }

            char buffer[BUFFER_SIZE] = {0};
            sockaddr_in response_addr;
            socklen_t addr_len = sizeof(response_addr);

            int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, NULL, NULL);

            if (recv_len >= 0) {
                std::cerr << "port " << port << " is listening! response on attempt: " << attempt + 1 << std::endl;
                is_listening = true;
                break;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No response received within the timeout
            } else {
                std::cerr << "error on port " << port << ": " << strerror(errno) << std::endl;
                break;
            }
        }

        if (!is_listening) {
            std::cerr << "port " << port << " is closed" << std::endl;
        }

        close(sock);
    }

    return 0;
}
