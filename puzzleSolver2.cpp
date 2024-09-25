#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h> // Provides declarations for tcp header
#include <netinet/ip.h>  // Provides declarations for ip header
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <list>
#include <iomanip> // for std::hex and std::setw

#define BUFFER_SIZE 1024
#define RETRY_COUNT 3
#define GROUP_ID 64
#define SECRET_PORT 4065

#define TIMEOUT_SEC 0
#define TIMEOUT_USEC 50000 // 0.5 seconds in microseconds

// // IP header from slides
// struct ip
// {
// #if BYTE_ORDER == LITTLE_ENDIAN
//     u_char ip_hl : 4, /* header length */
//         ip_v : 4;     /* version */
// #endif
// #if BYTE_ORDER == BIG_ENDIAN
//     u_char ip_v : 4, /* version */
//         ip_hl : 4;   /* header length */
// #endif
//     u_char ip_tos;                 /* type of service */
//     u_short ip_len;                /* total length */
//     u_short ip_id;                 /* identification */
//     u_short ip_off;                /* fragment offset field */
// #define IP_RF 0x8000               /* reserved fragment flag */
// #define IP_DF 0x4000               /* dont fragment flag */
// #define IP_MF 0x2000               /* more fragments flag */
// #define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
//     u_char ip_ttl;                 /* time to live */
//     u_char ip_p;                   /* protocol */
//     u_short ip_sum;                /* checksum */
//     struct in_addr ip_src, ip_dst; /* source and dest address */
// };

// struct udphdr
// {
//     unsigned short source;
//     unsigned short dest;
//     unsigned short len;
//     unsigned short check;
// };

/*
raw challenge: ???M
Challenge in host byte order: 3198809165
Signed challenge: 0xe20a4420
Server response: Well done group 64. You have earned the right to know the port: 4065!
*/

// method for getting the signature
uint32_t getSignature()
{
    uint32_t secret = 0x9eedfeaf;
    uint32_t challenge = 0xbea9f44d;

    // xor operation
    uint32_t signed_challenge = secret ^ challenge;

    signed_challenge = htonl(signed_challenge);

    std::cout << "Signed challenge: 0x" << std::hex << signed_challenge << std::endl;

    return signed_challenge;
}

// method for the S.E.C.R.E.T port, with message of five steps
void secretPort(int sock, sockaddr_in server_addr, int port)
{
    unsigned char group_id = GROUP_ID; // Store group ID as a single unsigned byte

    // Send the group ID as a single byte
    if (sendto(sock, &group_id, sizeof(group_id), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&response_addr, &addr_len);
    std::cerr << recv_len << std::endl;
    if (recv_len >= 0)
    {

        buffer[recv_len] = '\0';
        std::cerr << "raw challenge: " << buffer << std::endl;

        // the challeng is 4-byte
        if (recv_len == 4)
        {

            uint32_t challenge_network;
            std::memcpy(&challenge_network, buffer, sizeof(challenge_network));

            // convert from network byte order to host byte order
            uint32_t challenge_host = ntohl(challenge_network);

            std::cerr << "Challenge in host byte order: " << challenge_host << std::endl;
        }
        else
        {
            std::cerr << "Received data is too small to be a 4-byte challenge" << std::endl;
        }
    }
    else
    {
        std::cerr << "Error receiving response from port " << port << ": " << strerror(errno) << std::endl;
    }

    // sending signature
    uint32_t sign = getSignature();
    uint8_t message[5];
    message[0] = GROUP_ID;
    memcpy(&message[1], &sign, sizeof(sign));

    if (sendto(sock, message, sizeof(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    memset(buffer, 0, sizeof(buffer));

    recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, NULL, NULL);
    if (recv_len >= 0)
    {
        buffer[recv_len] = '\0';
        std::cerr << "Server response: " << buffer << std::endl;
    }
    else
    {
        std::cerr << "Failed to receive response: " << strerror(errno) << std::endl;
    }
}

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t zeroes;
    u_int8_t protocol;
    u_int16_t udp_length;
};

/*
Generic checksum method
*/
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

int sendSignatureEvilC(int port)
{
    std::cerr << "Send Signature Evil C was started and will be sent to " << port << std::endl;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0)
    {
        perror("Socket creation error");
        return 1;
    }

    uint32_t message = getSignature();
    message = htonl(187420);
    std::cerr << "THE message " << message << std::endl;

    // Buffer to hold the packet
    char packet[64];
    memset(packet, 0, 4096);

    memcpy(&packet[2048], &message, sizeof(message));

    // IP header
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    // struct payload *
    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 4);
    std::cerr << "tot len of iphdr: " << sizeof(struct iphdr) + sizeof(struct udphdr) << std::endl;

    iph->id = htons(18718); // ID of this packet

    iph->frag_off = htons(0x8000); // 0x8000 is 1000000000000000 in binary (sets the first bit)
    iph->ttl = 60;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0; // Set to 0 before calculating checksum
    // iph->saddr = inet_pton("130.208.24.80");   // Source IP
    // Convert string IP address to uint32_t
    const char *src_ip = "130.208.24.80"; // Source IP address in string form
    if (inet_pton(AF_INET, src_ip, &(iph->saddr)) != 1)
    {
        std::cerr << "Invalid IP address: " << src_ip << std::endl;
        return -1;
    }
    else
    {
        std::cerr << "Source address successfully converted to uint32_t and set in IP header." << std::endl;
    }

    iph->daddr = inet_addr("130.208.246.249"); // Destination IP

    // UDP Header
    udph->uh_sport = htons(58709); // Source port
    udph->uh_dport = htons(port);  // Destination port
    udph->uh_ulen = htons(12);
    udph->uh_sum = 0;

    // IP checksum
    // iph->check = checksum((unsigned short *)packet, iph->tot_len);

    // Now the pseudo-header for checksum
    psh.source_address = inet_addr("130.208.24.80");
    psh.dest_address = inet_addr("130.208.246.249");
    psh.zeroes = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(12);
    memcpy(&packet[28], &message, sizeof(message));

    std::cerr << "THE length of pseudo header" << sizeof(struct udphdr) << std::endl;

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
    char *pseudogram = (char *)malloc(psize);

    memcpy(pseudogram, (char *)&psh, 8);
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));

    udph->uh_sum = checksum((unsigned short *)pseudogram, psize);

    // Destination address
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr("130.208.246.249");

    // Print the packet in hex format
    std::cerr << "Packet contents (in hex): " << std::endl;
    for (int i = 0; i < 64; ++i)
    { // Adjust the loop limit to the actual size of your packet
        std::cerr << std::hex << std::setw(2) << std::setfill('0')
                  << (0xff & static_cast<unsigned int>(packet[i])) << " ";
        if ((i + 1) % 16 == 0)
        {
            std::cerr << std::endl; // New line every 16 bytes for readability
        }
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        std::cerr << "failed to set socket timeout: " << strerror(errno) << std::endl;
        close(sock);
    }

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }
    // Send the packet
    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        std::cerr << "sending failed" << packet << std::endl;
    }
    else
    {
        printf("Packet Sent\n");
        std::cerr << packet << std::endl;
    }

    // Print the packet in hex format
    std::cerr << "Packet contents (in hex): " << std::endl;
    for (int i = 0; i < 64; ++i)
    { // Adjust the loop limit to the actual size of your packet
        std::cerr << std::hex << std::setw(2) << std::setfill('0')
                  << (0xff & static_cast<unsigned int>(packet[i])) << " ";
        if ((i + 1) % 16 == 0)
        {
            std::cerr << std::endl; // New line every 16 bytes for readability
        }
    }

    // Set a receive timeout of 0.5 seconds
    socklen_t sin_len = sizeof(sin);
    int recv_len = recvfrom(sock, packet, BUFFER_SIZE - 1, 0, (struct sockaddr *)&sin, &sin_len);
    if (recv_len >= 0)
    {
        packet[recv_len] = '\0';
        std::cerr << "response: " << packet << std::endl;
    }
    else
    {
        std::cerr << "No response " << packet << std::endl;
    }

    close(sock);
    return 0;
}

// sending a signature to the port with message:
// "Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order)."
void sendSignatureEvil(int sock, sockaddr_in server_addr, int port)
{

    uint32_t message = getSignature();

    uint32_t evil_bit = 1; // Set the 31st bit to 1 (evil bit).

    message |= evil_bit;

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw == -1)
    {
        // socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
    }
    server_addr.sin_port = htons(port);

    // char buffer[1024];
    // struct ip *iphdf = (struct ip *)buffer;
    // struct udp *udph = (typecast)buffer + sideof(struct ip)

    int one = 1;
    const int *val = &one;
    if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
        return;
    }

    if (sendto(sock, &message, sizeof(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    // char buffer[BUFFER_SIZE] = {0};
    sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    char buffer[1024] = {0};
    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&response_addr, &addr_len);
    if (recv_len >= 0)
    {
        buffer[recv_len] = '\0';
        std::cerr << "The response: " << buffer << std::endl;
    }
}

void sendUDPport(int sock, sockaddr_in server_addr, int port)
{
    uint32_t message = getSignature();
    std::cerr << "MESSAGE: " << message << std::endl;

    if (sendto(sock, &message, sizeof(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&response_addr, &addr_len);
    if (recv_len >= 0)
    {

        buffer[recv_len] = '\0';
        std::cerr << "response: " << buffer << std::endl;
    }

    uint32_t last_four_bytes;
    uint16_t last_two_bytes;

    memcpy(&last_four_bytes, buffer + recv_len - 6, 4);
    last_four_bytes = ntohl(last_four_bytes); // Convert to network byte order (big-endian)

    // Copy the last 2 bytes (network-to-host order conversion)
    memcpy(&last_two_bytes, buffer + recv_len - 2, 2);
    last_two_bytes = ntohs(last_two_bytes);

    std::cerr << "Last 4 bytes in network byte order: " << std::hex << last_four_bytes << std::endl;
    std::cerr << "Last 2 bytes in network byte order: " << std::hex << last_two_bytes << std::endl;
}

// UDP message where:
// the payload is a encapsulated,
// valid UDP IPv4 packet,
// that has a valid UDP checksum of 0x9345,
// and with the source address being 34.221.123.205

/*
// function to calculate UDP checksum
unsigned short calculate_udp_checksum(struct iphdr *iph, struct udphdr *udph, char *payload, int payload_len) {
    unsigned long sum = 0;

    // pseudo-header checksum
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr) & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr) & 0xFFFF;
    sum += htons(iph->protocol);
    sum += htons(udph->len);

    // UDP header checksum
    sum += ntohs(udph->source);
    sum += ntohs(udph->dest);
    sum += ntohs(udph->len);
    sum += ntohs(udph->check);

    // payload checksum
    for (int i = 0; i < payload_len; i += 2) {
        unsigned short word = (payload[i] << 8) + (i + 1 < payload_len ? payload[i + 1] : 0);
        sum += word;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (unsigned short)(~sum);
}*/

int main(int argc, char *argv[])
{

    if (argc != 6)
    {
        std::cerr << "Usage: " << argv[0] << " <target-ip> <port1> <port2> <port3> <port4>" << std::endl;
        return 1;
    }

    const char *target_ip = argv[1];
    int port1 = std::atoi(argv[2]);
    int port2 = std::atoi(argv[3]);
    int port3 = std::atoi(argv[4]);
    int port4 = std::atoi(argv[5]);

    std::list<int> open_ports;
    open_ports.push_back(port1);
    open_ports.push_back(port2);
    open_ports.push_back(port3);
    open_ports.push_back(port4);

    for (int port : open_ports)
    {
        std::cerr << "\n\nTrying to open port " << port << std::endl;

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
        {
            std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
            return 1;
        }

        // Set a receive timeout of 0.5 seconds
        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = TIMEOUT_USEC;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            std::cerr << "failed to set socket timeout: " << strerror(errno) << std::endl;
            close(sock);
            continue;
        }

        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0)
        {
            std::cerr << "given IP address is weird" << std::endl;
            close(sock);
            continue;
        }

        for (int attempt = 0; attempt < RETRY_COUNT; ++attempt)
        {

            const char *message = "";
            if (sendto(sock, message, strlen(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
            {
                std::cerr << "failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
                break;
            }

            char buffer[BUFFER_SIZE] = {0};
            sockaddr_in response_addr;
            socklen_t addr_len = sizeof(response_addr);

            int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, NULL, NULL);
            if (recv_len >= 0)
            {
                std::cerr << "Successfully opened port: " << port << std::endl;
                buffer[recv_len] = '\0';
                std::cerr << "puzzle:  " << buffer << std::endl;
                std::string buffer_str(buffer);

                // challenge message
                if (buffer_str.find("Greetings from S.E.C.R.E.T") != std::string::npos)
                {
                    std::cerr << "\nThis is the secret challange:\n"
                              << std::endl;
                    secretPort(sock, server_addr, port);
                }

                // evil bit
                if (buffer_str.find("The dark side of network programming") != std::string::npos)
                {
                    std::cerr << "\nThe evil bit challange:" << std::endl;
                    // sendSignatureEvil(sock, server_addr, port);

                    sendSignatureEvilC(port);
                }

                // E.X.P.S.T.N

                if (buffer_str.find("Greetings! I am E.X.P.S.T.N, ") != std::string::npos)
                {
                    std::cerr << "expstn" << std::endl;
                }

                // 4 byte messafe
                if (buffer_str.find("Send me a 4-byte") != std::string::npos)
                {
                    std::cerr << "4 byte message" << std::endl;
                    // sendUDPport(sock, server_addr, port);
                }

                break;
            }
            else
            {
                std::cerr << "No answer :<()" << std::endl;
            }
        }
    }

    return 0;
}