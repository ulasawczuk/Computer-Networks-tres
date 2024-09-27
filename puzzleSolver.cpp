#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <list>
#include <cassert> 
#include <sstream>
#include <iomanip>

#define BUFFER_SIZE 1024
#define RETRY_COUNT 3
#define GROUP_ID 64

#define TIMEOUT_SEC 0
#define TIMEOUT_USEC 50000 // 0.5 seconds in microseconds

// IP header from slides
struct ip
{
#if BYTE_ORDER == LITTLE_ENDIAN
    u_char ip_hl : 4, /* header length */
        ip_v : 4;     /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_char ip_v : 4, /* version */
        ip_hl : 4;   /* header length */
#endif
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
#error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

// UDP header struct
struct updhdr
{
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

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

    //std::cout << "signature: " << std::hex << signed_challenge << std::endl;

    return signed_challenge;
}

// method to calculate the checksum
uint16_t udp_checksum(struct updhdr *p_udp_header, size_t len, uint32_t src_addr, uint32_t dest_addr)
{
    const uint16_t *buf = (const uint16_t *)p_udp_header;
    uint16_t *ip_src = (uint16_t *)&src_addr, *ip_dst = (uint16_t *)&dest_addr;
    uint32_t sum = 0;

    // sum up the header, length and payload
    for (size_t i = 0; i < len / 2; i++)
    {
        sum += *buf++;
    }

    // pad odd byte with zero
    if (len & 1)
    {
        sum += *((uint8_t *)buf);
    }

    // add pseudo-header fields, source IP split into two 4 bits, destination IP split into two 4 bits, protocol and length
    sum += ip_src[0] + ip_src[1];
    sum += ip_dst[0] + ip_dst[1];
    sum += htons(IPPROTO_UDP);
    sum += htons(len);

    // fold sum to 16 bits: anything above 16 bits, add to the 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // return then one's compliment
    return (uint16_t)~sum;
}

char* getKnock(std::string secret_phrase) {

    uint32_t signature = getSignature();
    //std::stringstream ss;
    //ss << std::hex << std::setw(8) << std::setfill('0') << signature;  // Format to 8 hex digits
    //std::string hex_signature = ss.str();

    size_t message_length = 4 + secret_phrase.length();
    //size_t message_length = hex_signature.length() + secret_phrase.length();
    char* message = new char[message_length];

    //memcpy(message, hex_signature.c_str(), hex_signature.length());
    //memcpy(message + hex_signature.length(), secret_phrase.c_str(), secret_phrase.length());

    memcpy(message, &signature, sizeof(signature));
    memcpy(message + 4, secret_phrase.c_str(), secret_phrase.length());

    //std::cerr << "mess: " << message << std::endl;

    return message;
}

// method for the secret port
int secretPort(int sock, sockaddr_in server_addr, int port)
{
    unsigned char group_id = GROUP_ID; 

    for (int attempt = 0; attempt < RETRY_COUNT; ++attempt)
    {
        // send the group ID as a single byte
        if (sendto(sock, &group_id, sizeof(group_id), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
            return -1;
            ;
        }

        char buffer[BUFFER_SIZE] = {0};
        sockaddr_in response_addr;
        socklen_t addr_len = sizeof(response_addr);

        int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&response_addr, &addr_len);
        // std::cerr << recv_len << std::endl;
        if (recv_len >= 0)
        {

            buffer[recv_len] = '\0';
            std::cerr << "Raw challenge: " << buffer << std::endl;

            // the challeng is 4-byte
            if (recv_len == 4)
            {

                uint32_t challenge_network;
                std::memcpy(&challenge_network, buffer, sizeof(challenge_network));

                // convert from network byte order to host byte order
                uint32_t challenge_host = ntohl(challenge_network);

                std::cout << "Challenge in host byte order: " << challenge_host << std::endl;
            }
            else
            {
                std::cout << "Received data is too small to be a 4-byte challenge" << std::endl;
            }
        }
        else
        {
            std::cerr << "Error receiving response from port " << port << std::endl;
            continue;
        }

        // sending signature
        uint32_t sign = getSignature();
        uint8_t message[5];
        message[0] = GROUP_ID;
        memcpy(&message[1], &sign, sizeof(sign));

        std::cout << "Sending signature " << sign << "...." << std::endl;

        if (sendto(sock, message, sizeof(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
            return -1;
        }

        memset(buffer, 0, sizeof(buffer));
        memset(buffer, 0, sizeof(buffer));

        recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, NULL, NULL);
        if (recv_len >= 0)
        {
            buffer[recv_len] = '\0';
            std::cout << "Response: " << buffer << std::endl;
        }
        else
        {
            std::cerr << "Failed to receive response: " << port << std::endl;
            continue;
        }

        // get the secret port from response

        std::cout << "Extracting secret port...." << std::endl;

        char port_str[5];

        memcpy(port_str, buffer + recv_len - 5, 4);
        port_str[4] = '\0';

        int secret_port = atoi(port_str);

        std::cerr << "Secret port: " << secret_port << std::endl;
        return secret_port;
        break;
    }
}

// method for the evil bit port
int sendSignatureEvil(int sock, sockaddr_in server_addr, int port, const char *target_ip)
{

    uint32_t message = getSignature();

    // create a raw socket with UDP protocol
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
    {
        perror("socket() error");
        return -1;
    }
    printf("OK: a raw socket is created.\n");

    // inform the kernel to not fill up the packet structure, we will build our own
    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        return -1;
    }
    printf("OK: socket option IP_HDRINCL is set.\n");

    // set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt SO_RCVTIMEO error");
        return -1;
    }
    std::cout << "OK: socket receive timeout is set to 5 seconds." << std::endl;

    char buffer[BUFFER_SIZE] = {0};
    struct iphdr *iph = (struct iphdr *)buffer;
    struct updhdr *udph = (struct updhdr *)(buffer + sizeof(struct iphdr));

    // set up iphdr
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(message);
    iph->id = htonl(54321); // Id of this packet
    iph->frag_off = 0x8000;
#ifdef __linux__
    iph->frag_off = htons(0x8000);
#endif
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0; // Set to 0 before calculating checksum

    // std::cerr << "Size of struct IP: " << sizeof(struct iphdr) << std::endl;
    // std::cerr << "Size of struct udphdr: " << sizeof(struct udphdr) << std::endl;
    // std::cerr << "Size of message: " << sizeof(message) << std::endl;

    // assign destination address
    if (inet_pton(AF_INET, target_ip, &(iph->daddr)) != 1)
    {
        perror("inet_pton");
        return -1;
    }

    // get own IP address from the socket
    struct sockaddr_in own_addr;
    socklen_t own_addr_len = sizeof(own_addr);
    if (getsockname(sock, (struct sockaddr *)&own_addr, &own_addr_len) < 0)
    {
        perror("can't get own IP address from socket");
        return -1;
    }

    // assign own ip address as source
    char myIP[16];
    iph->saddr = inet_addr(inet_ntop(AF_INET, &own_addr.sin_addr, myIP, sizeof(myIP)));

    // set up udphdr
    udph->source = own_addr.sin_port;
    udph->dest = htons(port);
    udph->len = htons(sizeof(struct updhdr) + sizeof(message));
    udph->check = 0;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &sin.sin_addr);

    memcpy(buffer + sizeof(struct ip) + sizeof(struct udphdr), &message, sizeof(message));

    for (int attempt = 0; attempt < RETRY_COUNT; ++attempt)
    {
        std::cout << "Sending packet with evil bit...." << std::endl;
        // send the packet
        if (sendto(sd, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            perror("sendto failed");
        }
        else
        {
            printf("Packet Send! Length : %d \n", iph->tot_len);
        }

        char response_buffer[BUFFER_SIZE];
        struct sockaddr_in response_addr;
        socklen_t addr_len = sizeof(response_addr);

        int recv_len = recvfrom(sock, response_buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&response_addr, &addr_len);
        std::string buffer_str(response_buffer);
        if (recv_len >= 0)
        {
            response_buffer[recv_len] = '\0';
            std::string buffer_str(response_buffer);
            if(buffer_str.find("is a pathway") != std::string::npos){
                continue;
            }
            std::cerr << "Response: " << response_buffer << std::endl;
        }
        else
        {
            std::cerr << "recvfrom failed: " << strerror(errno) << std::endl;
            continue;
        }

        // get the secret port
        std::cout << "Extracting secret port...." << std::endl;
        char port_str[5]; 
        
        memcpy(port_str, response_buffer + recv_len - 4, 4);
        port_str[4] = '\0';  

        int secret_port = atoi(port_str);

        std::cerr << "Secret port: " << secret_port << std::endl;
        return secret_port;
        break;
    }
    close(sd);
}

// method for the checksum port
std::string checksumPort(int sock, sockaddr_in server_addr, int port, const char *target_ip)
{
    uint32_t message = getSignature();
    uint16_t two_bytes;
    uint32_t four_bytes;
    in_addr src_ip;
    for (int attempt = 0; attempt < RETRY_COUNT; ++attempt)
    {
        // send the signature
        std::cout << "Sending signature " << message << "...." << std::endl;
        if (sendto(sock, &message, sizeof(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
            return "";
        }
        else
        {
            std::cerr << "Packet sent successfully! " << std::endl;
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
        else
        {
            continue;
        }

        // get last 6 bytes, 2 first bytes of last 6 - checksum, 4 bytes - ip
        uint32_t four_bytes_ip;

        memcpy(&two_bytes, buffer + recv_len - 6, 2); // checksum

        memcpy(&four_bytes_ip, buffer + recv_len - 4, 4); // IP

        // convert the IP address to the in_addr structure
        src_ip.s_addr = four_bytes_ip;

        std::cerr << "Extracted checksum: " << two_bytes << std::endl;
        std::cerr << "Extracted IP: " << inet_ntoa(src_ip) << std::endl;

        break;
    }

    char toSend[BUFFER_SIZE] = {0};
    struct ip *iphdr = (struct ip *)toSend;
    struct updhdr *udp_hd = (struct updhdr *)(toSend + sizeof(struct ip));

    memset(toSend, 0, BUFFER_SIZE);

    // set up IP header
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4; // IPv4
    iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct updhdr) + sizeof(uint16_t));
    iphdr->ip_tos = 0;
    iphdr->ip_id = htons(54321);
    iphdr->ip_ttl = 64;
    iphdr->ip_off = 0;
    iphdr->ip_src = src_ip;                             // source IP
    iphdr->ip_dst.s_addr = server_addr.sin_addr.s_addr; // destination IP
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_sum = 0;

    // std::cerr << "Source ip (from iphdr): " << inet_ntoa(iphdr->ip_src) << std::endl;
    // std::cerr << "IP Length (ip_len): " << ntohs(iphdr->ip_len) << std::endl;

    struct sockaddr_in own_addr;
    socklen_t own_addr_len = sizeof(own_addr);
    if (getsockname(sock, (struct sockaddr *)&own_addr, &own_addr_len) < 0)
    {
        perror("can't get own IP address from socket");
        exit(1);
    }

    // set up UDP header
    udp_hd->source = own_addr.sin_port;
    udp_hd->dest = htons(port);
    udp_hd->len = htons(sizeof(struct updhdr) + sizeof(uint16_t));
    udp_hd->check = 0;

    // modify the payload (add two bytes), we tried for very long to understand what payload to add, however the distance from needed
    // checksum and our checksum was always different, so we are bruteforcing the payload unfortunately:(
    // loop going through all hexadecimals
    for (int i = 0; i <= 0xffff; i++)
    {
        // printf( "%04x = %d\n", i, i );
        uint16_t data = i;
        memcpy(toSend + sizeof(struct ip) + sizeof(struct updhdr), &data, sizeof(data));

        // UDP checksum
        uint16_t calculated_checksum = udp_checksum(udp_hd, sizeof(struct updhdr) + sizeof(data), iphdr->ip_src.s_addr, iphdr->ip_dst.s_addr);

        if (calculated_checksum == two_bytes)
        { // if it's the same as two bytes for checksum from message we take it!
            std::cerr << "Calculated checksum: " << calculated_checksum << ", added payload: " << data << std::endl;
            udp_hd->check = calculated_checksum;
            uint16_t checksum_in_header = ntohs(udp_hd->check);
            // std::cerr << "Checksum in UDP header: " << std::hex << checksum_in_header << std::endl;
            break;
        }
    }

    // sending the packet
    for (int attempt = 0; attempt < RETRY_COUNT; ++attempt)
    {
        std::cout << "Sending packet with calculated checksum...." << std::endl;
        ssize_t sent_len = sendto(sock, toSend, ntohs(iphdr->ip_len), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent_len < 0)
        {
            std::cerr << "Failed to send packet: " << strerror(errno) << std::endl;
        }
        else
        {
            std::cerr << "Packet sent successfully: " << sent_len << " bytes to " << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << std::endl;
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
        else
        {
            std::cerr << "recvfrom failed: " << strerror(errno) << std::endl;
            continue;
        }

        // find the secret phrase

        std::cout << "Extracting secret phrase...." << std::endl;
        char *start = strchr(buffer, '"');
        if (start == nullptr) {
            std::cerr << "Failed to find the starting quotation mark." << std::endl;
            return "";
        }
        
        char *end = strchr(start + 1, '"');
        if (end == nullptr) {
            std::cerr << "Failed to find the ending quotation mark." << std::endl;
            return "";
        }
        
        int phrase_length = end - start - 1;
        std::string secret_phrase(start + 1, phrase_length);
        std::cerr << "Secret phrase: " << secret_phrase << std::endl;

        return secret_phrase;
        break;
    }
}

void expstn(int port, int secret_port1, int secret_port2, int sock, sockaddr_in server_addr, std::string secret_phrase, const char *target_ip){

    char message[BUFFER_SIZE];
    std::vector<int> secret_ports;
    snprintf(message, sizeof(message), "%d,%d", secret_port1, secret_port2); // combine secret ports
    std::cerr << "Sending: " << message << " to port: " << port << std::endl;

    for (int attempt = 0; attempt < RETRY_COUNT; ++attempt){

        server_addr.sin_port = htons(port);

        int sent_bytes = sendto(sock, message, strlen(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (sent_bytes == -1) {
            perror("sendto failed");
            exit(1);
        } else {
            std::cout << "Message sent successfully, sent bytes: " << sent_bytes << std::endl;
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
        else
        {
            std::cerr << "recvfrom failed: " << strerror(errno) << std::endl;
            continue;
        }

        // getting the ports in order of knocks
        // splitting the buffer
        char separator = ',';
        int i = 0;
        std::string s;

        // add a comma at the end of buffer to not miss the last knocks
        buffer[recv_len] = ',';   
        buffer[recv_len + 1] = '\0';
        while (buffer[i] != '\0') {
            if (buffer[i] != separator) {
                // Append the char to the temp string.
                s += buffer[i];
            } else {
                //std::cout << s << std::endl;
                int t = stoi(s, 0, 10);
                // Check if the port number is expected one
                assert(t == secret_port1 || t == secret_port2);
                //std::cout << t << std::endl;
                secret_ports.push_back(t);
                s.clear();
            }
            i++;
        }
        assert(secret_ports.size() == 6);
        assert(s.empty());

        std::cout << "knock: " << getKnock(secret_phrase) << std::endl;
  
        int j = 0;
        for(int porty : secret_ports){
            j++;

            std::cout << "knocking on port: " << porty << "..." << std::endl;
            //std::cout << "j: " << j << std::endl;
            char* knock = getKnock(secret_phrase);

            int socky = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (socky < 0)
            {
                std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
                return;
            }

            struct timeval timeout;
            timeout.tv_sec = TIMEOUT_SEC;
            timeout.tv_usec = TIMEOUT_USEC;
            if (setsockopt(socky, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
            {
                std::cerr << "failed to set socket timeout: " << strerror(errno) << std::endl;
                close(sock);
                continue;
            }

            sockaddr_in server_addr2;
            memset(&server_addr2, 0, sizeof(server_addr2));
            server_addr2.sin_family = AF_INET;
            server_addr2.sin_port = htons(porty);
            if (inet_pton(AF_INET, target_ip, &server_addr2.sin_addr) <= 0)
            {
                std::cerr << "given IP address is weird" << std::endl;
                close(sock);
                continue;
            }

            if (sendto(socky, knock, (4 + secret_phrase.length()), 0, (struct sockaddr *)&server_addr2, sizeof(server_addr2)) < 0)
            {
                perror("sendto failed\n");
            }
            else
            {
               std::cout << j << " knock sent!" << std::endl;
            }
            if(j == secret_ports.size()){
                std::cout << "last port" << std::endl;
                char buffer[BUFFER_SIZE] = {0};
                sockaddr_in response_addr;
                socklen_t addr_len = sizeof(response_addr);

                int recv_len = recvfrom(socky, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&response_addr, &addr_len);
                if (recv_len >= 0)
                {
                    buffer[recv_len] = '\0';
                    std::cout << "response: " << buffer << std::endl;
                }
                else
                {
                    std::cerr << "recvfrom failed: " << strerror(errno) << std::endl;
                }
            }
        }
    break;
    }
}

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
    int secret_port1;
    int secret_port2;
    std::string secret_phrase;

    std::list<int> open_ports;
    open_ports.push_back(port1);
    open_ports.push_back(port2);
    open_ports.push_back(port3);
    open_ports.push_back(port4);

    for (int port : open_ports)
    {
        std::cout << "\n\n-------------------------------------------------" << std::endl;
        std::cout << "Trying to open port: " << port << std::endl;

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
                buffer[recv_len] = '\0';
                std::cout << "Puzzle:  " << buffer << std::endl;
                std::string buffer_str(buffer);

                // secret port
                if (buffer_str.find("Greetings from S.E.C.R.E.T") != std::string::npos)
                {
                    std::cout << "Solving secret port" << std::endl;
                    secret_port1 = secretPort(sock, server_addr, port);
                }

                // evil bit
                if (buffer_str.find("The dark side of network programming") != std::string::npos)
                {
                    std::cout << "Solving evil bit port" << std::endl;
                    secret_port2 = sendSignatureEvil(sock, server_addr, port, target_ip);
                }

                // E.X.P.S.T.N

                if (buffer_str.find("Greetings! I am E.X.P.S.T.N, ") != std::string::npos)
                {
                    std::cout << "expstn" << std::endl;
                    expstn(port, secret_port1, secret_port2, sock, server_addr, secret_phrase, target_ip);
                }

                // checksum port
                if (buffer_str.find("Send me a 4-byte") != std::string::npos)
                {
                    std::cout << "Solving checksum port" << std::endl;
                    secret_phrase = checksumPort(sock, server_addr, port, target_ip);
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