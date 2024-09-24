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

#define BUFFER_SIZE 1024
#define RETRY_COUNT 3
#define GROUP_ID 64
#define SECRET_PORT 4065

// IP header from slides
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	u_short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	u_short	ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

/*
raw challenge: ???M
Challenge in host byte order: 3198809165
Signed challenge: 0xe20a4420
Server response: Well done group 64. You have earned the right to know the port: 4065!
*/

// method for getting the signature
uint32_t getSignature(){
    uint32_t secret = 0x9eedfeaf;
    uint32_t challenge = 0xbea9f44d;

    // xor operation
    uint32_t signed_challenge = secret ^ challenge;

    signed_challenge = htonl(signed_challenge);

    std::cout << "Signed challenge: 0x" << std::hex << signed_challenge << std::endl;

    return signed_challenge;
}

// method for the S.E.C.R.E.T port, with message of five steps
void secretPort(int sock, sockaddr_in server_addr, int port) {
    unsigned char group_id = GROUP_ID;  // Store group ID as a single unsigned byte

    // Send the group ID as a single byte
    if (sendto(sock, &group_id, sizeof(group_id), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&response_addr, &addr_len);
    std::cerr << recv_len << std::endl;
    if (recv_len >= 0) {

        buffer[recv_len] = '\0';  
         std::cerr << "raw challenge: " << buffer << std::endl;

        // the challeng is 4-byte
        if (recv_len == 4) { 
            
            uint32_t challenge_network;
            std::memcpy(&challenge_network, buffer, sizeof(challenge_network));

            //convert from network byte order to host byte order
            uint32_t challenge_host = ntohl(challenge_network);

            std::cerr << "Challenge in host byte order: " << challenge_host << std::endl;
        } else {
            std::cerr << "Received data is too small to be a 4-byte challenge" << std::endl;
        }
    } else {
        std::cerr << "Error receiving response from port " << port << ": " << strerror(errno) << std::endl;
    }


    // sending signature
    uint32_t sign = getSignature();
    uint8_t message[5];
    message[0] = GROUP_ID; 
    memcpy(&message[1], &sign, sizeof(sign)); 

    if (sendto(sock, message, sizeof(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    memset(buffer, 0, sizeof(buffer));

    recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, NULL, NULL);
    if (recv_len >= 0) {
        buffer[recv_len] = '\0';
        std::cerr << "Server response: " << buffer << std::endl;
    } else {
        std::cerr << "Failed to receive response: " << strerror(errno) << std::endl;
    }


}


// sending a signature to the port with message:
// "Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order)."
void sendSignatureEvil(int sock, sockaddr_in server_addr, int port){

    uint32_t message = getSignature();

    uint32_t evil_bit = 1; // Set the 31st bit to 1 (evil bit).
    message |= evil_bit;
    
    if (sendto(sock, &message, sizeof(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&response_addr, &addr_len);
    if (recv_len >= 0) {

        buffer[recv_len] = '\0';  
        std::cerr << "response: " << buffer << std::endl;
    }
}

void sendUDPport(int sock, sockaddr_in server_addr, int port){
    uint32_t message = getSignature();
    
    if (sendto(sock, &message, sizeof(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        std::cerr << "Failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&response_addr, &addr_len);
    if (recv_len >= 0) {

        buffer[recv_len] = '\0';  
        //std::cerr << "response: " << buffer << std::endl;
    }

    uint32_t last_four_bytes;
    uint16_t last_two_bytes;

    memcpy(&last_four_bytes, buffer + recv_len - 6, 4);
    last_four_bytes = ntohl(last_four_bytes);  // Convert to network byte order (big-endian)

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


int main(int argc, char* argv[]) {

    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <target-ip> <port1> <port2> <port3> <port4>" << std::endl;
        return 1;
    }

    const char* target_ip = argv[1];
    int port1 = std::atoi(argv[2]);
    int port2 = std::atoi(argv[3]);
    int port3 = std::atoi(argv[4]);
    int port4 = std::atoi(argv[5]);

    std::list<int> open_ports;
    open_ports.push_back(port1);
    open_ports.push_back(port2);
    open_ports.push_back(port3);
    open_ports.push_back(port4);

    
    for(int port : open_ports){

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
            return 1;
        }


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

            
            const char* message = "";
            if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                std::cerr << "failed to send packet to port " << port << ": " << strerror(errno) << std::endl;
                break;
            }
            
            
            std::cerr << "port: " << port << std::endl;

            char buffer[BUFFER_SIZE] = {0};
            sockaddr_in response_addr;
            socklen_t addr_len = sizeof(response_addr);

            int recv_len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, NULL, NULL);
            if (recv_len >= 0) {
                buffer[recv_len] = '\0';
                std::cerr << "[1m" << "puzzle:  "  << "[0m" << buffer << std::endl;
                std::string buffer_str(buffer);

                // challenge message
                if(buffer_str.find("Greetings from S.E.C.R.E.T") != std::string::npos){
                    std::cerr << "secret" << std::endl;
                    secretPort(sock, server_addr, port);
                }

                // evil bit
                if(buffer_str.find("The dark side of network programming") != std::string::npos){
                    std::cerr << "evil bit" << std::endl;
                    sendSignatureEvil(sock, server_addr, port);
                }

                // E.X.P.S.T.N

                if(buffer_str.find("Greetings! I am E.X.P.S.T.N, ") != std::string::npos){
                    std::cerr << "expstn" << std::endl;
                }

                // 4 byte messafe
                if(buffer_str.find("Send me a 4-byte") != std::string::npos){
                    std::cerr << "4 byte message" << std::endl;
                    sendUDPport(sock, server_addr, port);
                    
                }

                break;
            }

        }
    }
    

    return 0;
}