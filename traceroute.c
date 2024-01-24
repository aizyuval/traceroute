#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define SOCKADDR_LEN 16                              
#define IP4_HDRLEN32 5
void error(const char *msg)
{
    perror(msg);
    exit(0);
}
uint16_t checksum (uint16_t *, int);//prototype
int main(int argc, char **argv){

    if(argv[1]==NULL){
        printf("usage is: sudo %s google.com\n ", argv[0]);
        printf("it's sudo + execution + domain or ipv4 \n");
        exit(0);
    }
    // defining structures and variables for LinkedList of ip addresses (routes):
    
    
    struct addrstring{ 
        char string[INET_ADDRSTRLEN+1]; 
        char ttl;
        struct addrstring *string_next;
    };

    size_t addrstring_size = sizeof(struct addrstring);
    struct addrstring *adds, *addresses; // use addresses for filling the list. reserve adds for later iteration on that linked list.
    addresses = malloc(addrstring_size);
    adds = addresses;
                     
    // obtain my ipv4 address to later fill in ip header:

    struct ifaddrs *myaddrs, *ifa;

    struct in_addr *src_in_addr;
    if(getifaddrs(&myaddrs) != 0)
    {
        perror("getifaddrs");
        exit(1);
    }
    for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (!(ifa->ifa_flags & IFF_UP))
            continue;
        if (!(ifa->ifa_addr->sa_family == AF_INET)){
            continue;
        }
        if (!strcmp(ifa->ifa_name, "lo" )){
            continue;
        }
        struct sockaddr_in *srcaddr = (struct sockaddr_in *)ifa->ifa_addr;
        src_in_addr = &srcaddr->sin_addr;
    }



    socklen_t addr_size = SOCKADDR_LEN; // to later point to in recvfrom 

    // converting address given by user to network byte
    struct sockaddr_in their_addr; 
    struct addrinfo pre_destaddr, *destaddr;
    memset(&pre_destaddr,0,sizeof(pre_destaddr));
    pre_destaddr.ai_family = AF_INET;
    getaddrinfo(argv[1], "0", &pre_destaddr, &destaddr);

    struct sockaddr_in * destaddr_in;
    destaddr_in = (struct sockaddr_in*)destaddr->ai_addr;


    // define and fill packet buffer variables, structures and data:

    struct ip * packet_ip;
    struct icmp * packet_icmp; 
 
    char *mesg = "test";
    int icmp_buflen = ICMP_HDRLEN + strlen(mesg);		/* ICMP header and data */

    short packetLen = icmp_buflen + IP4_HDRLEN;
    char sent_packet[packetLen]; //buffer
    char income_packet[packetLen];

    // FILL data of the packet:
    
    packet_ip = (struct ip *)sent_packet; 
    packet_ip->ip_hl = IP4_HDRLEN32;
    packet_ip->ip_v = 4;
    packet_ip->ip_tos = 0;
    packet_ip->ip_len = htons(packetLen);
    packet_ip->ip_off= htons(0x4000);
    packet_ip->ip_p=1;
    packet_ip->ip_src = *src_in_addr; 
    packet_ip->ip_dst = destaddr_in->sin_addr;


    packet_icmp = (struct icmp *)(sent_packet+IP4_HDRLEN);
    packet_icmp->icmp_seq = 0;
    packet_icmp->icmp_type = ICMP_ECHO;
    packet_icmp->icmp_code = 0;

    // insert icmp data
    memcpy(packet_icmp->icmp_data, mesg, strlen(mesg));

    struct ip *recIp;
    char ipBytes[IP4_HDRLEN]; 
    recIp = (struct ip *)ipBytes;

    struct icmp *recIcmp;
    char * icmpBytes = malloc(2);// 2 bytes at first to determine the entire length by the type and code of the icmp packet. 
    recIcmp = (struct icmp *)icmpBytes;

    int sockfd;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // open socket
    if(sockfd<0){
        error("error in socket opening");
    }
    // Set flag so socket expects us to provide IPv4 header.
    const int on = 1;
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
        error ("setsockopt() failed to set IP_HDRINCL ");
    }

    // define variables
    int notRecEcho = 1;
    short iteration = 0;
    int bytesSent, bytesRecieved = 0;
    do {
        iteration += 1;

        // fill dynamic ip and icmp fields:
        packet_ip->ip_ttl = (char)iteration; 
        packet_ip->ip_id = htons(iteration);
        packet_ip->ip_sum = 0;
        packet_ip->ip_sum = checksum((uint16_t *) packet_ip, IP4_HDRLEN);
        packet_icmp->icmp_id = iteration; 
        packet_icmp->icmp_cksum = 0;
        packet_icmp->icmp_cksum = checksum((uint16_t *) packet_icmp, icmp_buflen);


        bytesSent = sendto(sockfd, sent_packet, packetLen, 0,destaddr->ai_addr, SOCKADDR_LEN );
        if(bytesSent<0){
            error("error in sending data through socketfd");
        }
        if(bytesSent!=packetLen){
            printf("should've sent %d bytes but instead send %d bytes ", packetLen, bytesSent);
        } 

        // Timing reciving from socket:

        struct pollfd fds[1];
        fds[0].fd = sockfd;
        fds[0].events = POLLIN;
        int num_events = poll(fds, 1, 10000);
        if(num_events == 0){
            // add the address (*) to list
            strcpy(addresses->string,"*");
            addresses->ttl = (char)iteration;
            addresses->string_next = malloc(addrstring_size);
            addresses = addresses->string_next; 

            continue;
        }else{
             // can recv 
            int pollin_happened = fds[0].revents & POLLIN;
            if(pollin_happened){
                bytesRecieved = recvfrom(sockfd, income_packet, packetLen, 0, (struct sockaddr*)&their_addr, &addr_size);
            }else{
                printf("unexpected event on iteration; %hu", iteration);
                // add the address (*) to list
            strcpy(addresses->string,"*");
            addresses->ttl = (char)iteration;
            addresses->string_next = malloc(addrstring_size);
            addresses = addresses->string_next;
                continue;
            }
        }
        if(bytesRecieved < 0){
            error("error on recvfrom");
        }

        // split the income_packet to ip and icmp:


        struct ip *recIpP = memcpy(recIp, income_packet, IP4_HDRLEN);
        struct icmp *recIcmpP = memcpy(recIcmp, (income_packet + IP4_HDRLEN), 2); // 2 byte at first
 
        if (recIcmpP->icmp_type == 11){
            size_t added_bytes = 6; //complement to -> 8 - 2;
            recIcmp = realloc(icmpBytes,added_bytes);//reallocate icmpBytes with the necessary space for icmp_code 11
            memcpy((recIcmp +2), (income_packet+IP4_HDRLEN + 2), added_bytes);// copy rest of the data

                if(recIcmpP->icmp_code == 0){
                    // copy ip addr to the linked list:
                    if(!inet_ntop(AF_INET, &recIpP->ip_src, addresses->string, INET_ADDRSTRLEN+1)){
                        error("inet_ntop failed");
                    }
                    addresses->ttl = (char)iteration;
                    addresses->string_next = malloc(addrstring_size);
                    addresses = addresses->string_next;

                }else if(recIcmpP->icmp_code==1){
                    printf("fragment reassembly time exceeded. try again");
                    iteration -= 1;
                    exit(0);
                }else {
                    
                    printf("problems with recv icmp code.. %d", recIcmpP->icmp_code);
                    exit(0);
                } 

        }else if(recIcmpP->icmp_type == 0 &&recIpP->ip_src.s_addr == packet_ip->ip_dst.s_addr){
                    // copy ip addr to the linked list:
            if(!inet_ntop(AF_INET, &recIpP->ip_src, addresses->string, INET_ADDRSTRLEN+1)){
                error("inet_ntop failed");
            }
                    addresses->ttl = (char)iteration;
                    addresses->string_next = malloc(addrstring_size);
                    addresses = addresses->string_next; // 
            notRecEcho = 0;
        }

    }while(notRecEcho);// no echo reply

    close(sockfd);

    // print result:

    for(adds = adds; adds->string_next!=NULL; adds=adds->string_next){
        printf("%d. %s\n",adds->ttl, adds->string);
    }

    return 0;

}

uint16_t checksum (uint16_t *addr, int length) {

    int count = length;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}


