// what's stopping me from impersonating someone else with sending an ip packet including his ip instead of mine?
// how often does while evaluate the condition?
// what exactly filters traffic into that sockfd? does the sendto also sends the sockfd details?(so they will send back to the same sockfd)
// ONLY WORKS WITH WIRELESS WIFI INTERFACES! - check against cable interface
// validate checksum to avoid curropted packets;
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
    // do - send and recieve packet with ttl++, get address, get packet types and data.
    // while notRecEcho 
    if(argv[1]==NULL){
        printf("usage is: sudo %s google.com\n ", argv[0]);
        printf("it's sudo + execution + domain or ipv4 \n");
        exit(0);
    }
    int notRecEcho = 1;
    short iteration = 0;

    char **strings = malloc(sizeof(char *));//every element is a pointer to string 
    char buffer[INET_ADDRSTRLEN+1];
            char *ptr = malloc(INET_ADDRSTRLEN+1);
            char *ptrPadd = ptr;
            memcpy(strings[0], ptrPadd, sizeof(char*));// to first string, copy allocated space address'
                                             // get src address 
    struct pollfd fds[1];
    int timeout = 10000;
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

    int sockfd;
    socklen_t  addr_size = SOCKADDR_LEN; // pointer to size 
    struct sockaddr_in their_addr; 
    // set up addrinfo struct for the info, with the address given by user
    struct addrinfo pre_destaddr, *destaddr;
    memset(&pre_destaddr,0,sizeof(pre_destaddr));
    pre_destaddr.ai_family = AF_INET;
    getaddrinfo(argv[1], "0", &pre_destaddr, &destaddr);
    // cast destination address to validate it seperately from src address (with sockaddr_in)
    struct sockaddr_in * destaddr_in;
    destaddr_in = (struct sockaddr_in*)destaddr->ai_addr;


    // structure the packets
    // ip, then icmp


    struct ip * packet_ip;

    struct icmp *packet_icmp; // actual structure of the packet
    char *mesg = "test";
    int icmp_buflen = ICMP_HDRLEN + strlen(mesg);		/* ICMP header and data */
    short packetLen = icmp_buflen + IP4_HDRLEN;
    char sent_packet[packetLen];

    // start with ip
    // outside do-while: 
    packet_ip = (struct ip *)sent_packet; 
    packet_ip->ip_hl = IP4_HDRLEN32;
    packet_ip->ip_v = 4;
    packet_ip->ip_tos = 0;
    packet_ip->ip_len = htons(packetLen);
    packet_ip->ip_off= htons(0x4000);
    packet_ip->ip_p=1;
    packet_ip->ip_src = *src_in_addr; // in_addr
    packet_ip->ip_dst = destaddr_in->sin_addr;// in_addr
                                                 //packet_icmp should point to sent_packet memory space
        packet_icmp = (struct icmp *)(sent_packet+IP4_HDRLEN);

    char income_packet[packetLen];

    //fill the header
    packet_icmp->icmp_seq = 0;
    packet_icmp->icmp_type = ICMP_ECHO;
    packet_icmp->icmp_code = 0;

    // insert data
    memcpy(packet_icmp->icmp_data, mesg, strlen(mesg));

    // define structures and assign space for icmp and ip splitted data
    struct ip *recIp, *recOrgIp;
    char ipBytes[IP4_HDRLEN]; 
    recIp = (struct ip *)ipBytes;
    char OrgipBytes[IP4_HDRLEN];
    recOrgIp = (struct ip *)OrgipBytes;

    struct icmp *recIcmp, *recOrgIcmp;
    char OrgicmpBytes[ICMP_HDRLEN];
    char * icmpBytes = malloc(2);// 2 bytes at first to determine the entire length by the type and code of the icmp packet. 
    recIcmp = (struct icmp *)icmpBytes;
    recOrgIcmp = (struct icmp *)OrgicmpBytes;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // initialize ipv4 raw socket of icmp protocol 
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;
    if(sockfd<0){
        error("error in socket opening");
    }
  // Set flag so socket expects us to provide IPv4 header.
    const int on = 1;
  if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    error ("setsockopt() failed to set IP_HDRINCL ");
  }

  // Bind socket to interface index.
                                                     
    // send the packet to the address

    // -> start do while

    do {
        iteration += 1;

        // inside do-while: ttl, checksum
        //
        packet_ip->ip_ttl = (char)iteration; 
        packet_ip->ip_id = htons(iteration);
        packet_ip->ip_sum = 0;
        packet_ip->ip_sum = checksum((uint16_t *) packet_ip, IP4_HDRLEN);
        // fill dynamic icmp data
        packet_icmp->icmp_id = iteration; // change id over iteration
        packet_icmp->icmp_cksum = 0;
        //compute checksum
        packet_icmp->icmp_cksum = checksum((uint16_t *) packet_icmp, icmp_buflen);


        int bytesSent, bytesRecieved = 0;// can be decalred outside
        bytesSent = sendto(sockfd, sent_packet, packetLen, 0,destaddr->ai_addr, SOCKADDR_LEN );
        if(bytesSent<0){
            error("error in sending data through socketfd");
        }
        if(bytesSent!=packetLen){
            printf("should've sent %d bytes but instead send %d bytes ", packetLen, bytesSent);
        } 

        int num_events = poll(fds, 1, timeout);
        if(num_events == 0){
            printf("timed out on iteration %hu ",iteration);
            // add no address to addrlist
            strcpy(buffer,"*");
            strcpy(strings[iteration-1],buffer);
            char * newstr = realloc(strings, sizeof(char*));
            char * p = malloc(INET_ADDRSTRLEN+1);
            char * pt = p;
            memcpy(newstr, pt, sizeof(char*)); // to new string space, copy allocated space address
            
            continue;
        }else{// 
            //can recv
            int pollin_happened = fds[0].revents & POLLIN;
            if(pollin_happened){
            //recv from
            bytesRecieved = recvfrom(sockfd, income_packet, packetLen, 0, (struct sockaddr*)&their_addr, &addr_size);
            }else{
                printf("unexpected event on iteration; %hu", iteration);
            // add no address to addrlist
            strcpy(buffer,"*");
            strcpy(strings[iteration-1],buffer);
            char * newstr = realloc(strings, sizeof(char*));
            char * p = malloc(INET_ADDRSTRLEN+1);
            char * pt = p;
            memcpy(newstr, pt, sizeof(char*)); // to new string space, copy allocated space address
                continue;
            }
        }
        // recieve the packet
        // there are 2 kind of packet that can be returned, and should be checked against:
        // 1. echo response
        // 2. icmp time exeeded, ttl exceeded
        // EXAMINE: if the icmp error message will go to the same sockfd
        if(bytesRecieved < 0){
            error("error on recvfrom");
        }
        // copy data from packet to structures
        // is pointer here useless?
        struct ip *recIpP = memcpy(recIp, income_packet, IP4_HDRLEN);
        struct icmp *recIcmpP = memcpy(recIcmp, (income_packet + IP4_HDRLEN), 2); // copying only 2 bytes. icmp_type, icmp_code - to then determine further copying according to packet nature
        if (recIcmpP->icmp_type == 11){// by the way, determine packet nature.
            size_t added_bytes = 6; //complement to 8 //ICMP_HDRLEN + IP4_HDRLEN + 8 - 2;
            recIcmp = realloc(icmpBytes,added_bytes);//reallocate icmpBytes with the necessary space for icmp_code 11
                memcpy(recIcmp, (income_packet+IP4_HDRLEN + 2), added_bytes); // icmp_type 11 includes: icmphdr, ip hdr, 8 bytes extra. minus already existing 2 bytes of space
            struct ip *recOrgIpP = memcpy (recOrgIp, (income_packet+IP4_HDRLEN + ICMP_HDRLEN), IP4_HDRLEN); // copying original ip hdr to the ip struct //NOT ERROR but, i have no need for ipP. just use ip.
                                                                                                        struct icmp *recOrgIcmpP = memcpy(recOrgIcmp, (income_packet+IP4_HDRLEN + ICMP_HDRLEN + IP4_HDRLEN), ICMP_HDRLEN); 
            if(recOrgIpP->ip_src.s_addr == packet_ip->ip_src.s_addr  && recOrgIpP->ip_dst.s_addr == packet_ip->ip_dst.s_addr  && recOrgIcmpP->icmp_type == packet_icmp->icmp_type && recOrgIcmpP->icmp_code == packet_icmp->icmp_code){

                    notRecEcho = 1;
                if(recIcmpP->icmp_code ==0){


                    inet_ntop(AF_INET, &(recIpP->ip_src.s_addr), buffer, INET_ADDRSTRLEN);
                    strcpy(strings[iteration-1], buffer);
                    char * newstr = realloc(strings, sizeof(char *));
                    char * p =malloc(INET_ADDRSTRLEN+1);
                    char *pt = p;
                    memcpy(newstr,pt,sizeof(char*));
                }else{//code 1
                    printf("fragment reassembly time exceeded. try again");
                    iteration -= 1;
                    //ttl stay the same!
                }
            } 
            // DO I NEED TO UPDATE recIcmP?
        }else if(recIcmpP->icmp_type == 0 &&recIpP->ip_src.s_addr == packet_ip->ip_dst.s_addr){
                    inet_ntop(AF_INET, &(recIpP->ip_src.s_addr), buffer, INET_ADDRSTRLEN);
                    strcpy(strings[iteration-1], buffer);
            printf("\nhost is up. | Sequence: %d| Id: %hu\n", packet_icmp->icmp_seq,packet_icmp->icmp_id);
            notRecEcho = 0;
        }

    }while(notRecEcho);//not recv'd echo
                      
    close(sockfd);
    printf("amount of hops: %d\n", packet_ip->ip_ttl);
    for(uint8_t i =0; i<packet_ip->ip_ttl; i++){
        printf("%d.%s -> ",i+1, strings[i]); 
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


