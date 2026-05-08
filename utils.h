#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define MAX_HOSTS 256

typedef struct{
    char ip[INET_ADDRSTRLEN];
    int packets;
    unsigned int bytes;
    int src_ports[256];
    int dst_ports[256];
    int src_port_count;
    int dst_port_count;
    int uses_tcp;
    int uses_udp;
} HostInfo;

void handle_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void update_host_info(const char *ip, int src_port, int dst_port, unsigned int bytes, int protocol);
void print_host_info();

#endif