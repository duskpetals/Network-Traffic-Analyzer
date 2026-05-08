#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <pcap.h>

void handle_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif