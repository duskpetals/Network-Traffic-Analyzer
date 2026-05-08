#include "analyzer.h"

void handle_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    printf("Packet captured: length %d\n", header->len);
}