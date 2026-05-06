#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
    if(argc != 3) {
        fprintf(stderr, "Usage is: %s <pcap_file> <ip_address>\n", argv[0]);
        return 1;
    }
    char buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], buffer);
    struct pcap_pkthdr *header;
    const u_char *packet;
    
    if(!handle) {
        printf("Error opening pcap file: %s\n", buffer);
        return 1;
    }

    while(pcap_next_ex(handle, &header, &packet) >= 0){
        printf("Packet length: %d\n", header->len);
    }

    pcap_close(handle);
    return 0;
}