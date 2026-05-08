#include "analyzer.h"

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage is: %s <pcap_file> <ip_address>\n", argv[0]);
        return 1;
    }
    char buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], buffer);

    if (!handle)
    {
        printf("Error opening pcap file: %s\n", buffer);
        return 1;
    }

    pcap_loop(handle, 0, handle_packet, NULL);

    pcap_close(handle);
    return 0;
}
