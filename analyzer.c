#include "analyzer.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage is: %s --analyze <pcap_file> <ip_address>\n", argv[0]);
        return 1;
    }
    char buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[2], buffer);

    if (!handle)
    {
        printf("Error opening pcap file: %s\n", buffer);
        return 1;
    }

    time_t curr_time = time(NULL);
    struct tm *tm_info = localtime(&curr_time);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("[INFO] %s Application started with argument \'%s\'\n", timestamp, argv[2]);
    printf("[INFO] %s Initialized data structures\n", timestamp);
    printf("[INFO] %s Filtering traffic of %s\n\n", timestamp, argv[3]);

    pcap_loop(handle, 0, handle_packet, (unsigned char *)argv[3]);
    print_host_info();
    pcap_close(handle);

    printf("[INFO] %s Analysis complete\n", timestamp);

    return 0;
}
