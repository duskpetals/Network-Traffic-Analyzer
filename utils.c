#include "utils.h"
static HostInfo hosts[MAX_HOSTS];
static int host_count = 0;

void print_host_info()
{
    for (int i = 0; i < host_count; i++)
    {
        printf("IP: %s\n", hosts[i].ip);
        printf("%d outgoing packets\t", hosts[i].packets);
        printf("[%u Bytes]\n", hosts[i].bytes);
        printf("Source Ports: ");
        for (int j = 0; j < hosts[i].src_port_count; j++)
        {
            printf("%d", hosts[i].src_ports[j]);
            if(j < hosts[i].src_port_count - 1)
            {
                printf(", ");
            }
        }
        printf("\nDestination Ports: ");
        for (int j = 0; j < hosts[i].dst_port_count; j++)
        {
            printf("%d", hosts[i].dst_ports[j]);
            if(j < hosts[i].dst_port_count - 1)
            {
                printf(", ");
            }
        }
        printf("\nProtocols: ");
        if (hosts[i].uses_tcp && hosts[i].uses_udp)
        {
            printf("TCP, UDP");
        }
        else if (hosts[i].uses_tcp)
        {
            printf("TCP");
        }
        else if (hosts[i].uses_udp)
        {
            printf("UDP");
        }
        printf("\n\n");
    }
}
void update_host_info(const char *ip, int src_port, int dst_port, unsigned int bytes, int protocol)
{
    int index = -1;
    int exists = 0;

    for (int i = 0; i < host_count; i++)
    {
        if (strcmp(hosts[i].ip, ip) == 0)
        {
            index = i;
            break;
        }
    }
    if (index == -1)
    {
        if (host_count < MAX_HOSTS)
        {
            index = host_count;
            strcpy(hosts[index].ip, ip);
            hosts[index].packets = 0;
            hosts[index].bytes = 0;
            hosts[index].src_port_count = 0;
            hosts[index].dst_port_count = 0;
            hosts[index].uses_tcp = 0;
            hosts[index].uses_udp = 0;
            host_count++;
        }
        else
        {
            fprintf(stderr, "Max host limit reached. Cannot track more hosts.\n");
            return;
        }
    }
    hosts[index].packets++;
    hosts[index].bytes += bytes;

    for (int i = 0; i < hosts[index].src_port_count; i++)
    {
        if (hosts[index].src_ports[i] == src_port)
        {
            exists = 1;
            break;
        }
    }
    if (!exists)
    {
        hosts[index].src_ports[hosts[index].src_port_count++] = src_port;
    }

    exists = 0;
    for (int i = 0; i < hosts[index].dst_port_count; i++)
    {
        if (hosts[index].dst_ports[i] == dst_port)
        {
            exists = 1;
            break;
        }
    }
    if (!exists)
    {
        hosts[index].dst_ports[hosts[index].dst_port_count++] = dst_port;
    }

    if (protocol == IPPROTO_TCP)
    {
        hosts[index].uses_tcp = 1;
    }
    else if (protocol == IPPROTO_UDP)
    {
        hosts[index].uses_udp = 1;
    }
}

void handle_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    const struct ether_header *ethernet_header = (struct ether_header *)packet;
    int header_size = ip_header->ip_hl * 4;
    char *filter_ip = (char *)args;
    const struct tcphdr *tcp_header;

    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, sizeof(dst_ip));

    if (strcmp(src_ip, filter_ip) == 0)
    {
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + header_size);
            update_host_info(dst_ip, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), header->len, IPPROTO_TCP);
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + header_size);
            update_host_info(dst_ip, ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), header->len, IPPROTO_UDP);
        }
    }
}
