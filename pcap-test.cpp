#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>

struct Param
{
    char *dev_{nullptr};

    bool parse(int argc, char *argv[])
    {
        if (argc != 2)
        {
            usage();
            return false;
        }
        dev_ = argv[1];
        return true;
    }

    static void usage()
    {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
    }
};

int main(int argc, char *argv[])
{
    Param param;
    if (!param.parse(argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct ether_header *eth_hdr = (struct ether_header *)(packet);
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(ether_header));
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(ether_header) + ip_hdr->ip_hl * 4);

        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP && ip_hdr->ip_p == IPPROTO_TCP)
        {
            printf("-----------------------------[START]-----------------------------\n");
            printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
            printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
            printf("src ip: %s\n", inet_ntoa(ip_hdr->ip_src));
            printf("dst ip: %s\n", inet_ntoa(ip_hdr->ip_dst));
            printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
            printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
            printf("payload:");
            const u_char *payload = packet + sizeof(ether_header) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;
            int len = header->caplen - sizeof(ether_header) - ip_hdr->ip_hl * 4 - tcp_hdr->th_off * 4;
            if (len > 16)
                len = 16;
            for (int i = 0; i < len; i++)
                printf(" %02x", payload[i]);
            printf("\n");
            printf("------------------------------[END]------------------------------\n");
        }
    }

    pcap_close(pcap);
}
