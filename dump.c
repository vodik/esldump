#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <err.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
    const char *filename = argv[1];
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "usage: %s filename", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(filename, err);
    if (!handle)
        errx(1, "couldn't open pcap file %s", filename);

    const uint8_t *packet;
    struct pcap_pkthdr header;

    while ((packet = pcap_next(handle, &header))) {
        const struct ip *ipheader = (struct ip *)&packet[14];
        const struct tcphdr* tcpheader = (struct tcphdr *)&packet[14 + ipheader->ip_hl * 4];

        if (ipheader->ip_p != 0x06)
            continue;
        if (tcpheader->th_sport != htons(8021))
            continue;
        if (!tcpheader->th_flags & TH_PUSH)
            continue;

        const uint8_t *payload = (uint8_t *)(packet + 14 + ipheader->ip_hl * 4 + tcpheader->th_off * 4 );
        size_t len = header.caplen - (payload - packet);

        write(1, payload, len);
        /* printf("%s\n", payload); */
    }

    return 0; //done
}