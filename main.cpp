#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_Ethernet(const u_char* packet){
    struct libnet_ethernet_hdr* ETH = (struct libnet_ethernet_hdr *) packet;
    int i = 0;

    printf("Destination MAC  | ");
    for (i = 0; i < 5; i++){
        printf("%02x:", ETH->ether_shost[i]);
    }
    printf("%02x\n", ETH->ether_shost[i]);

    printf("Source MAC       | ");
    for (i = 0; i < 5; i++){
        printf("%02x:", ETH->ether_dhost[i]);
    }
    printf("%02x\n", ETH->ether_dhost[i]);
}

void print_IP4(const u_char* packet) {
    struct libnet_ipv4_hdr* IP4 = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
    int i = 0;

    // 10.10.10.11 are catched 0a 0a 0a 0b, but packet bytes are 0b 0a 0a 0a.
    //
    // 0b 0a 0a 0a  -------------> 0a 0a 0a 0b
    // 24 16  8  0
    //
    // (0b 0a 0a 0a >> 24) ------> (00 00 00 0b) & 0xff ------> 00 00 00 0b
    // (0b 0a 0a 0a >> 16) ------> (00 00 0b 0a) & 0xff ------> 00 00 00 0a
    //
    // struct in_addr { uint32_t s_addr } so, we can use uint32_t ntohl

    printf("Source IP        | ");
    for(i = 24; i >= 8; i -= 8) {
        printf("%d.", (ntohl(IP4->ip_src.s_addr) >> i) & 0xff);
    }
    printf("%d\n", (ntohl(IP4->ip_src.s_addr) >> i) & 0xff);

    printf("Destination IP   | ");
    for(i = 24; i >= 8; i -= 8) {
        printf("%d.", (ntohl(IP4->ip_dst.s_addr) >> i) & 0xff);
    }
    printf("%d\n", (ntohl(IP4->ip_dst.s_addr) >> i) & 0xff);
}

void print_TCP(const u_char* packet){
    struct libnet_tcp_hdr* TCP = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

    // struct libnet_tcp_hdr { u_int16_t th_sport .... } so, we can use uint16_t ntohs
    printf("Source Port      | ");
    printf("%u\n", ntohs(TCP->th_sport));
    printf("Destination Port | ");
    printf("%u\n", ntohs(TCP->th_dport));
}

void print_Payload(const u_char* packet) {
    const u_char * payload = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
    int i = 0;

    printf("Payload          | ");
    for(i = 0; i < 8; i++) {
        printf("0x%02x ", *(payload + i));
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        print_Ethernet(packet);
        print_IP4(packet);
        print_TCP(packet);
        print_Payload(packet);
        printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
