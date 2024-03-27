#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "ess_libnet.h"


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
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
		printf("%u bytes captured\n", header->caplen);
	
	
		struct libnet_ethernet_hdr* eth_hdr = packet;

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		
			struct libnet_ipv4_hdr* ipv4_hdr = eth_hdr+1;

			
			if(ipv4_hdr->ip_p == IPTYPE_TCP){
			
				struct libnet_tcp_hdr* tcp_hdr = ipv4_hdr+1;
				
				printf("Src MAC: ");
				for(int i=0; i<5; i++) printf("%x:", eth_hdr->ether_shost[i]);
				printf("%x, ", eth_hdr->ether_shost[5]);
				
				printf("Dst MAC: ");
				for(int i=0; i<5; i++) printf("%x:", eth_hdr->ether_dhost[i]);
				printf("%x\n\n", eth_hdr->ether_dhost[5]);
				
				printf("Src IP: ");
				for(int i=0; i<3; i++) printf("%d.", ipv4_hdr->ip_src[i]);
				printf("%d, ", ipv4_hdr->ip_src[3]);
				
				printf("Dst IP: ");
				for(int i=0; i<3; i++) printf("%d.", ipv4_hdr->ip_dst[i]);
				printf("%d\n\n", ipv4_hdr->ip_dst[3]);
				
				printf("Src PORT: %d, Dst PORT: %d\n\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
				
				
				u_int16_t pay_len = ntohs(ipv4_hdr->total_length)-20-32;
				if(pay_len > 20) pay_len = 20;
				
				struct payload* payl = tcp_hdr+1;
			
				printf("Payload: ");
				if(pay_len == 0) printf("Empty Packet!");
				else for(int i=0; i<pay_len; i++) printf("%02x", payl->pay[i]);
				printf("\n\n\n");
				
				
			}
			
		}

	}

	pcap_close(pcap);
}
