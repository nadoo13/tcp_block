#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		char c=0;
		printf("default interface name : enp0s3, okay? y/n\n");
		scanf("%c",&c);
		if(c=='y') {
			argv[1]="enp0s3";
		}
		else {
			usage();
			return -1;
		}
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);
		printf("src MAC : ");
		for(int i=6;i<12;i++) { printf("%02x ",packet[i]);}
		printf("\n");
		printf("dest MAC : ");
		for(int i=0;i<6;i++) { printf("%02x ",packet[i]);}
		printf("\n");
		uint16_t eth_type = (packet[12]<<8) + packet[13];
		printf("type : %04x\n",eth_type);

		if(eth_type == 0x0800) {
			printf("src IP : ");
			for(int i=0;i<4;i++) { printf("%d%c",packet[26+i],i<3?'.':'\n');}
			printf("dest IP : ");
			for(int i=0;i<4;i++) { printf("%d%c",packet[30+i],i<3?'.':'\n');}
			uint8_t ip_hdlen = packet[14]&0x0f;
			if(ip_hdlen<5)ip_hdlen = 5;
			ip_hdlen*=4;
			uint16_t ip_totlen = (packet[16]<<8) + packet[17];
			uint8_t IP_prot = packet[23];

			if(IP_prot == 0x06) {
				printf("src Port : %d\n",(packet[14+ip_hdlen]<<8) + packet[15+ip_hdlen]);
				printf("dest Port : %d\n",(packet[16+ip_hdlen]<<8) + packet[17+ip_hdlen]);
				uint16_t tcp_hdlen = packet[14+ip_hdlen+12]>>4;
				tcp_hdlen*=4;
				int payload_size = ip_totlen - ip_hdlen - tcp_hdlen;
				if(payload_size>16) payload_size = 16;
				if(payload_size) printf("data : \n");
				for(int i=0;i<payload_size;i++) {
					if(i==8) printf("| ");
					printf("%02x ",packet[14+ip_hdlen+tcp_hdlen+i]);
				}
				if(payload_size) printf("\n");
			}
		}
		printf("\n");
	}



	pcap_close(handle);
	return 0;
}
