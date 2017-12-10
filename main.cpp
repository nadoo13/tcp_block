#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>

int failure(char word[],int n);
int KMP(char sentence[], char word[], int len);

unsigned int checksum(const u_char *buf, unsigned size) {
	unsigned int sum = 0;
	int i;
	
	for (i=0;i<size-1;i+=2) {
		sum += (buf[i]<<8) + buf[i+1];
	}
	
	if(size &1) {
		sum+=buf[i];
	}
	
	return sum;
}
void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void print_ip(const u_char *ip_addr) {
	int i;
	for(i=0;i<4;i++) {
		printf("%d%c",ip_addr[i],i==3?'\n':'.');
	}
}

void print_mac(const u_char *mac_addr) {
	int i;
	for(i=0;i<6;i++) {
		printf("%02x%c",mac_addr[i],i==5?'\n':':');
	}
}

void print_packet(const u_char *packet,int size) {
	int i;
	for(i=0;i<size;i++) {
		printf("%02x%s",packet[i],i%16==15?"\n":i%8==7?"  ":" ");
	}
	printf("\n");
}

void input_arp(u_char *packet, const void *text,int t_size, int *p_pos) {
	memcpy(packet+*p_pos,text,t_size);
	*p_pos+=t_size;
}


int getIPnMACaddr(char *interface, u_char *ip_addr, u_char *mac_addr) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	u_char *mac = NULL;
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("no socket\n");
		return 0;
	}

	strcpy(ifr.ifr_name, interface);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) { //get IP address
		printf("getIP failed\n");
		//close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	/*
	uint32_t temp;
	memcpy(&temp, (const void *)(&(sin->sin_addr)),4);
	memcpy(ip_addr,(const void *)&temp,4);	*/
	memcpy(ip_addr, (const void *)(&(sin->sin_addr)),4);
	
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) { //get MAC address
		printf("getMAC failed\n");
		//close(sock);
		return 0;
	}
	mac = (u_char *)ifr.ifr_hwaddr.sa_data;
	memcpy(mac_addr,mac,6);
	
	//close(sock);
	return 1;
}
char text403[] = "HTTP/1.1 404 Not Found\r\nContetn-Type: text/html; charset=UTP-8\r\nReferrer-Policy: no-referrer\r\nContetn-Length: 1561\r\nDate: Tue, 05 Dec 2017 12:15:36 GMT\r\n\r\n<!DOCTYPE html>\r\n<html lang=en>\r\n  <meta charset=utf-8>\r\n  <meta name=viewport content=\"initial-scale=1, minimum-scale=1, width=device-width\">\r\n  <style>\r\n    *{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7\% auto 0;max-width:390px;min-height:180px;pa";
char text404[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=us-ascii\r\nServer: Microsoft-HTTPAPI2.0\r\nDate: Tue, 05 Dec 2017 12:26:50 GMT\r\nConnection: close\r\nContent-Length: 9\r\n\r\nNOT FOUND";
int make_fake_packet_tcp(pcap_t *handle, const u_char *packet,int size,int ip_offset, int tcp_offset, u_char *my_MAC, u_char *my_IP,int isHTTP) {
	int i,j;
	int b_size = size;
	memcpy(my_MAC, "\x12\x34\x56\x78\x90\x12",6);
	if(packet[tcp_offset+13]&(1<<2)) return 2;
	u_char *forward, *backward;
	forward = (u_char *)malloc(size);
	if(isHTTP) {
		backward = (u_char *)malloc(size + strlen(text404));
		b_size +=strlen(text404);
	}
	else backward = (u_char *)malloc(size);
	memcpy(forward, packet, size);
	memcpy(backward, packet, size);

	forward[ip_offset+2] = 0; //payload len
	backward[ip_offset+2] = 0;
	forward[ip_offset+3] = size - ip_offset; 
	if(isHTTP) {
		backward[ip_offset+2] = (size - ip_offset+strlen(text404))/256;
		backward[ip_offset+3] = (size - ip_offset+strlen(text404))%256;
	}
	else backward[ip_offset+3] = size - ip_offset;
	
	forward[tcp_offset + 14] = 0;//window size
	forward[tcp_offset + 15] = 0;
	backward[tcp_offset + 14] = 0;
	backward[tcp_offset + 15] = 0;

	forward[tcp_offset + 16] = 0;//checksum 0
	forward[tcp_offset + 17] = 0;
	backward[tcp_offset + 16] = 0;
	backward[tcp_offset + 17] = 0;

	if(isHTTP) {
		forward[tcp_offset+13]|=(1<<2) + (1<<4);//Reset +Ack
		backward[tcp_offset+13]|=1; // Fin
		memcpy(backward + size, text404, strlen(text404));
	} else {
		forward[tcp_offset+13]|=(1<<2) + (1<<4);//Reset +Ack
		backward[tcp_offset+13]|=(1<<2) + (1<<4);
	}

	for(i=0;i<6;i++) {
		forward[i+6] = my_MAC[i];
		backward[i] = packet[i+6];
//		backward[i+6] = packet[i];
		backward[i+6] = my_MAC[i];
	}
	for(i=0;i<4;i++) {
		backward[i+ip_offset+12] = packet[i+ip_offset+16];
		backward[i+ip_offset+16] = packet[i+ip_offset+12];
	}
	for(i=0;i<2;i++) {
		backward[i+tcp_offset] = packet[i+tcp_offset+2];
		backward[i+tcp_offset+2] = packet[i+tcp_offset];
	}
	u_char ph[12] ={0};
	unsigned int cs = checksum(forward+tcp_offset, size-tcp_offset);
	memcpy(ph, packet + ip_offset + 12, 8);
	ph[9] = 6;
	ph[11] = size-tcp_offset;
	cs += checksum(ph,12);	
	while(cs>>16) cs = (cs & 0xffff) + (cs>>16);
	cs = ~cs;
	forward[tcp_offset+16] = cs >> 8;
	forward[tcp_offset+17] = cs&0xff;
	cs = checksum(backward+tcp_offset, b_size-tcp_offset);
	cs += checksum(ph,12);	
	while(cs>>16) cs = (cs & 0xffff) + (cs>>16);
	cs = ~cs;
	backward[tcp_offset+16] = cs >> 8;
	backward[tcp_offset+17] = cs&0xff;
	
	if(pcap_sendpacket(handle, forward, size)) {
		printf("error with sending forward packet\n");
		return 0;
	}
	if(pcap_sendpacket(handle,backward,b_size)) {
		printf("error with sending backward packet\n");
		return 0;
	}
	return 1;
}

int check_http(const u_char packet[], int size) {
	char set[][10] = {"GET","HEAD","POST","PUT","DELETE","CONNECT","OPTIONS","TRACE","PATCH"};
	int i;
	for(i=0;i<9;i++) if(KMP((char *)packet,set[i],size)!=-1) return 1;
	return 0;
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
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	u_char my_MAC[6], my_IP[4];
	if(!getIPnMACaddr(dev, my_IP, my_MAC)) {
		printf("error!\n");
		return 0;
	}

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
		print_mac(packet+6);
		printf("dest MAC : ");
		print_mac(packet);
		uint16_t eth_type = (packet[12]<<8) + packet[13];
		printf("type : %04x\n",eth_type);

		if(eth_type == 0x0800) {
			int ip_offset = 14;
			
			printf("src IP : ");
			print_ip(packet+ip_offset+12);
			printf("dest IP : ");
			print_ip(packet+ip_offset+16);
			uint8_t ip_hdlen = packet[ip_offset]&0x0f;
			if(ip_hdlen<5)ip_hdlen = 5;
			ip_hdlen*=4;
			uint16_t ip_totlen = (packet[ip_offset+2]<<8) + packet[ip_offset+3];
			uint8_t IP_prot = packet[ip_offset+9];

			if(IP_prot != 0x06) continue;
			int tcp_offset = ip_offset+ip_hdlen;
			uint16_t srcPort, destPort;
			printf("src Port : %d\n",srcPort=(packet[tcp_offset]<<8) + packet[tcp_offset+1]);
			printf("dest Port : %d\n",destPort=(packet[tcp_offset+2]<<8) + packet[tcp_offset+3]);
			uint16_t tcp_hdlen = packet[tcp_offset+12]>>4;
			tcp_hdlen*=4;
			if(ip_totlen - tcp_offset-tcp_hdlen > 10 && check_http(packet+tcp_offset+tcp_hdlen,10)) {
				printf("\n\n\n\n\nit\'s http!\n\n\n\n");
				if(!make_fake_packet_tcp(handle,  packet, tcp_offset + tcp_hdlen, ip_offset, tcp_offset,my_MAC,my_IP,1)) {
					printf("error with send fake HTTP packet\n");
					return 0;
				}
			} else if(!make_fake_packet_tcp(handle,  packet, tcp_offset + tcp_hdlen, ip_offset, tcp_offset,my_MAC,my_IP,0)) {
				printf("error with send fake packet\n");
				return 0;
			}
			else printf("send packet2\n");
		}
		printf("\n");
	}



	pcap_close(handle);
	return 0;
}




int fail[700];

int failure(char word[],int n) {
	int i=0,j=-1;
	for(i=0;i<n;i++) fail[i] = -1;
	i=1;
	fail[0]=-1;
	while(i<n) {
		if(word[fail[i]+1]==word[i+1]) {
			j++;
			fail[i] = j;
			i++;
		} else if(j>-1) j=fail[j];
		else {
			i++;
		}
	}
	return 0;	
}

int KMP(char sentence[], char word[], int len) {
	failure(word,strlen(word));
	int i=0,j=-1;
	int word_len = strlen(word);
	for(i=0;i<len;i++) {
		//printf("%d %d\n",i,j);
		j++;
		if(sentence[i] == word[j]) {
			if(j==word_len-1) return i-j;
		}
		else j = fail[j];
	}
	return -1;
}
