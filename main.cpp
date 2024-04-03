#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
//for getMAC, getIP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

//from "https://indienote.tistory.com/755"
int get_my_MAC(char* mac, char* dev) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        return 1;
    }

    unsigned char *tmp_mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
    printf("My MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           tmp_mac[0], tmp_mac[1], tmp_mac[2], tmp_mac[3], tmp_mac[4], tmp_mac[5]);

    for(int i = 0; i<6; i++){
    	mac[i] = tmp_mac[i];
    }

    close(sockfd);

    return 0;
}

//from "https://tjcplpllog.blogspot.com/2015/02/ip.html"
int get_my_IP(uint32_t *ip, char *dev){
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    struct ifreq ifr;
    struct sockaddr_in * sin;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        return 1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = htonl(sin->sin_addr.s_addr);

    close(sockfd);

    return 0;
}

void make_packet(EthArpPacket *packet, Mac smac_eth, Mac dmac_eth, Mac smac_ip, Mac tmac_ip, uint32_t sip, uint32_t tip, int r){
	packet.eth_.dmac_ = dmac_eth;
	packet.eth_.smac_ = smac_eth;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if(r){
		packet->arp_.op_ = htons(ArpHdr::Request);
	}
	else{
		packet->arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.arp_.smac_ = smac_ip;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac_ip;
	packet.arp_.tip_ = htonl(tip);
}

int send_packet(pcap_t* handle, EthArpPacket* packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 1;
	}
	return 0;
}

int receive_packet(pcap_t* handle, Mac* smac_ip, Mac tmac_ip, uint32_t sip, uint32_t tip) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while(1) {
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 1;
		}
		
		EthArpPacket* catched_packet = (EthArpPacket*)packet;
		
		if(ntohs(catched_packet->arp_.op_) != ArpHdr::Reply) continue;
		if(ntohl(catched_packet->arp_.sip_) != sip) continue;	
		if(ntohl(catched_packet->arp_.tip_) != tip) continue;
		for(int i=0; i<6; i++) {
			if(((uint8_t*)(catched_packet->arp_.tmac_))[i] != ((uint8_t*)tmac_ip)[i]){
				 continue;	
			}
		}
		*smac_ip = Mac(catched_packet->arp_.smac_); 
		break;
	}
	return 0;
}

int get_sender_MAC(pcap_t* handle, Mac my_mac, uint32_t my_ip, uint32_t sender_ip, Mac sender_mac_out){
	EthArpPacket tmp_packet;
	make_packet(&tmp_packet, my_mac, Mac("FF:FF:FF:FF:FF:FF"), my_mac, Mac("00:00:00:00:00:00"), my_ip, sender_ip, 1);

	//requst
	if(send_packet(handle, &tmp_packet)){
		printf("send error for get sender MAC");
		return 1;
	}

	//reply
	if(receive_packet(handle, sender_mac_out, my_mac, sender_ip, my_ip)){
		printf("receive error for get sender MAC");
		return 1;
	}

	return 0;
}

void print_MAC(Mac mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", ((char*)mac)[0], ((char*)mac)[1], ((char*)mac)[2], ((char*)mac)[3], ((char*)mac)[4], ((char*)mac)[5]);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char my_mac_str[6];
	memset(my_mac, 0, sizeof(my_mac));
	uint32_t my_ip = 0;
	Mac my_mac;

	//get my mac addr
	get_my_MAC(my_mac_str, dev);
	my_mac = Mac(my_mac_str);
	printf("my_mac : ");
	print_MAC(my_mac);

	//get my ip addr
	get_my_IP(&my_ip, dev);

	EthArpPacket packet;

	Mac sender_mac;
	uint32_t sender_ip;
	uint32_t target_ip;

	for(int i = 2; i<argc; i+=2){
		sender_ip = argv[i];
		target_ip = argv[i+1];


	}

	pcap_close(handle);
}
