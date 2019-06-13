#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <cstring>

template <typename T>
inline void print(T* container, size_t size) {
	
	for (size_t i = 0; i < size; ++i) {
		
		std::cout << container[i];
	}
	std::cout << std::endl;
}

const size_t ethernetAdressLen = 6;

struct EthernetHeader {

	u_char destinationAdress[ethernetAdressLen];
	u_char sourceAdress[ethernetAdressLen];
	u_short etherType;
};

void printInHex(const u_char* container, size_t size) {

	for (size_t i = 0; i < size; ++i) {

		if (i == size - 1) {

			printf("%02x ", container[i]);
			break;
		}

		printf("%02x:", container[i]);
	}
}

size_t digitLen(u_short number) {

	if (number == 0)
		return 0;

	return 1 + digitLen(number / 10);
}

enum Ipflags
{
	RF = 0x8000,
	DF = 0x4000,
	MF = 0x2000,
	OFFMASK = 0x1fff
};

struct IpHeader
{
	u_char getLenth() const { return this->versionAndLength & 0x0f; }

	u_char versionAndLength;
	u_char serviceType;
	u_short length;
	u_short id;
	u_short fragmentOffset;
	u_char ttl;
	u_char protocol;
	u_short checksum;
	u_int source;
	u_int destination;
};

void printIP(u_int ip) 
{
	u_char bytes[4];
	bytes[0] = ip & 0xff;
	bytes[1] = (ip >> 8) & 0xff;
	bytes[2] = (ip >> 16) & 0xff;
	bytes[3] = (ip >> 24) & 0xff;
	printf("%u.%u.%u.%u ", bytes[0], bytes[1], bytes[2], bytes[3]);
}

enum TcpFlags
{
	FIN = 0x01,
	SYN = 0x02,
	RST = 0x04,
	PSH = 0x08,
	ACK = 0x10,
	URG = 0x20,
	ECE = 0x40,
	CWR = 0x80
};

struct TcpHeader
{
	u_char getLength() const { return (this->lengthAndReserved & 0xf0) >> 4; }

	u_short sourcePort;
	u_short destinationPort;
	u_int sequenceNumber;
	u_int aknowledgement;
	u_char lengthAndReserved;
	u_char flags;
	u_short window;
	u_short checksum;
	u_short urgentPointer;
};

const char* checkFlags(u_char flags) 
{
	if ((flags & (1 << 0) >> 0) == FIN &&
		(flags & (1 << 1) >> 1) == 0x0 &&
		(flags & (1 << 2) >> 2) == 0x0 &&
		(flags & (1 << 3) >> 3) == PSH &&
		(flags & (1 << 4) >> 4) == 0x0 &&
		(flags & (1 << 5) >> 5) == URG &&
		(flags & (1 << 6) >> 6) == 0x0 &&
		(flags & (1 << 7) >> 7) == 0x0 ) {
		
		return "Xmas";
	}
	else if (flags == 0) {
		
		return "Null";
	}

	return "Normal";
}

void gotPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	
	const size_t ethernetSize = 14;

	const struct EthernetHeader* ethernet;
	ethernet = (struct EthernetHeader*)(packet);
	
	const struct IpHeader* ip;
	ip = (struct IpHeader*)(packet + ethernetSize);
	
	u_int sizeIp = ip->getLenth() * 4;
	if (sizeIp < 20) {
		
		printf("Invalid Ip header length: %u bytes\n", sizeIp);
		return;
	}

	const struct TcpHeader* tcp;
	tcp = (struct TcpHeader*)(packet + ethernetSize + sizeIp);

	u_int sizeTcp = tcp->getLength() * 4;
	if (sizeTcp < 20) {
		
		printf("Invalid Tcp header length: %u bytes\n", sizeTcp);
		return;
	}

	const char* tcpType = checkFlags(tcp->flags);

	if ( !strcmp("Null", tcpType) || !strcmp("Xmas", tcpType) ) {
		
		printInHex(ethernet->destinationAdress, sizeof(ethernet->destinationAdress));

		printInHex(ethernet->sourceAdress, sizeof(ethernet->sourceAdress));

		if (digitLen(ethernet->etherType) == 1)
			printf("Ox%02x00 ", ethernet->etherType);
		else
			printf("Ox%04x ", ethernet->etherType);

		printIP(ip->source);
		printIP(ip->destination);
		printf("%u ", ip->protocol);

		printf("%hu ", tcp->sourcePort);
		printf("%hu ", tcp->destinationPort);
		printf(tcpType);
		printf("\n");
	}

	const u_char* payload = packet + ethernetSize + sizeIp + sizeTcp;
}

int main() 
{
	size_t errorSize = PCAP_ERRBUF_SIZE;
	char* errorBuf = new(std::nothrow) char[errorSize];
	if (!errorBuf) {
		
		std::cerr << "Can`t alloc mem on line 7!\n";
		return -1;
	}

	const char* fileName = "C:/Users/User/source/repos/dom2NetworkSecurity/dom2NetworkSecurity/hw3_test.pcap";

	pcap_t* handler = pcap_open_offline(fileName, errorBuf);
	if (!handler) {
		
		std::cerr << "Couldn`t open file: " << fileName << " !\n";
		print<char>(errorBuf, errorSize);
		delete[] errorBuf;
		errorBuf = nullptr;
		return -2;
	}

	if (pcap_loop(handler, -1, gotPacket, nullptr) == PCAP_ERROR) {
		
		std::cerr << "Couldn`t read file: " << fileName << " !\n";
		print<char>(errorBuf, errorSize);
		delete[] errorBuf;
		errorBuf = nullptr;
		return -3;
	}

	pcap_close(handler);

	delete[] errorBuf;
	errorBuf = nullptr;

	return 0;
}