// vim: set noet;
#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unordered_map>
#include <signal.h>


#define UNUSED __attribute__((unused))

struct IpV4Key
{
	uint32_t sip;
	uint16_t sport;
	uint32_t dip;
	uint16_t dport;
	uint16_t proto;
	bool operator==(const IpV4Key &other) const
	{ return (sip == other.sip && sport == other.sport &&dip == other.dip && dport == other.dport && proto == other.proto);
	}

};

namespace std {
	template <>
		struct hash<IpV4Key>
		{
			std::size_t operator()(const IpV4Key& k) const
			{
				using std::size_t;
				using std::hash;
				using std::string;

				// Compute individual hash values for first,
				// second and third and combine them using XOR
				// and bit shifting:

				return (((((hash<uint32_t>{}(k.sip) ^ (hash<uint16_t>{}(k.sport) << 1)) >> 1) ^
								(((hash<uint32_t>{}(k.dip) ^ (hash<uint16_t>{}(k.dport) << 1)) >> 1) <<1)) >> 1) ^
						(hash<uint16_t>{}(k.proto) <<1 ) ) >>1;
			}
		};


}
struct ConnectionState {
	unsigned int cid ;
	unsigned int sent;
	unsigned int received;
	time_t last_access;

};
typedef unsigned int session_id_t;

static session_id_t g_session_id =0 ;
static unsigned int sessions =0;

static std::unordered_map<IpV4Key, unsigned int> connIdLookup;
static std::unordered_map<unsigned int,ConnectionState> connTable;

static ConnectionState & getConnectionState(const IpV4Key & key,const IpV4Key & rkey,session_id_t & cid, bool & isNew, bool & isReversed ) {
	isNew = false;
	isReversed= false;
	if (0 == connIdLookup.count(key)) {
		if (0 != connIdLookup.count(rkey)) {
			cid = connIdLookup[rkey];
			isReversed =true;
		}
		else {
			isNew = true;
			cid = g_session_id++;
			connIdLookup[key] = cid;
			connTable[cid].cid =cid;
			sessions ++;
		}
	}
	else {
		cid = connIdLookup[key];
	}
	return connTable[cid];
}
void printIpV4Key(const IpV4Key & key,const session_id_t cid) {
	const char * protoStr;
	switch (key.proto) {
		case IPPROTO_TCP:
			protoStr = "TCP";
			break;
		case IPPROTO_UDP:
			protoStr = "UDP";
			break;
		default:
			protoStr = "unknown";
			break;
	}
	struct in_addr ip_addr;
     ip_addr.s_addr = key.sip;
	 printf("%s ds=%s:%d->",protoStr, inet_ntoa(ip_addr), ntohs(key.sport));
     ip_addr.s_addr = key.dip;
	printf("%s:%d session %u", inet_ntoa(ip_addr), ntohs(key.dport),cid);
}

#define MAX_INACTIVE 18
static void expireInactive() {
	time_t now = time(NULL);
	for (auto itr = connIdLookup.begin(); itr != connIdLookup.end();) {
		unsigned int cid = itr->second;
		if ((now - connTable[cid].last_access) > MAX_INACTIVE ) {
			sessions --;
			printIpV4Key(itr->first, cid);
			printf(" session %d done (Total sessions %u)\n", cid ,sessions);
			connTable.erase(cid);
			itr = connIdLookup.erase(itr);

		}
		else {
			itr++;
		}
	}
}
static void pcap_callback(UNUSED u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
	unsigned int remaining = pkthdr->caplen;
	if(packet == NULL) {/* dinna work *sob* */
		return;
	}
	if (remaining < sizeof(struct ether_header)) {
		printf("snap_len too small for either\n");
		return;
	}
	struct ether_header *eptr;  /* net/ethernet.h */
	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;

	/* Do a couple of checks to see what packet type we have..*/
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
		//printf("Ethernet type hex:%x dec:%d is an IP packet\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
		;
	}else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
		//printf("Ethernet type hex:%x dec:%d is an ARP packet\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
		return;
	}else {
		return;
	}
	struct ip *ipp =(struct ip *) (eptr +1);
	bool isNew;
	bool isReversed;
	session_id_t cid;
	if (ipp->ip_p ==IPPROTO_TCP ) {
		struct tcphdr * tcpp = (struct tcphdr *) (((char *)ipp) + (ipp->ip_hl << 2 ));
		IpV4Key key = {ipp->ip_src.s_addr,tcpp->source, ipp->ip_dst.s_addr, tcpp->dest, ipp->ip_p};
		IpV4Key rkey = {ipp->ip_dst.s_addr, tcpp->dest,ipp->ip_src.s_addr,tcpp->source,  ipp->ip_p};
		ConnectionState &state = getConnectionState(key,rkey, cid, isNew, isReversed);
		state.last_access = time(NULL);
		printIpV4Key(key, cid);
		printf("\n");
	} else if (ipp->ip_p ==IPPROTO_UDP ) {
		struct udphdr * udpp = (struct udphdr *) (((char *)ipp) + (ipp->ip_hl << 2 ));
		IpV4Key key = {ipp->ip_src.s_addr,udpp->source, ipp->ip_dst.s_addr, udpp->dest, ipp->ip_p};
		IpV4Key rkey = {ipp->ip_dst.s_addr, udpp->dest,ipp->ip_src.s_addr,udpp->source,  ipp->ip_p};
		ConnectionState &state = getConnectionState(key,rkey, cid, isNew, isReversed);
		state.last_access = time(NULL);
		printIpV4Key(key, cid);
		printf("\n");
	}


}

int done =0;
void sigterm(UNUSED int sig) {
	done =1;
}

int main(UNUSED int argc,UNUSED  char * argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;

	descr = pcap_open_live("wlan0",10*1024,0,1000,errbuf);

	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);

	}
	signal(SIGTERM, sigterm);

	while (0 == done) {
		struct pcap_pkthdr pkthdr;
		const u_char *packet = pcap_next(descr, &pkthdr);
		if (packet) {
			pcap_callback(NULL, &pkthdr, packet);
		}
		else  {
			expireInactive();
		}
	}
	pcap_close(descr);
	return 0;
}
