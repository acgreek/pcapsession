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
    unsigned int sent;
    unsigned int received;
    time_t last_access;

};

static unsigned int g_session_id =0 ;

std::unordered_map<IpV4Key, unsigned int> connIdLookup;
std::unordered_map<unsigned int,ConnectionState> connTable;


void pcap_callback(UNUSED u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
    unsigned int remaining = pkthdr->caplen;
    if(packet == NULL) {/* dinna work *sob* */
        printf("Didn't grab packet\n");
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
        printf("Ethernet type hex:%x dec:%d is an IP packet\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
        //printf("Ethernet type hex:%x dec:%d is an ARP packet\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
        return;
    }else {
        return;
    }
    struct ip *ipp =(struct ip *) (eptr +1);
    if (ipp->ip_p ==IPPROTO_TCP ) {
        struct tcphdr * tcpp = (struct tcphdr *) (((char *)ipp) + (ipp->ip_hl << 2 ));
        printf("tcp ds=%s:%d->", inet_ntoa(ipp->ip_src), ntohs(tcpp->source));
        printf("%s:%d\n", inet_ntoa(ipp->ip_dst), ntohs(tcpp->dest));
        IpV4Key key = {ipp->ip_src.s_addr,tcpp->source, ipp->ip_dst.s_addr, tcpp->dest, ipp->ip_p};
        unsigned int cid;
        if (0 == connIdLookup.count(key)) {
            cid = g_session_id++;
            connIdLookup[key] = cid;
        }
        else {
            cid = connIdLookup[key];
            connIdLookup[key] = cid;
        }
        ConnectionState &state = connTable[cid];
        state.last_access = time(NULL);
    } else if (ipp->ip_p ==IPPROTO_UDP ) {
        struct udphdr * udpp = (struct udphdr *) (((char *)ipp) + (ipp->ip_hl << 2 ));
        printf("udp ds=%s:%d->", inet_ntoa(ipp->ip_src), ntohs(udpp->source));
        printf("%s:%d\n", inet_ntoa(ipp->ip_dst), ntohs(udpp->dest));
        IpV4Key key = {ipp->ip_src.s_addr,udpp->source, ipp->ip_dst.s_addr, udpp->dest, ipp->ip_p};
        unsigned int cid;
        if (0 == connIdLookup.count(key)) {
            cid = g_session_id++;
            connIdLookup[key] = cid;
        }
        else {
            cid = connIdLookup[key];
            connIdLookup[key] = cid;
        }
        ConnectionState &state = connTable[cid];
        state.last_access = time(NULL);
    }


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


    /*
     *        grab a packet from descr (yay!)
     *               u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h)
     *                      so just pass in the descriptor we got from
     *                             our call to pcap_open_live and an allocated
     *                                    struct pcap_pkthdr                                 */


	pcap_loop(descr, -1, pcap_callback, 0);
    return 0;
}
