#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

void pcap_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
    if(packet == NULL)
    {/* dinna work *sob* */
        printf("Didn't grab packet\n");
    }


    struct ether_header *eptr;  /* net/ethernet.h */
    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    /* Do a couple of checks to see what packet type we have..*/
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));

    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));

    }else {
    //    printf("Ethernet type %x not IP\n", ntohs(eptr->ether_type));
        //skip these for now
        return;

    }
    /*  struct pcap_pkthdr {
     *   struct timeval ts;   time stamp
     *   bpf_u_int32 caplen;  length of portion present
     *   bpf_u_int32;         lebgth this packet (off wire)
     *  }
     */
    printf("Grabbed packet of length %d\n",pkthdr->len);
    printf("Recieved at ..... %s\n",ctime((const time_t*)&pkthdr->ts.tv_sec));
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);


    u_char *ptr; /* printing out hardware header info */
    /* copied from Steven's UNP */
    ptr = eptr->ether_dhost;
    int i = ETHER_ADDR_LEN;
    printf(" Destination Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);

    }while(--i>0);
    printf("\n");

    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);

    }while(--i>0);
    printf("\n");

}


int main(int argc, char * argv[]) {
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */

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
