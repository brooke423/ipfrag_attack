#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <string.h>
#include "m_pcap.h"

extern pid_t g_pid;
extern int   g_seq;
extern int   g_ack;
extern unsigned int g_dsthost;
extern unsigned short g_port;

char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};
void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    //printf("----------------------------------------------\n");
    //printf("Packet length: %d \n",header->len);
    if(header->len>=14){
        struct tcphdr *tcp = (struct tcphdr *)(pkt_data+34);
        g_ack = ntohl(tcp->ack_seq);

        /*found the synack*/
        if(tcp->dest == htons(g_pid) && g_ack == g_pid+1){
            g_seq = ntohl(tcp->seq);
            printf("found!!!!!!!!!!!!!!!!!!!!!!!! seq=%x ack=%x\n",g_seq,g_ack);
        }
    }
}

void * pcap_entry(void *arg) 
{
    char *device="eth0";
    char errbuf[1024];
    pcap_t *phandle;

    bpf_u_int32 ipaddress,ipmask;
    struct bpf_program fcode;
    int datalink;

    if((device=pcap_lookupdev(errbuf))==NULL){
        perror(errbuf);
        return 1;
    }
    else
        printf("device: %s\n",device);

    phandle=pcap_open_live(device,200,0,500,errbuf);
    if(phandle==NULL){
        perror(errbuf);
        return 1;
    }

    if(pcap_lookupnet(device,&ipaddress,&ipmask,errbuf)==-1){
        perror(errbuf);
        return 1;
    }
    else{
        char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
            perror("inet_ntop error");
        else if(inet_ntop(AF_INET,&ipmask,mask,sizeof(mask))==NULL)
            perror("inet_ntop error");
        printf("IP address: %s, Network Mask: %s\n",ip,mask);
    }

    char filter_cmd[256];
    struct in_addr dest;
    dest.s_addr = g_dsthost;
    snprintf(filter_cmd,256,"host %s and port %d",inet_ntoa(dest),g_port);
        
    if(pcap_compile(phandle,&fcode,filter_cmd,0,ipmask)==-1)
        fprintf(stderr,"pcap_compile: %s,please input again....\n",pcap_geterr(phandle));

    if(pcap_setfilter(phandle,&fcode)==-1){
        fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(phandle));
        return 1;
    }

    if((datalink=pcap_datalink(phandle))==-1){
        fprintf(stderr,"pcap_datalink: %s\n",pcap_geterr(phandle));
        return 1;
    }

    printf("datalink= %d\n",datalink);

    pcap_loop(phandle,-1,pcap_handle,NULL);
    
    return 0;
}
