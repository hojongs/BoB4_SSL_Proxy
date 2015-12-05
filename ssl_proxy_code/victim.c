//victim.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
#define LINE    100

int OpenConnection(const char *hostname, int port)
{
	int client_sock;
	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
		abort();
	}
	client_sock = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(client_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(client_sock);
		perror(hostname);
	}
	return client_sock;
}

SSL_CTX* InitCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = TLSv1_2_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
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

int main(int argc, char *args[])
{
	int client_sock;
	SSL_CTX *ctx;
	SSL *ssl;
	char buf[65535];
	int bytes;
	char *hostname, *portnum;
	char getmsg[LINE][65535];
	char msg[65535];
	int i, j;
	int len;

	if ( argc != 3 )
	{
		printf("usage: %s <hostname> <portnum>\n", args[0]);
		exit(0);
	}

	SSL_library_init();
	hostname=args[1];
	portnum=args[2];

	ctx = InitCTX();
	client_sock = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_sock);
	if ( SSL_connect(ssl) == FAIL )
		ERR_print_errors_fp(stderr);
	else
	{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);

		while(1)
		{
		   memset(msg, 0, strlen(msg));
		   printf("\nInput(or exit) : \n");
		   for(i=0;i<LINE;i++)
		   {
			memset(getmsg[i], 0, strlen(getmsg[i]));
			fgets(getmsg[i], 65535, stdin);
			getmsg[i][strlen(getmsg[i])-1]='\0';
			if(strlen(getmsg[i])==0)
				break;
			len=strlen(getmsg[i]);
			getmsg[i][len]='\r';
			getmsg[i][len+1]='\n';
		}


		strcpy(msg, getmsg[0]);
		for(j=1;j<i;j++)
		{
			strcat(msg, getmsg[j]);
		}
		len=strlen(msg);
		msg[len]='\r';
		msg[len+1]='\n';
		
		printf("msg : %s\n", msg);
		SSL_write(ssl, msg, strlen(msg));
		if(strcmp(msg, "exit\r\n\r\n")==0)
		{
			SSL_free(ssl);
			break;
		}
		bytes = SSL_read(ssl, buf, sizeof(buf));
		buf[bytes] = 0;
		printf("\nResponse:\n");
		printf("**************************************************\n");
		printf("%s\n", buf);
		printf("**************************************************\n\n");
	}
}
close(client_sock);
SSL_CTX_free(ctx);
return 0;
}
