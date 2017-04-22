#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <memory.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "stdio.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000 
#define UDP_PORT 55555
#define TCP_PORT 11111
/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define KEY_LEN 16
#define AU_LEN 14
#define SHA256_LEN 32

/*Definiton for Authentication*/
#define CERTF "./ca/client.crt"
#define KEYF "./ca/client.key"
#define CACERT "./ca/ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/*************************************************************************
 * To get random IV 
**************************************************************************/
unsigned char* getRandom() {
    unsigned char* ret = (unsigned char *)malloc(sizeof(unsigned char)*KEY_LEN);
    FILE* random = fopen("/dev/urandom","r");
    fread(ret, sizeof(unsigned char)*KEY_LEN, 1, random);
    fclose(random);
    return ret;
}

/**************************************************************************
 * Encrypt the buffer with Sha alogrithm.                         
***************************************************************************/
int do_crypt(unsigned char *key, unsigned char *iv, unsigned char* plaintext, int inlen, unsigned char *encrypttext, int do_encrypt) {
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        unsigned char outbuf[1024];
        EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);
        int outlen, tmplen;
        if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, plaintext, inlen))
        {
            /* Error */
            return 0;
        }
         /* Buffer passed to EVP_EncryptFinal() must be after data just
         * encrypted to avoid overwriting it.
         */
        if(!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
        {
            /* Error */
            return 0;
        }
        outlen += tmplen;
        EVP_CIPHER_CTX_cleanup(&ctx);
        memcpy(encrypttext, outbuf, outlen);
        return outlen;
}
/**************************************************************************
   MAC 
***************************************************************************/
int do_hmac(unsigned char *key, unsigned char *plaintext, int inlen, unsigned char *outbuf)
{
        int outlen;
        HMAC_CTX mdctx;
        HMAC_CTX_init(&mdctx);
        HMAC_Init_ex(&mdctx,key, KEY_LEN, EVP_sha256(),NULL);
        HMAC_Update(&mdctx,plaintext,inlen);
        HMAC_Final(&mdctx,outbuf,&outlen);
        HMAC_CTX_cleanup(&mdctx);
        return outlen;

}


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * StartAuthentication: Use TCP + SSL for server and client authentication 
 **************************************************************************/
int StartAuthentication(const char *ip, const unsigned char *key, const unsigned char *iv) {
	int err;
  	int sd;
  	struct sockaddr_in sa;
 	SSL_CTX* ctx;
  	SSL*     ssl;
  	X509*    server_cert;
  	char*    str;
  	char*    buf;
	int buf_len;
  	const SSL_METHOD *meth;

  	SSLeay_add_ssl_algorithms();
  	meth = SSLv23_client_method();
  	SSL_load_error_strings();
  	ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);	
	CHK_SSL(err);
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  	SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
	
	/* ----------------------------------------------- */
 	/* Create a tcp socket, connect to server using normal socket calls. */ 
  	sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
  	memset (&sa, '\0', sizeof(sa));
  	sa.sin_family      = AF_INET;
  	sa.sin_addr.s_addr = inet_addr(ip);   /* Server IP */
  	sa.sin_port = htons(TCP_PORT);          /* Server Port number */
	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));         
	CHK_ERR(err, "connect");
	 /* Now we have TCP conncetion. Start SSL negotiation. */
  
 	ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  	SSL_set_fd (ssl, sd);
  	err = SSL_connect (ssl);                     CHK_SSL(err);
	 /* Then we need to check the name of common name*/
	server_cert = SSL_get_peer_certificate (ssl);
	CHK_NULL(server_cert);
 	printf ("Server certificate:\n");
	str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  	CHK_NULL(str);
	char *common_name = "IS";
//	printf("%s \n", str);
	if(strstr(str, common_name) == NULL) {
		return 0;  // Failed on the CommonName Test
	}
	printf("CommmonName Test Passed. \n");
  	OPENSSL_free (str);
	str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  	CHK_NULL(str);
  	if (memcmp(common_name, str, strlen(str)) == 0) {
		return 0;  // Failed on the CommonName Test
	}
  	OPENSSL_free (str);
	/* DATA EXCHANGE - Send a message and receive a reply. */
	unsigned char *username;
	unsigned char *password;
	username = malloc(AU_LEN);  // seed
	password = malloc(AU_LEN);  // dees
	buf = malloc(BUFSIZE);
	printf("Please enter the username: ");
	scanf("%s", username);
	password = getpass("Please enter the password: ");	
	memcpy(buf, username, AU_LEN);
	memcpy(buf + AU_LEN, password, AU_LEN);
	memcpy(buf + 2 * AU_LEN, key, KEY_LEN);
	memcpy(buf + 2 * AU_LEN + KEY_LEN, iv, KEY_LEN);
	buf_len = 2 * AU_LEN + 2 * KEY_LEN;
	err = SSL_write (ssl, buf, buf_len);

	CHK_SSL(err);
	memset(buf, 0, BUFSIZE); 
	memset(username, 0, AU_LEN);
	memset(password, 0, AU_LEN);
  	err = SSL_read (ssl, buf, sizeof(buf) - 1);       CHK_SSL(err);
	
	char *au_msg = "Failed";
	if (memcmp(au_msg, buf, strlen(au_msg)) == 0) {
		 close (sd);
  		 SSL_free (ssl);
  		 SSL_CTX_free (ctx);
		 return 0;
	}

//	printf("%s", buf);
	printf("\n");
	printf("User Authentication Test Passed.\n");
	close (sd);
        SSL_free (ssl);
        SSL_CTX_free (ctx);
	return 1;
}
void StartClient(const char *ip, unsigned char *key, unsigned char* iv) {
	struct sockaddr_in server;
	struct sockaddr_in client;
	socklen_t clientlen;
	socklen_t serverlen;
	char buffer[BUFSIZE];
	int flags = IFF_TUN;
	//unsigned char *iv;
	//unsigned char *key;	
	int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset((char*)&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_port = htons(UDP_PORT);
	serverlen = sizeof(server);
	int tap_fd, ret, maxfd;
	fd_set rd_set;
	char  if_name[IFNAMSIZ] = "tun0";
	memset((char*)&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_ANY);
	client.sin_port = htons(UDP_PORT);
	clientlen = sizeof(client);
	// Create the TUN Interface if you are first in it
	if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
	    perror("Error connecting to TUN/TAP Interface");
	    exit(1);
	}
	if (bind(sock_fd, (struct sockaddr *)&client, sizeof(client)) < 0) {
	    perror("ERROR ON binding");
	}
	//  Send the packetout
	char *data = "Hello Server";
	sendto(sock_fd, data, strlen(data), 0, (struct sockaddr *)&server, serverlen);
	// use select to handle two descriptiors
	unsigned char *cryptbuffer, *plainbuffer, *hmacbuffer, *tempbuffer;
	cryptbuffer = malloc(BUFSIZE);
	plainbuffer = malloc(BUFSIZE);
	tempbuffer = malloc(BUFSIZE);
	hmacbuffer = malloc(BUFSIZE);
	//iv = malloc(KEY_LEN);
	//key = malloc(KEY_LEN);
	// Initialize the key and iv
	/*int start;
	for (start = 0; start < 16; start++) {
		key[start] = 'a' + start;
		iv[start] = 'a' + start;
	}*/
	int cryptlen, plainlen, buffer_len;
	maxfd = (tap_fd > sock_fd)? tap_fd:sock_fd;
	printf("key:");
       
	//Send and receive packets
	while(1) {
		FD_ZERO(&rd_set);
		FD_SET(sock_fd, &rd_set);
		FD_SET(tap_fd, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (ret < 0 && errno == EINTR)  continue;      
        	if (ret < 0) {
            	    perror("select()");
            	    exit(1);
        	}
		if (FD_ISSET(tap_fd, &rd_set)) {
	        // Server, Data is from tun/tap, read it and write it to the network
		    plainlen = read(tap_fd, buffer, sizeof(buffer));
		// Encrypt
		    cryptlen = do_crypt(key, iv, buffer, plainlen, cryptbuffer, 1);
		    memcpy(tempbuffer, iv, KEY_LEN);
		    memcpy(tempbuffer + KEY_LEN, cryptbuffer, cryptlen);
		    do_hmac(key, tempbuffer, KEY_LEN + cryptlen, hmacbuffer);
		    memcpy(buffer, iv, KEY_LEN);
		    memcpy(buffer + KEY_LEN, cryptbuffer, cryptlen);
		    memcpy(buffer + KEY_LEN + cryptlen, hmacbuffer, SHA256_LEN);
		    buffer_len = KEY_LEN + cryptlen + SHA256_LEN;	
		 
		// Print the Encrypt data
		// Send the encrypted message to ethernet	    
		    if (sendto(sock_fd, buffer, buffer_len, 0, (struct sockaddr *)&server, serverlen) < 0) perror("send to Network, dest: Server");
		// Clean the buffer
		    memset(buffer, 0, BUFSIZE); 
		    memset(tempbuffer, 0, BUFSIZE);
		    memset(cryptbuffer, 0, BUFSIZE);
		    memset(hmacbuffer, 0, BUFSIZE);
		} 
	        if (FD_ISSET(sock_fd, &rd_set)) {
		// Server, Data is from socket, read it and write it to the tun0
		cryptlen = recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&server, &serverlen);
		// Check the integrity
		memcpy(cryptbuffer, buffer, cryptlen);
		memcpy(iv, buffer, KEY_LEN);
		do_hmac(key, cryptbuffer, cryptlen - SHA256_LEN, hmacbuffer);
		if (memcmp(hmacbuffer, cryptbuffer + cryptlen - SHA256_LEN, SHA256_LEN) == 0) {
		    // decyrpt the message and sent it to socket
		    plainlen = do_crypt(key, iv, cryptbuffer + KEY_LEN, cryptlen - KEY_LEN - SHA256_LEN, tempbuffer, 0);
		    if (write(tap_fd, tempbuffer, plainlen) < 0) perror("write in TUN");
		}
		}
	}
	exit(1);
}

int main(int argc, char *argv[]) {
	//Directly Start Our Server.
	if (argc != 2) {
	    printf("Please type in the hostname");
	}
	char *server_ip;
	struct hostent *serverHost;
	//char server_ip[16] = "";
	/*Get the ip by host name*/
	serverHost = gethostbyname(argv[1]);
	if (serverHost == NULL) {
		printf("There no such hostname");
	} else {
		server_ip = inet_ntoa(*((struct in_addr *)serverHost->h_addr));
	}
	//strncpy(server_ip, argv[1], 15)
	unsigned char *key;
	key = malloc(KEY_LEN);
	unsigned char *iv;
	iv = malloc(KEY_LEN);
	key = getRandom();
	iv = getRandom();
//	printf("%s", server_ip);
	int flag = StartAuthentication(server_ip, key, iv);
	if (flag == 0) {  // Authentication Failed
		printf("Authentication Failed");
		return 0;
	}
	printf("Authentication Succeed");
	
	pid_t pid = fork();
	pid_t wpid;
	int status;
	if (pid == 0) {  // Child Process	
		StartClient(server_ip, key, iv);
	} 
	while ( ( wpid = wait ( &status ) ) > 0 );
	return 0;
}
