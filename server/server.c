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
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <memory.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>       /* SSLeay stuff */
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
#define SHA256_LEN 32
#define AU_LEN 14

/* define HOME to be dir for key and cert files... */
#define HOME "./ca/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"
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
int do_hmac(unsigned char *key, unsigned char *plaintext, int inlen, unsigned char *outbuf) {
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
int authenticationHelper(char* buf, unsigned char *key, unsigned char* iv) {
	/*username,passwd,key*/
	unsigned char *username;
	unsigned char *passwd;
	int i;

	username = malloc(AU_LEN);
	passwd = malloc(AU_LEN);
	
	/*In the future, we could read the file from shadow*/
	unsigned char *shadow;
	shadow = malloc(32);
/*	char *temp;
	FILE *f = fopen("shadow", "r");
	size_t shadow_len;
	shadow = malloc(32);
	getline(&temp, &shadow_len, f);
	fclose(f);
	memcpy(shadow, temp, 32);*/
	shadow = "\xde\xad\x17\x35\x3d\x9c\xbb\x51\x4e\x3d\xd3\x7f\xb5\xd4\x90\xb9\xe5\x2f\x4d\xd9\x1f\xc8\x51\xcb\xb5\xbe\x04\x64\x6d\xbb\x54\x2f";
	unsigned char *hash_passwd;
	hash_passwd = malloc(EVP_MAX_MD_SIZE);

	memcpy(username, buf, AU_LEN);
	memcpy(passwd, buf + AU_LEN, AU_LEN);
	memcpy(key, buf + AU_LEN * 2, KEY_LEN);
	memcpy(iv, buf + AU_LEN * 2 + KEY_LEN, KEY_LEN);
//	printf("username: %s \n", username);
//	printf("passwd: %s \n", passwd);
	/*Hash the passwd with SHA256*/
	EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        int md_len;
	passwd = (unsigned char*)realloc(passwd, strlen(passwd));	
        OpenSSL_add_all_digests();
        md = EVP_get_digestbyname("sha256");
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, passwd, strlen(passwd));
        EVP_DigestFinal_ex(mdctx, hash_passwd, &md_len);
        EVP_MD_CTX_destroy(mdctx);
	
        /* Call this once before exit. */
        EVP_cleanup();	
	/*Compare the two hashvalue*/
/*	printf("Test: \n");
	for (i = 0; i < 32; i++) {
		printf("\\x%2x", hash_passwd[i]);
	}
	printf("\n");
	for (i = 0; i < 32; i++) {
		printf("%2x ", shadow[i]);
	}*/
//	return 1;
/*	unsigned char *hash_buffer;
	hash_buffer = malloc(EVP_MAX_MD_SIZE);
	for (i = 0; i < 32; i++) {
		sprintf(hash_buffer + i * 2, "02x", hash_passwd[i]);
	}*/
	if (memcmp(hash_passwd, shadow, md_len) == 0) {
		printf("Username And Passwd Test Succeeed. \n");
		memset(username, 0, AU_LEN);
		memset(passwd, 0, AU_LEN);
		memset(buf, 0, BUFSIZE);
		return 1;  // Pass on the Password test
	} else {
		memset(username, 0, AU_LEN);
		memset(passwd, 0, AU_LEN);
		memset(buf, 0, BUFSIZE);
		return 0;  // Failed in the Password test
	}
	
}
/*Wait for the client to pass the Authentication*/
int Authentication(unsigned char* key, unsigned char *iv) {
	int err;
  	int listen_sd;
  	int sd;
  	struct sockaddr_in sa_serv;
  	struct sockaddr_in sa_cli;
  	size_t client_len;
  	SSL_CTX* ctx;
  	SSL*     ssl;
  	X509*    client_cert;
  	char*    str;
  	char*    buf;
  	const SSL_METHOD *meth;
	/* SSL preliminaries. keep the certificate and key with the context. */
        	
  	SSL_load_error_strings();
  	SSLeay_add_ssl_algorithms();
  	meth = SSLv23_server_method();
  	ctx = SSL_CTX_new (meth);
  	if (!ctx) {
    		ERR_print_errors_fp(stderr);
		printf("2");
    		exit(2);
  	}
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
		printf("2");
    		exit(3);
  	}
  	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
    		exit(4);
  	}
  	if (!SSL_CTX_check_private_key(ctx)) {
    		fprintf(stderr,"Private key does not match the certificate public key\n");
    		exit(5);
  	}

	 /* ----------------------------------------------- */
  	/* Prepare TCP socket for receiving connections */
	
  	listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket"); 	     memset (&sa_serv, '\0', sizeof(sa_serv));
  	sa_serv.sin_family      = AF_INET;
  	sa_serv.sin_addr.s_addr = INADDR_ANY;
  	sa_serv.sin_port        = htons (TCP_PORT);          /* Server Port number*/  	     err = bind(listen_sd, (struct sockaddr*) &sa_serv,sizeof (sa_serv));                 CHK_ERR(err, "bind");
	err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
	client_len = sizeof(sa_cli);
  	sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  	CHK_ERR(sd, "accept");
//  	close(listen_sd);

	/* ----------------------------------------------- */
  	/* TCP connection is ready. Do server side SSL. */
	
  	ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  	SSL_set_fd (ssl, sd);
  	err = SSL_accept (ssl);                        CHK_SSL(err);
	buf = malloc(BUFSIZE);
	/* DATA EXCHANGE - Receive message and send reply. */
	err = SSL_read (ssl, buf, BUFSIZE);                   CHK_SSL(err);
	int i;
	/*Check the UserName and Password*/
	if (authenticationHelper(buf, key, iv) == 0) {
		printf("Failed on the UserName and Password Test\n");
		memset(buf, 0, BUFSIZE);
		buf = "Failed";
		SSL_write(ssl, buf, strlen(buf));
		close(sd);
		SSL_free (ssl);
                SSL_CTX_free (ctx);
		return 0;
	} else {
		printf("Succeed on the UserName and Password Test\n");
		memset(buf, 0, BUFSIZE);
		buf = "Passed";
		SSL_write(ssl, buf, strlen(buf));
/*		close (sd);
  		SSL_free (ssl);
  		SSL_CTX_free (ctx);	*/
		return 1;
	}
}

void StartServer(unsigned char* key, unsigned char *iv) {
	struct sockaddr_in server;
	struct sockaddr_in client;
	int clientlen;
	char buffer[BUFSIZE];
	int flags = IFF_TUN;	
	int optval = 1;
//	unsigned char *key;
//	unsigned char *iv;
	int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
		perror("setsockopt");
		exit(1);
	}
	
	memset((char*)&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(UDP_PORT);
	int tap_fd, ret, maxfd;
	fd_set rd_set;
	char  if_name[IFNAMSIZ] = "tun0";
	// Create the TUN Interface if you are first in it
	if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
	    perror("Error connecting to TUN/TAP Interface");
	    exit(1);
	}
	// Bind the UDP socket
	if (bind(sock_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("ERROR on binging");
	}
	// Wait to get message from client and get client addr
	while (1) {
	    bzero(buffer, BUFSIZE);
	    if(recvfrom(sock_fd, buffer, BUFSIZE - 1, 0, (struct sockaddr *)&client, &clientlen)> 0){
		char *data = "Hello Server";
		if(memcmp(buffer, data, sizeof(data)) == 0) break;
	}    
	}
        // Test

	unsigned char *cryptbuffer, *plainbuffer, *hmacbuffer, *tempbuffer;
        cryptbuffer = malloc(BUFSIZE);
        plainbuffer = malloc(BUFSIZE);
        tempbuffer = malloc(BUFSIZE);
        hmacbuffer = malloc(BUFSIZE);
//	iv = malloc(BUFSIZE);
//	key = malloc(BUFSIZE);
	// Initialize the iv and keys
/*	int start;
	for (start = 0; start < 16; start++) {
		iv[start] = 'a' + start;
		key[start] = 'a' + start;
	}
*/
        int cryptlen, plainlen, buffer_len;
		
	// use select to handle two descriptiors
	maxfd = (tap_fd > sock_fd)? tap_fd:sock_fd;
	
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
		    // Encrpt the message the send it to the Tun0
		    cryptlen = do_crypt(key, iv, buffer, plainlen, cryptbuffer, 1);
	            memcpy(tempbuffer, iv, KEY_LEN);
		    memcpy(tempbuffer + KEY_LEN, cryptbuffer, cryptlen);
		    // Do hmac 
		    do_hmac(key, tempbuffer, KEY_LEN + cryptlen, hmacbuffer);
		    memcpy(buffer, iv, KEY_LEN);
		    memcpy(buffer + KEY_LEN, cryptbuffer, cryptlen);
		    memcpy(buffer + KEY_LEN + cryptlen, hmacbuffer, SHA256_LEN);
		    buffer_len = KEY_LEN + cryptlen + SHA256_LEN;
		    if (sendto(sock_fd, buffer, buffer_len, 0, (struct sockaddr *)&client, clientlen) < 0) perror("send to Network, dest: Client"); 
		   memset(cryptbuffer, 0, BUFSIZE);
                   memset(hmacbuffer, 0, BUFSIZE);
                   memset(buffer, 0, BUFSIZE);
                   memset(tempbuffer, 0, BUFSIZE);
		} 
	        if (FD_ISSET(sock_fd, &rd_set)) {
		// Server, Data is from socket, read it and write it to the tun0
		    cryptlen = recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &clientlen);
		    // Check the integrity
		    memcpy(cryptbuffer, buffer, cryptlen - SHA256_LEN);
		    memcpy(iv, buffer, KEY_LEN);
		    do_hmac(key, cryptbuffer, cryptlen - SHA256_LEN, hmacbuffer);
		    if (memcmp(hmacbuffer, buffer + cryptlen - SHA256_LEN, SHA256_LEN) == 0) {
		    	// Decrpyt the message and send the plaintext to the tun0

		    	plainlen = do_crypt(key, iv, cryptbuffer + KEY_LEN, cryptlen - KEY_LEN -SHA256_LEN, tempbuffer, 0);
		    	if (write(tap_fd, tempbuffer, plainlen) < 0) perror("write in TUN");	
		    }
		   memset(cryptbuffer, 0, BUFSIZE);
		   memset(hmacbuffer, 0, BUFSIZE);
		   memset(buffer, 0, BUFSIZE);
		   memset(tempbuffer, 0, BUFSIZE);
		}

	}
	exit(1);
}

int main(int argc, char *argv[]) {
	//Directly Start Our Server.
	unsigned char *key;
	key = malloc(KEY_LEN);
	unsigned char *iv;
	iv = malloc(KEY_LEN);
	int flag = Authentication(key, iv);
	
	if (flag == 0) {
		printf("Authenticaton Failed");
		return 0;
	}	
	
	printf("Authentication Succeed. \n"); 
	
	pid_t pid = fork();
	pid_t wpid;
	int status;
	if (pid == 0) {  // Child Process
		StartServer(key, iv);
	} 
	while ( ( wpid = wait ( &status ) ) > 0 );
	return 0;
}
