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

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000 
#define UDP_PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28


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

void StartServer() {
	struct sockaddr_in server;
	struct sockaddr_in client;
	int clientlen;
	char buffer[BUFSIZE];
	int flags = IFF_TUN;
	
	int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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
	    if (recvfrom(sock_fd, buffer, BUFSIZE - 1, 0, (struct sockaddr *)&client, &clientlen) > 0) {
		break;
	}
	    
	}		
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
		    if (read(tap_fd, buffer, sizeof(buffer)) < 0) perror("read from TUN");
		    if (sendto(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, clientlen) < 0) perror("send to Network, dest: Client"); 
		} 
	        if (FD_ISSET(sock_fd, &rd_set)) {
		// Server, Data is from socket, read it and write it to the tun0
		    if (recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &clientlen) < 0) perror("receive from the Network, dest:server");
		    if (write(tap_fd, buffer, sizeof(buffer)) < 0) perror("write in TUN");
		}

	}
	exit(1);
}

int main(int argc, char *argv[]) {
	//Directly Start Our Server.
	StartServer();
	return 0;
}
