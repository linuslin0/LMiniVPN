/*
 * LMiniVPN - Common Part
 * Author: Zhouyu Lin
 *
 */

#include "common.h"

/* SIGCHLD handler. */
void sigchld_hdl (int sig)
{
	/* Wait for all dead processes.
	 * We use a non-blocking call to be sure this signal handler will not
	 * block if a child was cleaned up in another part of the program. */
	while (waitpid(-1, NULL, WNOHANG) > 0) 
	{
	}
}

/* Generate random numbers. */
int randgen(uint8_t *data, int length)
{
	uint32_t seed;
	FILE* urandom = fopen("/dev/urandom", "r");
	fread(&seed, sizeof(uint32_t), 1, urandom);
	fclose(urandom);
	srand(seed);

	while(length > 0)
	{
		length--;
		*(data+length) = rand()%256;
	}
	return 0;
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) 
{
	struct ifreq ifr;
  	int fd, err;

  	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) 
	{
    		perror("tun_alloc(): Opening /dev/net/tun");
    		return fd;
  	}

 	memset(&ifr, 0, sizeof(ifr));
  	ifr.ifr_flags = flags;

  	if (*dev)
    		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
	{
		perror("tun_alloc(): ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

  	strcpy(dev, ifr.ifr_name);
  	return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(SSL* fd, char *buf, int n)
{
	int nread;
  	if((nread=SSL_read(fd, buf, n))<0)
	{
    		perror("cread() -> read()");
    		exit(1);
  	}
  	return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(SSL* fd, char *buf, int n)
{  
	int nwrite;

  	if((nwrite=SSL_write(fd, buf, n))<0)
	{
    		perror("cwite() -> write()");
    		exit(1);
  	}
  	return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(SSL* fd, char *buf, int n) 
{
  	int nread, left = n;
  	while(left > 0) 
	{
    		if ((nread = cread(fd, buf, left))==0)
		{
      			return 0 ;      
    		}
		else 
		{
      			left -= nread;
      			buf += nread;
    		}
  	}
  	return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{  
	va_list argp;
  	if(debug)
	{
		va_start(argp, msg);
		vfprintf(stderr, msg, argp);
		va_end(argp);
  	}
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) 
{
  	va_list argp;
  	va_start(argp, msg);
  	vfprintf(stderr, msg, argp);
  	va_end(argp);
}

/* wait to read from tcp socket. */
int wait_readtcp(SSL* fd,message *result)
{
	int nread, plength;

	nread = read_n(fd, (char *)&plength, sizeof(plength));
	if(nread == 0) 
	{
		do_debug("TCP: Client disconnected. Bye.\n");
		SSL_free (fd);
		exit(1);
	}
			
	/* read packet */
	nread = read_n(fd, (char *)result, ntohs(plength));
		return nread;	
		
}

/* send tcp message */
int tcpsend(SSL* fd, message *send, int length)
{
	int plength,nwrite;
	plength = htons(length);
	nwrite = cwrite(fd, (char *)&plength, sizeof(plength));
        nwrite = cwrite(fd, (char *)send, length);
	return 0;
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(int role) 
{
	fprintf(stderr, "Usage:\n");
	if (role==1)
  		fprintf(stderr, "%s [-i <ifacename>] [-c <hostname>] [-p <port>] [-u|-a] [-d]\n", progname);
	else
		fprintf(stderr, "%s [-p <port>] [-u|-a] [-d]\n", progname);
  	fprintf(stderr, "%s -h\n", progname);
  	fprintf(stderr, "\n");
	if (role==1)
	{
  		fprintf(stderr, "-i <ifacename>: Name of interface to use\n");
  		fprintf(stderr, "-c <hostname>: specify server hostnmae (-c <hostname>) (mandatory)\n");
	}
  	fprintf(stderr, "-p <port>: port to use, default 55555\n");
  	fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  	fprintf(stderr, "-d: outputs debug information while running\n");
  	fprintf(stderr, "-h: prints this help text\n");
  	exit(1);
}
