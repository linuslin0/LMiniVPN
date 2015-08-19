#ifndef _common_h
#define _common_h

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
#include <signal.h>


#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* define HOME to be dir for key and cert files... */
#define HOME "./auth/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"
#define SECERTS HOME "secrets.conf"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2048   
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define KEY_SIZE 16
#define IV_SIZE 16
#define SHA256_LEN 32
#define UNAME_SIZE 64
#define PWD_SIZE 64

#define MSG_ROGER 0x01
#define MSG_KEY 0x02
#define MSG_USER 0x03
#define MSG_PWD 0x04
#define MSG_KILL 0x05
#define MSG_VALID 0x06
#define MSG_INVALID 0x07
#define MSG_UDPPORT 0x08
#define MSG_READY 0x09


typedef struct
{
	uint8_t type;
	uint8_t data[BUFSIZE];
}message;

int debug;
char *progname;

void do_debug(char *msg, ...);
void my_err(char *msg, ...);
void sigchld_hdl (int sig);

int randgen(uint8_t *data, int length);
int tun_alloc(char *dev, int flags);

int cread(SSL* fd, char *buf, int n);
int cwrite(SSL* fd, char *buf, int n);
int read_n(SSL* fd, char *buf, int n);

int wait_readtcp(SSL* fd,message *result);
int tcpsend(SSL* fd, message *send, int length);

void usage(int role);

#endif
