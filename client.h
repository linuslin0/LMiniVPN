#ifndef _client_h
#define _client_h

#include <termios.h>
#include <netdb.h>

#define ECHOFLAGS (ECHO | ECHOE | ECHOK | ECHONL)
#define HOSTNAME_SIZE 512

static int set_disp_mode(int fd,int option);
static int wait_readstdin(char *msg, unsigned char *inbuf);

#endif

