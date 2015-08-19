#ifndef _server_h
#define _server_h

#define MAX_CLIENT 128

static int gethash(unsigned char * plain, unsigned int length, unsigned char * hash);
static int authclient(unsigned char *user, unsigned int ulen, unsigned char *pwd,unsigned int plen);

#endif

