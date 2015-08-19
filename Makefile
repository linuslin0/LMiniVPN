CC=gcc
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
all:	DVServer DVClient
DVServer:	
	$(CC) -I$(INC) -L$(LIB) -o DVServer server.c common.c -lssl -lcrypto -ldl
DVClient:	
	$(CC) -I$(INC) -L$(LIB) -o DVClient client.c common.c -lssl -lcrypto -ldl

clean:
	rm *~ DVServer DVClient
