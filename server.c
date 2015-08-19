/*
 * LMiniVPN - Server
 * Author: Zhouyu Lin
 *
 */
 
#include "server.h"
#include "common.h"

static int gethash(uint8_t * plain, uint32_t length, uint8_t * hash)
{
	EVP_MD_CTX *mdctx;
 	const EVP_MD *md = EVP_get_digestbyname("md5");
	uint32_t md_len;
	uint8_t value[EVP_MAX_MD_SIZE];
	OpenSSL_add_all_digests();

	mdctx = EVP_MD_CTX_create();
 	EVP_DigestInit_ex(mdctx, md, NULL);
 	EVP_DigestUpdate(mdctx, plain, length);
 	EVP_DigestFinal_ex(mdctx, value, &md_len);
	
	int i=0;
	for (i=0;i<16;i++)
		sprintf(hash+2*i,"%2x",(uint8_t)value[i]);

	return 0;
}


/* Read from file to do the client auth. */
static int authclient(uint8_t *user, uint32_t ulen, uint8_t *pwd, uint32_t plen)
{
	FILE *fuser;
	char *line = NULL;
	uint32_t len = 0;
	int read;

	fuser = fopen(SECERTS, "r");
	if (fuser == NULL)
	{
		do_debug("No secret file found!\n");
		return 1;
	}

	while ((read = getline(&line, &len, fuser)) != -1)
	{
		int f=0,i,x=0,y=0;
		uint8_t ruser[UNAME_SIZE], rpwd[33],plaintext[UNAME_SIZE+PWD_SIZE],hash[33];
		memset(ruser,0,UNAME_SIZE);
		memset(rpwd,0,EVP_MAX_MD_SIZE);
		memset(plaintext,0,UNAME_SIZE+PWD_SIZE);
		memset(hash,0,33);
		for (i=0;i<read-1;i++)
		{
			if (*(line+i)==' ' || *(line+i)=='\t' )
				continue;
			else if (*(line+i)=='*')
			{
				f=1;
				continue;
			}	
			else 
			{
				if (f==0)
					ruser[x++]=*(line+i);
				else 
					rpwd[y++]=*(line+i);	
			}
		}

		memcpy(plaintext,user,ulen);
		memcpy(plaintext+ulen,pwd,plen);
		gethash(plaintext,ulen+plen,hash);

		if (x==ulen && memcmp(user,ruser,ulen)==0 && y==32 && strncmp(hash,rpwd,32)==0)
			return 0;
	}
	return 1;
}


int main(int argc, char *argv[]) 
{
	int tap_fd, option;
  	int flags = IFF_TUN;
  	char if_name[IFNAMSIZ] = "";
  	int header_len = IP_HDR_LEN;
  	int maxfd;
  	uint16_t nread, nwrite, plength;
  	
  	struct sockaddr_in local, remote;
  	char remote_ip[16] = "";
  	unsigned short int port = PORT;
  	int sock_fd, net_fd, sock_tcp,sock_tcp_client, fd[2],optval = 1;

  	socklen_t remotelen,locallen;
  	unsigned long int tap2net = 0, net2tap = 0;

  	char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

	uint8_t key[KEY_SIZE];
	uint8_t buffer[BUFSIZE*2];

	SSL_CTX* ctx;
  	SSL*     ssl;
  	char*    str;
  	
	int err;

	int clientcount = 0;

  	progname = argv[0];
  
  	/* Check command line options */
  	while((option = getopt(argc, argv, "i:p:uahd")) > 0)
	{
    		switch(option) 
		{
			case 'd':
				debug = 1;
				break;
	      		case 'h':
        			usage(0);
        			break;
      			case 'i':
        			strncpy(if_name,optarg,IFNAMSIZ-1);
        			break;
		      	case 'p':
				port = atoi(optarg);
				break;
		      	case 'u':
				flags = IFF_TUN;
				break;
		      	case 'a':
				flags = IFF_TAP;
				header_len = ETH_HDR_LEN;
				break;
		      	default:
				my_err("Unknown option %c\n", option);
				usage(0);
    		}
  	}

  	argv += optind;
  	argc -= optind;

  	if(argc > 0)
	{
    		my_err("Too many options!\n");
    		usage(0);
  	}

  	if(*if_name == '\0')
	{
    		//my_err("Must specify interface name!\n");
    		//usage(0);
		strncpy(if_name,"tun0",4);
  	}

	
	// create tcp socket
	if ( (sock_tcp = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{
    		perror("TCP process: socket()");
    		exit(1);
  	}

		/* SSL preliminaries. We keep the certificate and key with the context. */
	  	SSL_load_error_strings();
	  	SSLeay_add_ssl_algorithms();
	  	const SSL_METHOD *meth = SSLv23_server_method();
	  	ctx = SSL_CTX_new (meth);
	  	if (!ctx) 
		{
	    		ERR_print_errors_fp(stderr);
	    		exit(2);
	  	}

	  	//SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
	  	SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
	  
	  	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) 
		{
	    		ERR_print_errors_fp(stderr);
	    		exit(3);
	  	}
	  	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) 
		{
			ERR_print_errors_fp(stderr);
			exit(4);
	  	}

	  	if (!SSL_CTX_check_private_key(ctx)) 
		{
	    		fprintf(stderr,"Private key does not match the certificate public key\n");
	    		exit(5);
	  	}


    		/* Server, wait for connections */

    		/* avoid EADDRINUSE error on bind() */
    		if(setsockopt(sock_tcp, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
		{
      			perror("setsockopt()");
      			exit(1);
    		}
	
    
    		memset(&local, 0, sizeof(local));
    		local.sin_family = AF_INET;
    		local.sin_addr.s_addr = htonl(INADDR_ANY);
    		local.sin_port = htons(port);

    		if (bind(sock_tcp, (struct sockaddr*) &local, sizeof(local)) < 0)
		{
      			perror("bind()");
      			exit(1);
    		}


		if (listen(sock_tcp, 5) < 0)
		{
      			perror("listen()");
      			exit(1);
    		}
    
		struct sigaction act;
		memset (&act, 0, sizeof(act));
		act.sa_handler = sigchld_hdl;
		if (sigaction(SIGCHLD, &act, 0)) 
		{
			perror ("sigaction");
			exit(1);
		}

		
		while(1)
		{
    			/* wait for connection request */
    			remotelen = sizeof(remote);
    			memset(&remote, 0, remotelen);
			do_debug("MAIN: TCP: Listening on port %d...\n",port);

			for (;;) 
			{
    				if ((sock_tcp_client = accept(sock_tcp, (struct sockaddr*)&remote, &remotelen)) < 0) 
				{
  					if (errno == EINTR)
    						continue;
  					else
					{
    						perror("accept()");
      						exit(1);
					}
    				}
				else 
					break;  
        		}

    			do_debug("TCP: Connected from %s\n", inet_ntoa(remote.sin_addr));

				
			//fork child tcp process
			pid_t pid = fork();
			if (pid < 0)
			{
				perror("level 1 fork()");
				exit(1);
			}
			if (pid == 0) //child tcp process
			{
				break;
				//jump out of the loop		

			}
			if (pid > 0) //server hypervisor process
			{
				clientcount++;
				continue;
			}
			
		}


		ssl = SSL_new (ctx);                           
		CHK_NULL(ssl);
  		SSL_set_fd (ssl, sock_tcp_client);
  		err = SSL_accept (ssl);                        
		CHK_SSL(err);
  
  		/* Get the cipher - opt */
  		do_debug("SSL connection using %s\n", SSL_get_cipher (ssl));


		//out of the loop, tcp process
		message *result, *send;
		send = malloc(sizeof(message));
                result = malloc(sizeof(message));

		int length,userlen,pwdlen;
		char username[UNAME_SIZE];
		char password[PWD_SIZE];
		// auth server

		// auth client
		while (1)
		{
			memset(username,0,UNAME_SIZE);
			memset(password,0,PWD_SIZE);

			userlen = wait_readtcp(ssl,result) - sizeof(uint8_t);
			if (result->type == MSG_USER && userlen <= UNAME_SIZE)
			{	
				memcpy(username,result->data,userlen);
				//do_debug("TCP: Username received.\n");
				send->type = MSG_ROGER;
				char m[]="\n";
				memcpy(send->data,m,sizeof(m));
				tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
			}
			else
			{
				send->type = MSG_INVALID;
				char m[]="SERVER: TCP: Invalid username length.";
                                memcpy(send->data,m,sizeof(m));
                                tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
				continue;
			}

			pwdlen = wait_readtcp(ssl,result) - sizeof(uint8_t);
                        if (result->type == MSG_PWD && pwdlen <= PWD_SIZE)
                        { 
                                memcpy(password,result->data,pwdlen);
                                //do_debug("TCP: Password received.\n");

				// compare password and username
				if (authclient(username,userlen,password,pwdlen)==0)
				{
                                	send->type = MSG_VALID;
                                	char m[]="* Welcome to Delta's VPN Server! *";
                                	memcpy(send->data,m,sizeof(m));
                                	tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
					break;
				}
				else
				{
					send->type = MSG_INVALID;
                                        char m[]="Invalid username/password.";
                                        memcpy(send->data,m,sizeof(m));
                                        tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
					continue;
				}
                        }
                        else
                        {
                                send->type = MSG_INVALID;
                                char m[]="SERVER: TCP: Invalid password length.";
                                memcpy(send->data,m,sizeof(m));
                                tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
                                continue;
                        }
			
			sleep(2);
			
		}	
	
		
		// recv key
		length = wait_readtcp(ssl,result) - sizeof(uint8_t);
		if (length == KEY_SIZE && result->type == MSG_KEY)
		{
			memcpy(key,result->data,KEY_SIZE);
			do_debug("TCP: KEY received & set.\n");
			//send confirm back to client
			send->type = MSG_ROGER;
			char m[]="SERVER: TCP: KEY received & set.";
                        memcpy(send->data,m,sizeof(m));
			tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
		}
		else
		{
			my_err("Invalid KEY msg.\n");
			exit(1);
		}

		//send server udp port to client
		send->type = MSG_UDPPORT;
		char udpport[6];
		sprintf(udpport,"%d",port+clientcount);
		memcpy(send->data,udpport,sizeof(udpport));
		tcpsend(ssl,send,sizeof(uint8_t)+sizeof(udpport));

		// server active tcp process
		if (pipe(fd) < 0)
		{
			perror("pipe()");
		}
		

		//fork here

		pid_t pid = fork();
		
		if (pid < 0)
		{
			perror("level 2 fork()");
			exit(1);
		}
		if (pid == 0) //child udp process
		{
			//close(sock_tcp);
			close(fd[1]);

			//set interface name
			sprintf(if_name+3,"%d",clientcount);

			/* initialize tun/tap interface */
  			if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) 
			{
    				my_err("Error connecting to tun/tap interface %s!\n", if_name);
    				exit(1);
  			}

  			do_debug("UDP: Connected to interface %s\n", if_name);

  			if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
			{
    				perror("socket()");
    				exit(1);
  			}
						

			local.sin_port = htons(port+clientcount);

			if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0)
			{
      				perror("bind()");
      				exit(1);
    			}
									

			while(1) 
			{
				//do_debug("while()\n");
    				if (recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remote, &remotelen) < 0)
				{
					perror("recvfrom()");
    				}
				//do_debug("recv()\n");
        			if (strncmp(MAGIC_WORD, buffer, sizeof(MAGIC_WORD)) == 0)
					break;
				printf("Bad magic word from %s:%i\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));

    			}

						

    			if (sendto(sock_fd, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&remote, remotelen) < 0) 		
				perror("sendto()"); 
    

    			net_fd = sock_fd;
    			do_debug("UDP: Connected from %s\n", inet_ntoa(remote.sin_addr));
			
			//get key/iv from tcp process			
						
		}

		if (pid > 0) //tcp process
		{
			close(fd[0]);
		
			//for security reason
			memset(key,0,KEY_SIZE);
			memset(username,0,UNAME_SIZE);
			memset(password,0,PWD_SIZE);
			
			//inform udp tunnel to get ready
			send->type = MSG_READY;
			char m[]="Ready.";
			memcpy(send->data,m,sizeof(m));
			write(fd[1],(uint8_t *)send,sizeof(uint8_t)+sizeof(m));
			do_debug("TCP: Sent ready cmd to UDP process\n");

			//wait for tcp msg
			while(1)
			{
				memset(send,0,sizeof(message));
				memset(result,0,sizeof(message));
				length = wait_readtcp(ssl, result);
				
        			switch (result->type)
        			{
        			case MSG_KILL:
					//do abort
					do_debug("TCP: Connection closed by client. Bye.\n");
					close(sock_tcp_client);
					int status;
              
                			kill(pid,SIGKILL);
                			sleep(1);
                			waitpid(pid, &status, WNOHANG);
					exit(0);
                			break;
				case MSG_KEY:
					//forward the new key to udp process
					if (length == KEY_SIZE+sizeof(uint8_t))
					{
						do_debug("TCP: Received NEW KEY from client\n");
						//send new key to udp process
						write(fd[1],(uint8_t *)result,sizeof(uint8_t)+KEY_SIZE);
						do_debug("TCP: Sent NEW KEY to UDP process\n");
						//send confirm back to client
						send->type = MSG_ROGER;
						char m[]="SERVER: TCP: NEW KEY received & set.";
                        			memcpy(send->data,m,sizeof(m));
						tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
					}
					else
					{
						my_err("Invalid KEY msg.\n");
						break;
					}

					break;
					
				default:
					my_err("TCP: Invalid msg got.\n");
					break;
        			}

			}		

		}
	
	
	result=malloc(sizeof(message));
	read(fd[0], (uint8_t *)result, sizeof(message));
	if (result->type == MSG_READY)
		do_debug("UDP: Tunnel ready.\n");
	else
		do_debug("UDP: Invalid ready msg from TCP.\n");
	

	// use select() to handle 3 descriptors at once
	maxfd = 0;
	if(tap_fd > maxfd)
		maxfd = tap_fd;
	if(net_fd > maxfd)
		maxfd = net_fd;
	if(fd[0] > maxfd)
		maxfd = fd[0];

	while(1) 
	{
		if (getppid()==1)
		{
			close(net_fd);
			close(tap_fd);
			close(fd[0]);
			exit(0);
		}
		memset(buffer,0,sizeof(buffer));
    		int ret;
    		fd_set rd_set;

    		FD_ZERO(&rd_set);
    		FD_SET(tap_fd, &rd_set); 
		FD_SET(net_fd, &rd_set);
		FD_SET(fd[0], &rd_set);

    		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    		if (ret < 0 && errno == EINTR){
      			continue;
    		}

    		if (ret < 0) 
		{
      			perror("select()");
      			exit(1);
    		}

		
		if(FD_ISSET(fd[0], &rd_set))
		{
			if (getppid()==1)
			{
				close(net_fd);
				close(tap_fd);
				close(fd[0]);
				exit(1);
			}
			read(fd[0], (uint8_t *)result, sizeof(message));
			if (result->type == MSG_KEY)
			{
				memcpy(key,result->data,KEY_SIZE);
				do_debug("UDP: NEW KEY set.\n");
			}
			else
				do_debug("UDP: Invalid msg got from TCP\n");

		}


    		if(FD_ISSET(tap_fd, &rd_set))
		{
      			/* data from tun/tap: just read it and write it to the network */
      
			// read packet
			remotelen = sizeof(remote);
      			nread = read(tap_fd, buffer, BUFSIZE);
			//do_debug("plaintext read from tap_fd, length = %d\n",nread);
	 
			uint8_t *plain_text = buffer;
			int plain_len = nread;
			uint8_t packet[2*BUFSIZE]; //iv header + data + hash
			uint8_t tem_buffer[BUFSIZE+32]; // large enough.
			//uint8_t *buf;
			int outlen,tmplen,len;

			// !! add iv header, should not be encrypted
			uint8_t iv[IV_SIZE];
			//gen iv
                	if (randgen(iv,IV_SIZE) != 0)
                	{
                        	my_err("ERROR: TCP: IV generate failed.\n");
                        	exit(1);
                	}
			memcpy(packet,iv,IV_SIZE);

			// encrypt packet
			EVP_CIPHER_CTX ctx;
			EVP_CIPHER_CTX_init(&ctx);
			EVP_EncryptInit_ex(&ctx,EVP_aes_128_cbc(),NULL,key,iv);
			EVP_EncryptUpdate(&ctx,tem_buffer,&outlen,plain_text,plain_len);
			EVP_EncryptFinal_ex(&ctx, tem_buffer + outlen, &tmplen);
			EVP_CIPHER_CTX_cleanup(&ctx);
			len = outlen + tmplen;
			//buf = (uint8_t *)malloc(len);
			memcpy(packet+IV_SIZE,tem_buffer,len);

			// hash packet
			uint8_t *mess = packet;
			int mess_len = len+IV_SIZE;
			uint8_t *hashbuffer = (uint8_t *)malloc(SHA256_LEN);
			int md_len;
			HMAC_CTX mdctx;
			HMAC_CTX_init(&mdctx);
			HMAC_Init_ex(&mdctx, key, KEY_SIZE, EVP_sha256(),NULL);
			HMAC_Update(&mdctx, mess, mess_len);
			HMAC_Final(&mdctx, hashbuffer, &md_len);
			HMAC_CTX_cleanup(&mdctx);
			// should check packet size here
			memcpy(packet+IV_SIZE+len,hashbuffer,SHA256_LEN); 

			// send to socket
      			if (sendto(net_fd, packet, IV_SIZE+len+SHA256_LEN, 0, (struct sockaddr *)&remote, remotelen) < 0) 
				perror("sendto()");
			//do_debug("encrypted data send to net_fd, length = %d\n",IV_SIZE+len+SHA256_LEN);
			
    		}

   		if(FD_ISSET(net_fd, &rd_set))
		{
      			// data from the network: read it, and write it to the tun/tap interface. 
       				
			locallen=sizeof(local);
      			
			// read packet from socket
      			nread = recvfrom(net_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remote, &remotelen);
			//do_debug("encrypted data read from net_fd, nread = %d\n",nread);
			
			char iv[IV_SIZE];
			
			// hash compare
			int md_len;
			char *mess = buffer;
			int mess_len = nread - SHA256_LEN;
			char *hashbuffer = (uint8_t *)malloc(SHA256_LEN);
			HMAC_CTX mdctx;
			HMAC_CTX_init(&mdctx);
			HMAC_Init_ex(&mdctx, key, KEY_SIZE, EVP_sha256(),NULL);
			HMAC_Update(&mdctx, mess, mess_len);
			HMAC_Final(&mdctx, hashbuffer, &md_len);
			HMAC_CTX_cleanup(&mdctx);
			
			if (memcmp(hashbuffer, buffer+mess_len,SHA256_LEN)==0)
			{
				//do_debug("Hash matched.\n");
				// hash matched, decrypt data
				memcpy(iv,buffer,IV_SIZE);
				char tem_buffer[BUFSIZE+32]; // large enough. 
			
				int outlen,tmplen,len;
				EVP_CIPHER_CTX ctx;
				EVP_CIPHER_CTX_init(&ctx);
				EVP_DecryptInit_ex(&ctx,EVP_aes_128_cbc(),NULL,key,iv);
				EVP_DecryptUpdate(&ctx,tem_buffer,&outlen,mess+IV_SIZE,mess_len-IV_SIZE);
				EVP_DecryptFinal_ex(&ctx, tem_buffer + outlen, &tmplen);
				EVP_CIPHER_CTX_cleanup(&ctx);
	
				memcpy(buffer,tem_buffer,outlen+tmplen);
				len = outlen+tmplen;
				
				// send to interface
      				if (write(tap_fd, buffer, len) < 0) 
					perror("write");
			}
			else
				do_debug("UDP: Hash not match! Packet droped.\n");
    		}
	}


	//never come here
	return 0;
}

