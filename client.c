/*
 * LMiniVPN - Client
 * Author: Zhouyu Lin
 *
 */

#include "client.h"
#include "common.h"

/* Control terminal echo on/off */
static int set_disp_mode(int fd,int option)
{
   	int err;
   	struct termios term;
   	if(tcgetattr(fd,&term)==-1)
	{
     		perror("Cannot get the attribution of the terminal");
     		return 1;
   	}
   	if(option)
        	term.c_lflag|=ECHOFLAGS;
   	else
        	term.c_lflag &=~ECHOFLAGS;
   	
	err=tcsetattr(fd,TCSAFLUSH,&term);
   	if(err==-1 && err==EINTR)
	{
        	perror("Cannot set the attribution of the terminal");
        	return 1;
   	}
   	return 0;
}


/* wait to read from stdin. */
static int wait_readstdin(char *msg, uint8_t *inbuf)
{
	my_err("%s",msg);

	int ret;
        uint16_t nread;
        fd_set rd_set;
        
	while(1)
	{
		FD_ZERO(&rd_set);
		FD_SET(0, &rd_set);
		memset(inbuf,0,BUFSIZE);
		  	
		ret = select(1, &rd_set, NULL, NULL, NULL);
		if (ret < 0 && errno == EINTR)
			continue;

		if (ret < 0) {
		  	perror("select()");
		}

		if(FD_ISSET(0, &rd_set))
		{
		        fgets(inbuf,BUFSIZE,stdin);
			nread = strlen(inbuf) - 1;
			
		       	if (nread > 0)
			{
				//do_debug("nread = %d\n",nread);
		               	return nread;
			}
		       	else
		               	return -1;
		}
	}

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
  	int sock_fd, net_fd, sock_tcp,fd[2], optval = 1;
  	socklen_t remotelen,locallen;
  	unsigned long int tap2net = 0, net2tap = 0;

  	char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

	uint8_t key[KEY_SIZE];
	
	uint8_t buffer[BUFSIZE*2];
	uint8_t inbuf[BUFSIZE];

	SSL_CTX* ctx;
  	SSL*     ssl;
  	char*    str;
	char hostname[HOSTNAME_SIZE];
  	
	int err;

  	progname = argv[0];
  
  	/* Check command line options */
  	while((option = getopt(argc, argv, "i:c:p:uahd")) > 0)
	{
    		switch(option) 
		{
			case 'd':
				debug = 1;
				break;
	      		case 'h':
        			usage(1);
        			break;
      			case 'i':
        			strncpy(if_name,optarg,IFNAMSIZ-1);
        			break;
			case 'c':
				//get server ip by hostname
				strncpy(hostname,optarg,HOSTNAME_SIZE);
				struct hostent *answer;
				int i;
				answer = gethostbyname(optarg);
				if (answer == NULL) 
				{
					herror("gethostbyname()");
					exit(1);
				}
				for (i = 0; (answer->h_addr_list)[i] != NULL; i++) 
					inet_ntop(AF_INET, (answer->h_addr_list)[i], remote_ip, 16);
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
				usage(1);
    		}
  	}

  	argv += optind;
  	argc -= optind;

  	if(argc > 0)
	{
    		my_err("Too many options!\n");
    		usage(1);
  	}

  	if(*if_name == '\0')
	{
    		//my_err("Must specify interface name!\n");
    		//usage(1);
		strncpy(if_name,"tun0",4);
  	}
	else if(*remote_ip == '\0')
	{
    		my_err("Must specify server address!\n");
    		usage(1);
  	}

	
	// create tcp socket
	if ( (sock_tcp = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{
    		perror("TCP process: socket()");
    		exit(1);
  	}	


		X509*    server_cert;
		SSLeay_add_ssl_algorithms();
  		const SSL_METHOD *meth = SSLv23_client_method();
  		SSL_load_error_strings();
  		ctx = SSL_CTX_new (meth);                        
		CHK_NULL(ctx);
  		CHK_SSL(err);

		/* assign the destination address */
    		memset(&remote, 0, sizeof(remote));
    		remote.sin_family = AF_INET;
    		remote.sin_addr.s_addr = inet_addr(remote_ip);
    		remote.sin_port = htons(port);

    		remotelen = sizeof(remote);
		
		if (pipe(fd) < 0)
		{
			perror("pipe()");
		}

		//start tcp connection to server

                /* connection request */
                if (connect(sock_tcp, (struct sockaddr*) &remote, sizeof(remote)) < 0)
                {
                	perror("TCP: connect()");
                        exit(1);
                }
		else
                	do_debug("TCP: Connected to server %s\n", inet_ntoa(remote.sin_addr));


		message *send, *result;
		send = malloc(sizeof(message));
		result = malloc(sizeof(message));
		int length,inputlen;

                //start ssl
		ssl = SSL_new (ctx);                         
		CHK_NULL(ssl);    
  		SSL_set_fd (ssl, sock_tcp);
  		err = SSL_connect (ssl);                     
		CHK_SSL(err);

		do_debug("TCP: SSL connection using %s\n", SSL_get_cipher (ssl));

		//do server auth
		
		SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
		SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); 
		//SSL_CTX_set_verify_depth(ctx,1);
		int verify_result = SSL_get_verify_result(ssl);
    		if (verify_result == X509_V_OK || verify_result == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
        		do_debug("TCP: Server certificate valid.\n");
    		else 
		{
        		my_err("TCP: ERROR: Invalid certificate: %d. Disconnecting...\n", verify_result);
			exit(1);
		}

		server_cert = SSL_get_peer_certificate (ssl);       
		CHK_NULL(server_cert);
  		//do_debug("TCP: Server certificate:\n");
		str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  		CHK_NULL(str);
  		//do_debug ("\t subject: %s\n", str);
  		OPENSSL_free (str);

  		str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  		CHK_NULL(str);
  		//do_debug ("\t issuer: %s\n", str);
  		OPENSSL_free (str);

  		/* We could do all sorts of certificate verification stuff here before
     			deallocating the certificate. */

		char commonName [512]; 
		X509_NAME * name = X509_get_subject_name(server_cert);

		X509_NAME_get_text_by_NID(name, NID_commonName, commonName, 512); 
		if(strcasecmp(commonName, hostname) != 0) 
		{
			my_err("TCP: ERROR: CN and Hostname mismatch! Disconnecting...\n");
			exit(1);
		}

  		X509_free (server_cert);
      

		//auth client by send username/password
		while (1)
		{
			//get user input and send username
			inputlen = wait_readstdin("\nUsername: ",inbuf);
			send->type = MSG_USER;
			//do_debug("%s, length=%d\n",inbuf, inputlen);
			
			memcpy(send->data,inbuf,inputlen);
			if (tcpsend(ssl,send,sizeof(uint8_t)+inputlen)!= 0)
				my_err("ERROR: TCP: Unable to send username.\n");

			//wait for reply
			length = wait_readtcp(ssl, result);
                       	if (result->type != MSG_ROGER)
                        {
                        	if (result->type == MSG_INVALID)
				{
					printf("%s\n",result->data);
					continue;
				}
				else
                                	my_err("ERROR: TCP: Invalid confirm msg got.\n");
                	}
		
			//get user input and send password
			set_disp_mode(STDIN_FILENO,0);
			inputlen = wait_readstdin("Password: ",inbuf);
			set_disp_mode(STDIN_FILENO,1);
                	send->type = MSG_PWD;
                	memcpy(send->data,inbuf,inputlen);
                	if (tcpsend(ssl,send,sizeof(uint8_t)+inputlen)!= 0) 
                        	my_err("ERROR: TCP: Unable to send password.\n");
			
			//wait for reply
			length = wait_readtcp(ssl, result);
                
                        if (result->type == MSG_VALID)
			{
				//print welcome msg from server
                                printf("\n\n%s\n\n",result->data);
				break;
			}
			else if (result->type == MSG_INVALID)
			{
				printf("%s\n",result->data);
				continue;
			}
                        else
                                my_err("ERROR: TCP: No auth result msg got.\n");
                }
                
		
 		//gen key
                if (randgen(key,KEY_SIZE) == 0)
                        do_debug("TCP: KEY generated.\n");
                else
		{
			my_err("ERROR: TCP: KEY generate failed.\n");
			exit(1);
		}

                
		//send key
                send->type = MSG_KEY;
                memcpy(send->data,key,KEY_SIZE);
                if (tcpsend(ssl, send,sizeof(uint8_t)+KEY_SIZE) != 0)
                	my_err("ERROR: TCP: Send KEY failed.\n");

                length = wait_readtcp(ssl, result);
                if (result->type != MSG_ROGER)
                       	my_err("ERROR: TCP: No confirm msg got.\n");
		
		uint16_t udpport = 0;               
		//receive udp port from tcp;
		length = wait_readtcp(ssl, result);
		if (result->type == MSG_UDPPORT)
		{
			sscanf(result->data,"%d",(int *)&udpport);
			do_debug("TCP: Server UDP port = %d\n",udpport);
		}
		else
			my_err("ERROR: TCP: No port number msg got.\n");

		//do the fork
		pid_t pid = fork();
		
		if (pid < 0)
		{
			perror("fork()");
			exit(1);
		}
		if (pid == 0) //child udp process
		{
			//close(sock_tcp);
			close(fd[1]);

			/* initialize tun/tap interface */
  			if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) 
			{
    				my_err("Error connecting to tun/tap interface %s!\n", if_name);
    				exit(1);
  			}
				
			remote.sin_port = htons(udpport);

  			do_debug("UDP: Connected to interface %s\n", if_name);

  			if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
			{
    				perror("socket()");
    				exit(1);
  			}

  
    			/* Client, try to connect to server */

			int i;
			for (i=1;i<2;i++)
			{
    				if (sendto(sock_fd, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&remote, remotelen) < 0) 				
					perror("sendto()");
					sleep(2);
			}

			while(1)
			{
    				if (recvfrom(sock_fd,buffer, sizeof(buffer), 0, (struct sockaddr *)&remote, &remotelen) < 0) 
					perror("recvfrom()");
    				if (strncmp(MAGIC_WORD, buffer, sizeof(MAGIC_WORD) != 0))
					printf("Bad magic word for peer\n");
				break;
			}
    			net_fd = sock_fd;
    			do_debug("UDP: Connected to server %s\n", inet_ntoa(remote.sin_addr));
			

			//go to loop, same part of c/s			
			
			
		}
		if (pid > 0) //parent tcp process
		{
			close(fd[0]);

			//inform udp tunnel to get ready
			send->type = MSG_READY;
			char m[]="Ready.";
			memcpy(send->data,m,sizeof(m));
			write(fd[1],(uint8_t *)send,sizeof(uint8_t)+sizeof(m));
			do_debug("TCP: Sent ready cmd to UDP process\n");
			
			//loop wait user input
			sleep(3);
			while (1)
			{
				//for security reason
				memset(key,0,KEY_SIZE);
				memset(inbuf,0,BUFSIZE);

        			length = wait_readstdin("\n> ", inbuf);

				//parse user input
				int i;
				for (i=0;i<length;i++)
				{
					if (*(inbuf+i)==' ')
						continue;
					if(*(inbuf+i)=='-')
					{
						if (memcmp(inbuf+i+1,"abort",5)==0)
						{
							send->type = MSG_KILL;
							do_debug("Disconnecting...\n");
							char m[]="Abort.";
							memcpy(send->data,m,sizeof(m));
							tcpsend(ssl,send,sizeof(uint8_t)+sizeof(m));
							close(sock_tcp);
							
							int status;
                					kill(pid,SIGKILL);
                					sleep(1);
                					waitpid(pid, &status, WNOHANG);
							exit(0);
							break;
						}
						if (memcmp(inbuf+i+1,"newkey",6)==0)
						{
							//gen key
                					if (randgen(key,KEY_SIZE) == 0)
                        					do_debug("TCP: NEW KEY generated.\n");
                					else
							{
								my_err("ERROR: TCP: KEY generate failed.\n");
								break;
							}

							//send key to server
                					send->type = MSG_KEY;
                					memcpy(send->data,key,KEY_SIZE);
                					if (tcpsend(ssl, send,sizeof(uint8_t)+KEY_SIZE) != 0)
                						my_err("ERROR: TCP: Send KEY failed.\n");

                					length = wait_readtcp(ssl, result);
                					if (result->type != MSG_ROGER)
                       						my_err("ERROR: TCP: No confirm msg got.\n");

							//send key to udp process
							write(fd[1],(uint8_t *)send,sizeof(uint8_t)+KEY_SIZE);
							do_debug("TCP: Sent NEW KEY to UDP process\n");
							break;
							
						}
					}
					else 
					{
						my_err("Invalid command.\n");
						break;
					}
				}

				sleep(1);

			}
		}


	//message *result;
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
	
