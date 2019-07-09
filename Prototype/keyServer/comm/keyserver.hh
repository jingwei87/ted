/*
 * keyserver.hh
 */

#ifndef __SERVER_HH__
#define __SERVER_HH__

#include <bits/stdc++.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#include <err.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/types.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

// client cerificate
#define SSL_CA_CRT "./keys/ca/ca.crt"
// server certificate
#define SSL_SERVER_CRT "./keys/server.crt"
// server key
#define SSL_SERVER_KEY "./keys/private/server.key"
// hash value size 256 bits
#define HASH_SIZE 32
// rsa size 1024 bits
#define RSA_LENGTH 128
// buffer size
#define BUFFER_SIZE (32*1024*1024)

using namespace std;

class KeyServer {

	private:

		//port number
		int hostPort_;
		//server address struct
		struct sockaddr_in myAddr_;
		//receiving socket
		int hostSock_;
		//socket size
		socklen_t addrSize_;
		//client socket
		int* clientSock_;
		//socket address
		struct sockaddr_in sadr_;
		//thread ID
		pthread_t threadId_;
		// SSL context
		SSL_CTX* ctx_;

	public:

		// SSL connection structure
		SSL* ssl_;
		// constructor
		KeyServer(int port);
		// destructor 
		~KeyServer();
		// main loop
		void runReceive();
		//	void* SocketHandler(void* lp);
};

#endif
