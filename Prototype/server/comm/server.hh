/*
 * server.hh
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

#include "DedupCore.hh"
#include "BackendStorer.hh"

/* buffer length*/
#define BUFFER_LEN (4*1024*1024)

/* meta buffer length */
#define META_LEN (2*1024*1024)

/* indicator types */
#define NEW 1
#define UPDATE 2
#define STUB 3
#define GETSTUB 4
#define META (-1)
#define DATA (-2)
#define STAT (-3)
#define DOWNLOAD (-7)



#define KEY_NEW 1
#define KEY_UPDATE 2
#define DOWNLOAD_KEY 3



using namespace std;

class Server{
	private:

		//port number
		int dataHostPort_;
		int keyHostPort_;

		//server address struct
		struct sockaddr_in dataAddr_;
		struct sockaddr_in keyAddr_;
		//receiving socket
		int dataHostSock_;

		//receiving socket
		int keyHostSock_;
		

		//socket size
		socklen_t addrSize_;

		//client socket
		int* clientSock_;
		int* keyclientSock_;
		//socket address
		struct sockaddr_in sadr_;

		//thread ID
		pthread_t threadId_;

	public:
		Server(int dataPort, int keyPort, DedupCore* dedupObj);
		void runReceive();
		//	void* SocketHandler(void* lp);
};

#endif
