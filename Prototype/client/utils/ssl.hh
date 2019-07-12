/*
 * ssl.hh
 */

#ifndef __SSL_HH__
#define __SSL_HH__

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#define SSL_CA_CRT "./keys/ca.crt"
#define SSL_CLIENT_CRT "./keys/client.crt"
#define SSL_CLIENT_KEY "./keys/client.key"

#define SOCKET_BUFFER_SIZE (8 + 4 * 1024 * 1024)

using namespace std;

class Ssl {
private:
    /* port number */
    int hostPort_;

    /* ip address */
    char* hostName_;

    /* address structure */
    struct sockaddr_in myAddr_;

    /* host socket */
    SSL_CTX* ctx_;
    SSL* ssl_;

    char buffer_[SOCKET_BUFFER_SIZE];

public:
    /*
		 * constructor: initialize sock structure and connect
		 *
		 * @param ip - server ip address
		 * @param port - port number
		 */
    Ssl(char* ip, int port, int userID);

    int hostSock_;

    /*
		 * @ destructor
		 */
    ~Ssl();

    /*
		 * basic send function
		 * 
		 * @param raw - raw data buffer_
		 * @param rawSize - size of raw data
		 */
    int genericSend(char* raw, int rawSize);

    /*
		 * data download function
		 *
		 * @param raw - raw data buffer
		 * @param rawSize - the size of data to be downloaded
		 * @return raw
		 */
    int genericDownload(char* raw, int rawSize);
};

#endif
