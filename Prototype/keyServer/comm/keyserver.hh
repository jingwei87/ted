/*
 * keyserver.hh
 */

#ifndef __SERVER_HH__
#define __SERVER_HH__

#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "solver.hh"
#include <err.h>
#include <signal.h>
#include <sys/types.h>
#include <sysexits.h>

#define OPENSSL_VERSION_1_1 1
#define HASH_SIZE_SHORT 3
#define W 1024 * 1024 // W - sketch table size
#define K 3000        // K - max chunk number sketch store before opsolver
#define storageBlow 0.5
// client cerificate
#define SSL_CA_CRT "./keys/ca.crt"
// server certificate
#define SSL_SERVER_CRT "./keys/server.crt"
// server key
#define SSL_SERVER_KEY "./keys/server.key"
// hash value size 256 bits
#define HASH_SIZE 32
// rsa size 1024 bits
#define RSA_LENGTH 128
// buffer size
#define BUFFER_SIZE (32 * 1024 * 1024)
#define RANDOM_TYPE 1
#define UNIFORM_INT_RAND 1
#define POISSON_RAND 2
#define NORMAL_RAND 3
#define GEOMETRIC_RAND 4
#define NO_RAND 5

using namespace std;

class KeyServer
{

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
    int *clientSock_;
    //socket address
    struct sockaddr_in sadr_;
    //thread ID
    pthread_t opSolverThreadId_;
    // SSL context
    SSL_CTX *ctx_;

public:
    // SSL connection structure
    SSL *ssl_;
    // constructor
    KeyServer(int port);
    // destructor
    ~KeyServer();
    // main loop
    void runReceive();
    //	void* SocketHandler(void* lp);
};

#endif
