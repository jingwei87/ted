#ifndef GENERALDEDUPSYSTEM_SSL_HPP
#define GENERALDEDUPSYSTEM_SSL_HPP

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <sys/types.h>

#define SERVERSIDE 0
#define CLIENTSIDE 1

#define SECRT "key/servercert.pem"
#define SEKEY "key/server.key"
#define CLCRT "key/clientcert.pem"
#define CLKEY "key/client.key"
#define CACRT "key/cacert.pem"

using namespace std;

class ssl {
private:
    SSL_CTX* _ctx;
    struct sockaddr_in _sockAddr;
    std::string _serverIP;
    int _port;

public:
    int listenFd;
    ssl(std::string ip, int port, int scSwitch);
    ~ssl();
    std::pair<int, SSL*> sslConnect();
    std::pair<int, SSL*> sslListen();
    bool send(SSL* connection, char* data, int dataSize);
    bool recv(SSL* connection, char* data, int& dataSize);
};

#endif //GENERALDEDUPSYSTEM_SSL_HPP
