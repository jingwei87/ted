#include "ssl.hpp"

ssl::ssl(std::string ip, int port, int scSwitch)
{
    this->_serverIP = ip;
    this->_port = port;
    this->listenFd = socket(AF_INET, SOCK_STREAM, 0);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    memset(&_sockAddr, 0, sizeof(_sockAddr));
    std::string keyFile, crtFile;

    _sockAddr.sin_port = htons(port);
    _sockAddr.sin_family = AF_INET;

    switch (scSwitch) {
    case SERVERSIDE: {
        _ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_mode(_ctx, SSL_MODE_AUTO_RETRY);
        crtFile = SECRT;
        keyFile = SEKEY;
        _sockAddr.sin_addr.s_addr = htons(INADDR_ANY);
        if (bind(listenFd, (sockaddr*)&_sockAddr, sizeof(_sockAddr)) == -1) {
            std::cerr << "Can not bind to sockfd\n";
            std::cerr << "May cause by shutdown server before client\n";
            std::cerr << "Wait for 30 sec and try again\n";
            exit(1);
        }
        if (listen(listenFd, 10) == -1) {
            std::cerr << "Can not set listen socket\n";
            exit(1);
        }
        break;
    }
    case CLIENTSIDE: {
        _ctx = SSL_CTX_new(TLS_client_method());
        keyFile = CLKEY;
        crtFile = CLCRT;
        _sockAddr.sin_addr.s_addr = inet_addr(ip.c_str());
        break;
    };
    }

    SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(_ctx, CACRT, NULL)) {
        std::cerr << "Wrong CA crt file at ssl.cpp:ssl(ip,port)\n";
        exit(1);
    }
    if (!SSL_CTX_use_certificate_file(_ctx, crtFile.c_str(), SSL_FILETYPE_PEM)) {
        std::cerr << "Wrong crt file at ssl.cpp:ssl(ip,port)\n";
        exit(1);
    }
    if (!SSL_CTX_use_PrivateKey_file(_ctx, keyFile.c_str(), SSL_FILETYPE_PEM)) {
        std::cerr << "Wrong key file at ssl.cpp:ssl(ip,port)\n";
        exit(1);
    }
    if (!SSL_CTX_check_private_key(_ctx)) {
        std::cerr << "1\n";
        exit(1);
    }
}

ssl::~ssl()
{
}
std::pair<int, SSL*> ssl::sslConnect()
{
    //std::pair<int,SSL*> ssl::sslConnect(){
    int fd;
    SSL* sslConection;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr*)&_sockAddr, sizeof(sockaddr)) < 0) {
        std::cerr << "ERROR Occur on ssl(fd) connect\n";
        exit(1);
    }
    sslConection = SSL_new(_ctx);
    SSL_set_fd(sslConection, fd);
    SSL_connect(sslConection);

    //_fdList.push_back(fd);
    //_sslList.push_back(sslConection);
    return std::make_pair(fd, sslConection);
}

std::pair<int, SSL*> ssl::sslListen()
{
    //std::pair<int,SSL*> ssl::sslListen(){
    int fd;
    fd = accept(listenFd, (struct sockaddr*)NULL, NULL);
    SSL* sslConection = SSL_new(_ctx);
    SSL_set_fd(sslConection, fd);
    SSL_accept(sslConection);

    //_fdList.push_back(fd);
    //_sslList.push_back(sslConection);
    return std::make_pair(fd, sslConection);
}

bool ssl::recv(SSL* connection, char* data, int& dataSize)
{
    int recvd = 0, len = 0;
    if (SSL_read(connection, (char*)&len, sizeof(int)) == 0) {
        return false;
    }
    while (recvd < len) {
        recvd += SSL_read(connection, data + recvd, len - recvd);
    }
    dataSize = len;
    return true;
}

bool ssl::send(SSL* connection, char* data, int dataSize)
{
    if (SSL_write(connection, (char*)&dataSize, sizeof(int)) == 0) {
        return false;
    }
    int sendSize = 0;
    while (sendSize < dataSize) {
        sendSize += SSL_write(connection, data + sendSize, dataSize - sendSize);
    }
    return true;
}
