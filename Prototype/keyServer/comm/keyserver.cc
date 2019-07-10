/*
 * keyserver.cc
 */

#include "keyserver.hh"
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <string>
#include <sys/time.h>

using namespace std;

void fatalx(char* s)
{

    ERR_print_errors_fp(stderr);
    errx(EX_DATAERR, "%.30s", s);
}

/*
 * constructor: initialize host socket
 *
 * @param port - port number
 * @param dedupObj - dedup object passed in
 */
KeyServer::KeyServer(int port)
{

    //server port
    hostPort_ = port;
    //initiate ssl functions
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    // create TSL connection
    ctx_ = SSL_CTX_new(TLSv1_server_method());
    if (ctx_ == NULL)
        fatalx("ctx");
    //load client certificate
    if (!SSL_CTX_load_verify_locations(ctx_, SSL_CA_CRT, NULL))
        fatalx("verify");
    SSL_CTX_set_client_CA_list(ctx_, SSL_load_client_CA_file(SSL_CA_CRT));
    if (!SSL_CTX_use_certificate_file(ctx_, SSL_SERVER_CRT, SSL_FILETYPE_PEM))
        fatalx("cert");
    //Load server key file
    if (!SSL_CTX_use_PrivateKey_file(ctx_, SSL_SERVER_KEY, SSL_FILETYPE_PEM))
        fatalx("key");
    //check server key
    if (!SSL_CTX_check_private_key(ctx_))
        fatalx("cert/key");
    //init SSL connection
    SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx_, 1);
    //server socket initialization
    hostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (hostSock_ == -1) {

        printf("Error initializing socket %d\n", errno);
    }
    //set socket options
    int* p_int = (int*)malloc(sizeof(int));
    *p_int = 1;

    if ((setsockopt(hostSock_, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int)) == -1) || (setsockopt(hostSock_, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1)) {

        printf("Error setting options %d\n", errno);
        free(p_int);
    }
    free(p_int);
    //initialize address struct
    myAddr_.sin_family = AF_INET;
    myAddr_.sin_port = htons(hostPort_);
    memset(&(myAddr_.sin_zero), 0, 8);
    myAddr_.sin_addr.s_addr = INADDR_ANY;
    //bind port
    if (bind(hostSock_, (sockaddr*)&myAddr_, sizeof(myAddr_)) == -1) {

        fprintf(stderr, "Error binding to socket %d\n", errno);
    }
    //start to listen
    if (listen(hostSock_, 10) == -1) {

        fprintf(stderr, "Error listening %d\n", errno);
    }
}

/*
 * Timer functions
 */
void timerStart(double* t)
{

    struct timeval tv;
    gettimeofday(&tv, NULL);
    *t = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
}

double timerSplit(const double* t)
{

    struct timeval tv;
    double cur_t;
    gettimeofday(&tv, NULL);
    cur_t = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
    return (cur_t - *t);
}

int sketchTable[4][W] = { 0 };
int EditSketchTable(int hash_1, int hash_2, int hash_3, int hash_4)
{
}

/*
 * Thread function: each thread maintains a socket from a certain client
 *
 * @param lp - input parameter structure
 */
void* SocketHandler(void* lp)
{

    //double timer,split,bw;
    //get socket from input param
    SSL* ssl = ((KeyServer*)lp)->ssl_;
    //variable initialization
    int bytecount;
    char* buffer = (char*)malloc(sizeof(char) * BUFFER_SIZE + sizeof(int));
    char* output = (char*)malloc(sizeof(char) * BUFFER_SIZE + sizeof(int));
    if ((bytecount = SSL_read(ssl, buffer, sizeof(int))) == -1) {

        fprintf(stderr, "Error recv userID %d\n", errno);
    }
    int user = ntohl(*(int*)buffer);
    printf("connection from user %d\n", user);

    while (true) {

        if ((bytecount = SSL_read(ssl, buffer, sizeof(int))) == -1) {

            fprintf(stderr, "Error recv chunk batch size %d\n", errno);
        }
        if (bytecount == 0) {
            break;
        }
        // prepare to recv data
        int num, total;
        memcpy(&num, buffer, sizeof(int));
        total = 0;
        // recv data (blinded hash, 1024bits values)
        char* hash_buffer_1 = (char*)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        char* hash_buffer_2 = (char*)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        char* hash_buffer_3 = (char*)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        char* hash_buffer_4 = (char*)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        if ((bytecount = SSL_read(ssl, hash_buffer_1, num * HASH_SIZE_SHORT)) == -1) {
            fprintf(stderr, "Error recv hash_1 list %d\n", errno);
            exit(1);
        }
        if ((bytecount = SSL_read(ssl, hash_buffer_2, num * HASH_SIZE_SHORT)) == -1) {
            fprintf(stderr, "Error recv hash_2 list %d\n", errno);
            exit(1);
        }
        if ((bytecount = SSL_read(ssl, hash_buffer_3, num * HASH_SIZE_SHORT)) == -1) {
            fprintf(stderr, "Error recv hash_3 list %d\n", errno);
            exit(1);
        }
        if ((bytecount = SSL_read(ssl, hash_buffer_4, num * HASH_SIZE_SHORT)) == -1) {
            fprintf(stderr, "Error recv hash_4 list %d\n", errno);
            exit(1);
        }

        // main loop for computing params
        double timer, split;
        timerStart(&timer);

        //TODO

        split = timerSplit(&timer);
        printf("server compute: %lf\n", split);
        // send back the result

        if ((bytecount = SSL_write(ssl, output + sizeof(int) + total, num * RSA_LENGTH - total)) == -1) {

            fprintf(stderr, "Error recv file hash %d\n", errno);
            exit(1);
        }
    }
    return 0;
}

/*
 * main procedure for receiving data
 */
void KeyServer::runReceive()
{

    addrSize_ = sizeof(sockaddr_in);
    //create a thread whenever a client connects
    while (true) {

        printf("waiting for a connection\n");
        clientSock_ = (int*)malloc(sizeof(int));

        if ((*clientSock_ = accept(hostSock_, (sockaddr*)&sadr_, &addrSize_)) != -1) {

            printf("Received connection from %s\n", inet_ntoa(sadr_.sin_addr));
            // SSL verify
            ssl_ = SSL_new(ctx_);
            SSL_set_fd(ssl_, *clientSock_);
            int r;
            if ((r = SSL_accept(ssl_)) == -1)
                warn("SSL_accept");
            pthread_create(&threadId_, 0, &SocketHandler, (void*)this);
            pthread_detach(threadId_);
        } else {

            fprintf(stderr, "Error accepting %d\n", errno);
        }
    }
}

KeyServer::~KeyServer()
{

    SSL_free(ssl_);
    SSL_CTX_free(ctx_);
}
