#include "ssl.hh"

using namespace std;

extern void timerStart(double *t);
extern double timerSplit(const double *t);

/*
 * constructor: initialize sock structure and connect
 *
 * @param ip - server ip address
 * @param port - port number
 */
Ssl::Ssl(char *ip, int port, int userID)
{

    /* get port and ip */
    hostPort_ = port;
    hostName_ = ip;
    int err;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

#if defined(OPENSSL_VERSION_1_1)
    ctx_ = SSL_CTX_new(TLS_client_method());
#else
    ctx_ = SSL_CTX_new(TLSv1_2_client_method());
#endif

    if (ctx_ == NULL)
        cerr << "ctx" << endl;

    if (!SSL_CTX_load_verify_locations(ctx_, SSL_CA_CRT, NULL))
        cerr << "verify" << endl;

    if (!SSL_CTX_use_certificate_file(ctx_, SSL_CLIENT_CRT, SSL_FILETYPE_PEM))
        cerr << "cert" << endl;
    if (!SSL_CTX_use_PrivateKey_file(ctx_, SSL_CLIENT_KEY, SSL_FILETYPE_PEM))
        cerr << "key" << endl;
    if (!SSL_CTX_check_private_key(ctx_))
        cerr << "cert/key" << endl;

    SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx_, 1);

    /* initializing socket object */
    hostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hostSock_ == -1)
    {
        printf("Error initializing socket %d\n", errno);
    }
    int *p_int = (int *)malloc(sizeof(int));
    *p_int = 1;

    /* set socket options */
    if (
        (setsockopt(hostSock_,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char *)p_int,
                    sizeof(int)) == -1) ||
        (setsockopt(hostSock_,
                    SOL_SOCKET,
                    SO_KEEPALIVE,
                    (char *)p_int,
                    sizeof(int)) == -1))
    {
        printf("Error setting options %d\n", errno);
        free(p_int);
    }
    free(p_int);

    /* set socket address */
    myAddr_.sin_family = AF_INET;
    myAddr_.sin_port = htons(port);
    memset(&(myAddr_.sin_zero), 0, 8);
    myAddr_.sin_addr.s_addr = inet_addr(ip);

    /* trying to connect socket */
    if (connect(hostSock_, (struct sockaddr *)&myAddr_, sizeof(myAddr_)) == -1)
    {
        if ((err = errno) != EINPROGRESS)
        {
            fprintf(stderr, "Error connecting socket %d\n", errno);
        }
    }

    ssl_ = SSL_new(ctx_);
    SSL_set_fd(ssl_, hostSock_);

    if (SSL_connect(ssl_) <= 0)
        cerr << "SSL_connect" << endl;

    if (SSL_get_verify_result(ssl_) != X509_V_OK)
        cerr << "cert error" << endl;

    /* prepare user ID and send it to server */
    int netorder = htonl(userID);
    int bytecount;
    if ((bytecount = SSL_write(ssl_, &netorder, sizeof(int))) == -1)
    {
        fprintf(stderr, "Error sending userID %d\n", errno);
    }
    else
    {
        fprintf(stderr, "Sending userID done\n");
    }
}

/*
 * @ destructor
 */
Ssl::~Ssl()
{
    SSL_free(ssl_);
    SSL_CTX_free(ctx_);
    close(hostSock_);
}

/*
 * basic send function
 * 
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 */
int Ssl::genericSend(char *raw, int rawSize)
{

    int bytecount;
    int total = 0;
    while (total < rawSize)
    {
        if ((bytecount = SSL_write(ssl_, raw + total, rawSize - total)) == -1)
        {
            fprintf(stderr, "Error sending data %d\n", errno);
            return -1;
        }
        total += bytecount;
    }
    return total;
}

/*
 *
 * @param raw - raw data buffer
 * @param rawSize - the size of data to be downloaded
 * @return raw
 */
int Ssl::genericDownload(char *raw, int rawSize)
{

    int bytecount;
    int total = 0;
    while (total < rawSize)
    {
        if ((bytecount = SSL_read(ssl_, raw + total, rawSize - total)) == -1)
        {
            fprintf(stderr, "Error sending data %d\n", errno);
            return -1;
        }
        total += bytecount;
    }
    return 0;
}
