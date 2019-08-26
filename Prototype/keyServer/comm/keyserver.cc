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

struct timeval timestartInit;
struct timeval timeendInit;

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

#if defined(OPENSSL_VERSION_1_1)
    ctx_ = SSL_CTX_new(TLS_server_method());
#else
    ctx_ = SSL_CTX_new(TLSv1_2_server_method());
#endif

    if (ctx_ == NULL)
        cerr << "ssl ctx create error" << endl;
    //load client certificate
    if (!SSL_CTX_load_verify_locations(ctx_, SSL_CA_CRT, NULL))
        cerr << "ssl load verify error" << endl;
    SSL_CTX_set_client_CA_list(ctx_, SSL_load_client_CA_file(SSL_CA_CRT));
    if (!SSL_CTX_use_certificate_file(ctx_, SSL_SERVER_CRT, SSL_FILETYPE_PEM))
        cerr << "ssl use cert file error" << endl;
    //Load server key file
    if (!SSL_CTX_use_PrivateKey_file(ctx_, SSL_SERVER_KEY, SSL_FILETYPE_PEM))
        cerr << "ssl use private key error" << endl;
    //check server key
    if (!SSL_CTX_check_private_key(ctx_))
        cerr << "ssl check private key error" << endl;
    //init SSL connection
    SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx_, 1);
    //server socket initialization
    hostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (hostSock_ == -1)
    {

        printf("Error initializing socket %d\n", errno);
    }
    //set socket options
    int *p_int = (int *)malloc(sizeof(int));
    *p_int = 1;

    if ((setsockopt(hostSock_, SOL_SOCKET, SO_REUSEADDR, (char *)p_int, sizeof(int)) == -1) || (setsockopt(hostSock_, SOL_SOCKET, SO_KEEPALIVE, (char *)p_int, sizeof(int)) == -1))
    {

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
    if (bind(hostSock_, (sockaddr *)&myAddr_, sizeof(myAddr_)) == -1)
    {

        fprintf(stderr, "Error binding to socket %d\n", errno);
    }
    //start to listen
    if (listen(hostSock_, 10) == -1)
    {

        fprintf(stderr, "Error listening %d\n", errno);
    }
}

/*
 * Timer functions
 */
void timerStart(double *t)
{

    struct timeval tv;
    gettimeofday(&tv, NULL);
    *t = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
}

double timerSplit(const double *t)
{

    struct timeval tv;
    double cur_t;
    gettimeofday(&tv, NULL);
    cur_t = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
    return (cur_t - *t);
}

unsigned int sketchTable[4][W] = {0};
int sketchTableCounter = 0;
double T = 1;
bool opSolverFlag = false;
vector<pair<string, int>> opInput;
int opm = W * (1 + storageBlow);
std::mutex EditTMutex;
std::mutex EditSketchTableMutex;

double opSolver(int m, vector<pair<string, int>> opInput)
{
    OpSolver *solver = new OpSolver(m, opInput);
    return solver->GetOptimal();
}

int EditSketchTable(unsigned int hash_1, unsigned int hash_2, unsigned int hash_3, unsigned int hash_4)
{
    std::lock_guard<std::mutex> locker(EditSketchTableMutex);
    int cmpNumber = 0;
    sketchTableCounter++;
    //cout << "sketch table count = " << sketchTableCounter << endl;
    //cout << "4 hash number = " << hash_1 % W << "," << hash_2 % W << "," << hash_3 % W << "," << hash_4 % W << endl;
    sketchTable[0][hash_1 % W]++;
    sketchTable[1][hash_2 % W]++;
    sketchTable[2][hash_3 % W]++;
    sketchTable[3][hash_4 % W]++;
    cmpNumber = sketchTable[0][hash_1 % W];
    if (cmpNumber > sketchTable[1][hash_2 % W])
    {
        cmpNumber = sketchTable[1][hash_2 % W];
    }
    if (cmpNumber > sketchTable[2][hash_3 % W])
    {
        cmpNumber = sketchTable[2][hash_3 % W];
    }
    if (cmpNumber > sketchTable[3][hash_4 % W])
    {
        cmpNumber = sketchTable[3][hash_4 % W];
    }
    //cout << "cmpNumber  = " << cmpNumber << endl;
    if (sketchTableCounter == K)
    {
        std::lock_guard<std::mutex> locker(EditTMutex);
        opInput.clear();
        opInput.reserve(W);
        for (int i = 0; i < W; i++)
        {
            stringstream ss;
            ss << i;
            string strTemp = ss.str();
            opInput.push_back(make_pair(strTemp, sketchTable[0][i]));
        }
        cout << "key server start optimization solver" << endl;
        //T = opSolver(opm, opInput);
        sketchTableCounter = 0;
        // for (int i = 0; i < W; i++) {
        //     sketchTable[0][i] = 0;
        //     sketchTable[1][i] = 0;
        //     sketchTable[2][i] = 0;
        //     sketchTable[3][i] = 0;
        // }
        opSolverFlag = true;
    }
    //cout << "Edit Sketch Table Over" << endl;
    return cmpNumber;
}

/*
 * Thread function: each thread maintains a socket from a certain client
 *
 * @param lp - input parameter structure
 */

void *SocketHandler(void *lp)
{

    random_device rd_;
    mt19937_64 gen_ = mt19937_64(rd_());
    //double timer,split,bw;
    //get socket from input param
    SSL *ssl = ((KeyServer *)lp)->ssl_;
    char serverPrivate[64];
    memset(serverPrivate, 1, 64);
    //variable initialization
    int bytecount;
    char *buffer = (char *)malloc(sizeof(int));
    if ((bytecount = SSL_read(ssl, buffer, sizeof(int))) == -1)
    {
        fprintf(stderr, "Error recv userID %d\n", errno);
        return 0;
    }
    int user = ntohl(*(int *)buffer);
    printf("keyserver recv connection from user %d\n", user);

    while (true)
    {

        if ((bytecount = SSL_read(ssl, buffer, sizeof(int))) == -1)
        {
            fprintf(stderr, "Error recv chunk batch size %d\n", errno);
            return 0;
        }
        if (bytecount == 0)
        {
            break;
        }
        // prepare to recv data
        int num;
        cerr << "Recv number = " << num << endl;
        memcpy(&num, buffer, sizeof(int));
        // cout << "recv count request for " << num << " chunks" << endl;
        char *hash_buffer_1 = (char *)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        char *hash_buffer_2 = (char *)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        char *hash_buffer_3 = (char *)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        char *hash_buffer_4 = (char *)malloc(sizeof(char) * num * HASH_SIZE_SHORT);
        if ((bytecount = SSL_read(ssl, hash_buffer_1, num * HASH_SIZE_SHORT)) == -1)
        {
            fprintf(stderr, "Error recv hash_1 list %d\n", errno);
            free(hash_buffer_1);
            free(hash_buffer_2);
            free(hash_buffer_3);
            free(hash_buffer_4);
            return 0;
        }
        if ((bytecount = SSL_read(ssl, hash_buffer_2, num * HASH_SIZE_SHORT)) == -1)
        {
            fprintf(stderr, "Error recv hash_2 list %d\n", errno);
            free(hash_buffer_1);
            free(hash_buffer_2);
            free(hash_buffer_3);
            free(hash_buffer_4);
            return 0;
        }
        if ((bytecount = SSL_read(ssl, hash_buffer_3, num * HASH_SIZE_SHORT)) == -1)
        {
            fprintf(stderr, "Error recv hash_3 list %d\n", errno);
            free(hash_buffer_1);
            free(hash_buffer_2);
            free(hash_buffer_3);
            free(hash_buffer_4);
            return 0;
        }
        if ((bytecount = SSL_read(ssl, hash_buffer_4, num * HASH_SIZE_SHORT)) == -1)
        {
            fprintf(stderr, "Error recv hash_4 list %d\n", errno);
            free(hash_buffer_1);
            free(hash_buffer_2);
            free(hash_buffer_3);
            free(hash_buffer_4);
            return 0;
        }

        // main loop for computing params
        //double timer, split;
        //timerStart(&timer);
        int currentFreqList[num];
        //cout << "Frequency count start for " << num << " chunks" << endl;
        char outPutBuffer[num * 32];

        for (int i = 0; i < num; i++)
        {
            gettimeofday(&timestartInit, NULL);
            //EditSketchTableMutex.lock();
            unsigned int hash_int_1, hash_int_2, hash_int_3, hash_int_4;
            memcpy(&hash_int_1, hash_buffer_1 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(&hash_int_2, hash_buffer_2 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(&hash_int_3, hash_buffer_3 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(&hash_int_4, hash_buffer_4 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            // cout << "current num = " << i << endl;
            currentFreqList[i] = EditSketchTable(hash_int_1, hash_int_2, hash_int_3, hash_int_4);
            // cout << "current done num = " << i << endl;
            int param;

            param = floor(currentFreqList[i] / T);

            if (RANDOM_TYPE == POISSON_RAND)
            {
                int lambda = ceil(param / 2.0);
                poisson_distribution<> dis(lambda);
                param = dis(gen_);
            }
            else if (RANDOM_TYPE == UNIFORM_INT_RAND)
            {
                uniform_int_distribution<> dis(0, param);
                param = dis(gen_);
            }
            else if (RANDOM_TYPE == GEOMETRIC_RAND)
            {
                geometric_distribution<> dis;
                int random = dis(gen_);
                if (param < random)
                    param = 0;
                else
                    param = param - random;
            }
            else if (RANDOM_TYPE == NORMAL_RAND)
            {
                normal_distribution<> dis(param, 1);
                int result = round(dis(gen_));
                if (result < 0)
                    param = 0;
                else
                    param = result;
            }

            // gettimeofday(&timeendInit, NULL);
            // long diff = 1000000 * (timeendInit.tv_sec - timestartInit.tv_sec) + timeendInit.tv_usec - timestartInit.tv_usec;
            // double second = diff / 1000000.0;
            // printf("generate key seed time is %ld us = %lf s\n", diff, second);
            // // cout << "current num = " << i << endl;
            // gettimeofday(&timestartInit, NULL);
            unsigned char newKeyBuffer[64 + 4 * HASH_SIZE_SHORT + sizeof(int)];
            memcpy(newKeyBuffer, serverPrivate, 64);
            memcpy(newKeyBuffer + 64, hash_buffer_1 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(newKeyBuffer + 64 + HASH_SIZE_SHORT, hash_buffer_2 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(newKeyBuffer + 64 + 2 * HASH_SIZE_SHORT, hash_buffer_3 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(newKeyBuffer + 64 + 3 * HASH_SIZE_SHORT, hash_buffer_4 + i * HASH_SIZE_SHORT, HASH_SIZE_SHORT);
            memcpy(newKeyBuffer + 64 + 4 * HASH_SIZE_SHORT, &param, sizeof(int));
            // cout << "current = " << i << "memcpy done" << endl;
            unsigned char key[32];
            SHA256(newKeyBuffer, 64 + 4 * HASH_SIZE_SHORT + sizeof(int), key);
            memcpy(outPutBuffer + i * 32, key, 32);
            // gettimeofday(&timeendInit, NULL);
            // diff = 1000000 * (timeendInit.tv_sec - timestartInit.tv_sec) + timeendInit.tv_usec - timestartInit.tv_usec;
            // second = diff / 1000000.0;
            // printf("update param time is %ld us = %lf s\n", diff, second);
            //cout << "Frequency for chunk " << i << " = " << currentFreqList[i] << endl;
            //EditSketchTableMutex.unlock();
        }

        //split = timerSplit(&timer);
        //printf("server compute: %lf\n", split);
        cout << "current T = " << T << endl;
        // send back the result
        // cout << "generate key for " << num << "done" << endl;
        if ((bytecount = SSL_write(ssl, outPutBuffer, num * 32)) == -1)
        {
            fprintf(stderr, "Error send compute ans %d\n", errno);
            free(hash_buffer_1);
            free(hash_buffer_2);
            free(hash_buffer_3);
            free(hash_buffer_4);
            return 0;
        }
        free(hash_buffer_1);
        free(hash_buffer_2);
        free(hash_buffer_3);
        free(hash_buffer_4);
    }
    return 0;
}

void *opSolverThread(void *lp)
{
    while (true)
    {
        std::lock_guard<std::mutex> locker(EditTMutex);
        if (opSolverFlag)
        {
            // gettimeofday(&timestartInit, NULL);
            T = opSolver(opm, opInput);
            opSolverFlag = false;
            // gettimeofday(&timeendInit, NULL);
            // long diff = 1000000 * (timeendInit.tv_sec - timestartInit.tv_sec) + timeendInit.tv_usec - timestartInit.tv_usec;
            // double second = diff / 1000000.0;
            // printf("optimal compute time is %ld us = %lf s\n", diff, second);
        }
    }
}

/*
 * main procedure for receiving data
 */

void KeyServer::runReceive()
{

    addrSize_ = sizeof(sockaddr_in);
    //create a thread whenever a client connects
    pthread_create(&opSolverThreadId_, 0, &opSolverThread, NULL);
    while (true)
    {

        printf("key server waiting for a connection\n");
        clientSock_ = (int *)malloc(sizeof(int));

        if ((*clientSock_ = accept(hostSock_, (sockaddr *)&sadr_, &addrSize_)) != -1)
        {

            printf("key server Received connection from %s\n", inet_ntoa(sadr_.sin_addr));
            // SSL verify
            ssl_ = SSL_new(ctx_);
            SSL_set_fd(ssl_, *clientSock_);
            int r;
            if ((r = SSL_accept(ssl_)) == -1)
                warn("SSL_accept");
            pthread_t threadId_;
            pthread_create(&threadId_, 0, &SocketHandler, (void *)this);
        }
        else
        {

            fprintf(stderr, "Error accepting %d\n", errno);
        }
    }
}

KeyServer::~KeyServer()
{

    SSL_free(ssl_);
    SSL_CTX_free(ctx_);
}
