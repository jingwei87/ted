#include "keyServer.hpp"
#include "ssl.hpp"

Configure config("config.json");
keyServer* server;
ssl* keySecurityChannelTemp;

void CTRLC(int s)
{
    cerr << " key server close" << endl;
    if (keySecurityChannelTemp != nullptr)
        delete keySecurityChannelTemp;
    if (server != nullptr)
        delete server;
    exit(0);
}

#if SINGLE_THREAD_KEY_MANAGER == 1

int main()
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    server = new keyServer(keySecurityChannelTemp);
    while (true) {
        SSL* sslConnection = keySecurityChannelTemp->sslListen().second;
        th = new boost::thread(boost::bind(&keyServer::runKeyGen, server, sslConnection));
        th->detach();
    }
    return 0;
}

#else

int main(int argc, char* argv[])
{

    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

#if SINGLE_MACHINE_TEST == 1
    keySecurityChannelTemp = new ssl("127.0.0.1", atoi(argv[1]), SERVERSIDE);
#else
    keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
#endif
    boost::thread* th;
#if OLD_VERSION == 1
    server = new keyServer(keySecurityChannelTemp);
#else
    uint64_t secretValue;
#if SINGLE_MACHINE_TEST == 1
    secretValue = atoi(argv[2]);
#else
    secretValue = config.getSecretShare();
#endif
    server = new keyServer(keySecurityChannelTemp, secretValue);
#endif
    th = new boost::thread(boost::bind(&keyServer::runOptimalSolver, server));
    while (true) {
        SSL* sslConnection = keySecurityChannelTemp->sslListen().second;
        if (OLD_VERSION) {
            th = new boost::thread(boost::bind(&keyServer::runKeyGen, server, sslConnection));
        } else {
            if (ENABLE_SECRET_SHARE) {
                th = new boost::thread(boost::bind(&keyServer::runKeyGenSS, server, sslConnection));
            } else {
                th = new boost::thread(boost::bind(&keyServer::runKeyGenSimple, server, sslConnection));
            }
        }
        th->detach();
    }
    return 0;
}
#endif
