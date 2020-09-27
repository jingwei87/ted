#include "keyServer.hpp"
#include "ssl.hpp"

Configure config("config.json");

#if SINGLE_THREAD_KEY_MANAGER == 1

int main()
{
    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    keyServer* server = new keyServer(keySecurityChannelTemp);
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

#if SINGLE_MACHINE_TEST == 1
    ssl* keySecurityChannelTemp = new ssl("127.0.0.1", atoi(argv[1]), SERVERSIDE);
#else
    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
#endif
    boost::thread* th;
#if OLD_VERSION == 1
    keyServer* server = new keyServer(keySecurityChannelTemp);
#else
    uint64_t secretValue;
#if SINGLE_MACHINE_TEST == 1
    secretValue = atoi(argv[2]);
#else
    secretValue = config.getSecretShare();
#endif
    keyServer* server = new keyServer(keySecurityChannelTemp, secretValue);
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
