#include "keyServer.hpp"
#include "ssl.hpp"

Configure config("config.json");

int main()
{
    ssl* keySecurityChannelTemp = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), SERVERSIDE);
    boost::thread* th;
    keyServer* server = new keyServer(keySecurityChannelTemp);
    th = new boost::thread(boost::bind(&keyServer::runOptimalSolver, server));
    while (true) {
        std::pair<int, SSL*> sslConnection = keySecurityChannelTemp->sslListen();
        th = new boost::thread(boost::bind(&keyServer::runKeyGen, server, sslConnection));
        th->detach();
    }
    return 0;
}
