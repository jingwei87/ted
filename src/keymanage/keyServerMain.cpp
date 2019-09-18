#include "keyServer.hpp"
#include "socket.hpp"

Configure config("config.json");

int main()
{
    Socket socket(SERVER_TCP, "", config.getKeyServerPort());
    boost::thread* th;
    keyServer* server = new keyServer();
    th = new boost::thread(boost::bind(&keyServer::runOptimalSolver, server));
    while (true) {
        Socket tmpSocket = socket.Listen();
        th = new boost::thread(boost::bind(&keyServer::runKeyGen, server, tmpSocket));
        th->detach();
    }
    return 0;
}