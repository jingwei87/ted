#include "keyserver.hh"

using namespace std;

KeyServer* keyserver;

int main(int argv, char** argc) {

	/* initialize server object */
	keyserver = new KeyServer(atoi(argc[1]));
	/* run server service */
	keyserver->runReceive();
	return 0;
}
