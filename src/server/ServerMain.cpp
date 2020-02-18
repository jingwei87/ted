#include "boost/thread.hpp"
#include "configure.hpp"
#include "dataSR.hpp"
#include "database.hpp"
#include "dedupCore.hpp"
#include "messageQueue.hpp"
#include "storageCore.hpp"
#include <signal.h>
Configure config("config.json");

Database fp2ChunkDB;
Database fileName2metaDB;

DataSR* dataSRObj;
StorageCore* storageObj;
DedupCore* dedupCoreObj;
vector<boost::thread*> thList;

void CTRLC(int s)
{
    cerr << "server close" << endl;
    if (storageObj != nullptr)
        delete storageObj;
    if (dataSRObj != nullptr)
        delete dataSRObj;
    if (dedupCoreObj != nullptr)
        delete dedupCoreObj;
    for (auto it : thList) {
        it->join();
    }
    exit(0);
}

int main()
{

    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    fp2ChunkDB.openDB(config.getFp2ChunkDBName());
    fileName2metaDB.openDB(config.getFp2MetaDBame());

    dedupCoreObj = new DedupCore();
    storageObj = new StorageCore();
    dataSRObj = new DataSR(storageObj, dedupCoreObj);

    boost::thread* th;
    boost::thread::attributes attrs;
    attrs.set_stack_size(200 * 1024 * 1024);
    Socket socketData(SERVER_TCP, "", config.getStorageServerPort());
    while (true) {
        Socket tmpSocket = socketData.Listen();
        th = new boost::thread(attrs, boost::bind(&DataSR::run, dataSRObj, tmpSocket));
        thList.push_back(th);
    }

    return 0;
}
