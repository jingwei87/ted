#ifndef TEDSTORE_DATASR_HPP
#define TEDSTORE_DATASR_HPP

#include "boost/bind.hpp"
#include "boost/thread.hpp"
#include "configure.hpp"
#include "dataStructure.hpp"
#include "dedupCore.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "socket.hpp"
#include "storageCore.hpp"
#include <bits/stdc++.h>

using namespace std;

extern Configure config;

class DataSR {
private:
    StorageCore* storageObj_;
    DedupCore* dedupCoreObj_;
    uint32_t restoreChunkBatchSize;

public:
    DataSR(StorageCore* storageObj, DedupCore* dedupCoreObj);
    ~DataSR() {};
    void run(Socket socket);
};

#endif //TEDSTORE_DATASR_HPP
