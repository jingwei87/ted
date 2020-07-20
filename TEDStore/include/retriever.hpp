#ifndef TEDSTORE_RETRIEVER_HPP
#define TEDSTORE_RETRIEVER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "recvDecode.hpp"
#include "socket.hpp"
#include <bits/stdc++.h>
#include <boost/thread.hpp>

using namespace std;

class Retriever {
private:
    int chunkCnt_;
    std::ofstream retrieveFile_;
    RecvDecode* recvDecodeObj_;
    // unordered_map<uint32_t, string> chunkTempList_;
    std::mutex multiThreadWriteMutex;
    uint32_t currentID_ = 0;
    uint32_t totalChunkNumber_;
    uint32_t totalRecvNumber_ = 0;
#if SYSTEM_BREAK_DOWN == 1
    double writeFileTime_ = 0;
#endif
public:
    Retriever(string fileName, RecvDecode*& recvDecodeObjTemp);
    ~Retriever();
    void recvThread();
    void retrieveFileThread();
    bool extractMQFromRecvDecode(RetrieverData_t& data);
};

#endif //TEDSTORE_RETRIEVER_HPP
