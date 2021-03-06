#ifndef TEDSTORE_RECIVER_HPP
#define TEDSTORE_RECIVER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "socket.hpp"
#include <bits/stdc++.h>

using namespace std;

class RecvDecode {
private:
    Socket socket_;
    Socket socketPow_;
    void receiveChunk();
    u_char fileNameHash_[FILE_NAME_HASH_SIZE];
    CryptoPrimitive* cryptoObj_;
    messageQueue<RetrieverData_t>* outPutMQ_;
    std::mutex multiThreadDownloadMutex;
    uint32_t totalRecvChunks = 0;
    int clientID_;

public:
    Recipe_t fileRecipe_;
    RecipeList_t fileRecipeList_;
    RecvDecode(string fileName);
    ~RecvDecode();
    void run();
    bool processRecipe(Recipe_t& recipeHead, RecipeList_t& recipeList, u_char* fileNameHash);
    bool recvChunks(ChunkList_t& recvChunk, int& chunkNumber, uint32_t& startID, uint32_t& endID);
    Recipe_t getFileRecipeHead();
    bool insertMQ(RetrieverData_t& newChunk);
    bool extractMQ(RetrieverData_t& newChunk);
    bool getJobDoneFlag();
};

#endif //TEDSTORE_RECIVER_HPP
