#ifndef TEDSTORE_SENDER_HPP
#define TEDSTORE_SENDER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "socket.hpp"

class Sender {
private:
    std::mutex mutexSocket_;
    Socket socket_;
    int clientID_;
    messageQueue<Data_t>* inputMQ_;
    CryptoPrimitive* cryptoObj_;

public:
    Sender();

    ~Sender();

    //status define in protocol.hpp
    bool sendRecipe(Recipe_t request, RecipeList_t requestList, int& status);
    bool sendChunkList(ChunkList_t request, int& status);
    bool sendChunkList(char* requestBufferIn, int sendBufferSize, int sendChunkNumber, int& status);

    //send chunk when socket free
    void run();

    //general send data
    bool sendData(u_char* request, int requestSize, u_char* respond, int& respondSize, bool recv);
    bool sendEndFlag();
    bool insertMQFromEncoder(Data_t& newChunk);
    bool extractMQFromEncoder(Data_t& newChunk);
    bool editJobDoneFlag();
};

#endif //TEDSTORE_SENDER_HPP
