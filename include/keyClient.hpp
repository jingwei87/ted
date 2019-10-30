#ifndef GENERALDEDUPSYSTEM_KEYCLIENT_HPP
#define GENERALDEDUPSYSTEM_KEYCLIENT_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "murmurHash3.hpp"
#include "sender.hpp"
#include "ssl.hpp"

#define KEYMANGER_PUBLIC_KEY_FILE "key/serverpub.key"

class keyClient {
private:
    CryptoPrimitive* cryptoObj_;
    messageQueue<Data_t>* inputMQ_;
    Sender* senderObj_;
    int keyBatchSize_;
    ssl* keySecurityChannel_;
    SSL* sslConnection_;
    int sendShortHashMaskBitNumber;
    double keySocketRecvTime = 0;
    double keySocketSendTime = 0;

public:
    keyClient(Sender* senderObjTemp);
    ~keyClient();
    void run();
    bool encodeChunk(Data_t& newChunk);
    bool insertMQFromChunker(Data_t& newChunk);
    bool extractMQFromChunker(Data_t& newChunk);
    bool insertMQToSender(Data_t& newChunk);
    bool editJobDoneFlag();
    bool setJobDoneFlag();
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber);
};

#endif //GENERALDEDUPSYSTEM_KEYCLIENT_HPP
