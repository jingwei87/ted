#ifndef TEDSTORE_KEYCLIENT_HPP
#define TEDSTORE_KEYCLIENT_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#if ENCODER_MODULE_ENABLED == 1
#include "encoder.hpp"
#else
#include "sender.hpp"
#endif
#include "messageQueue.hpp"
#include "murmurHash3.hpp"
#include "ssl.hpp"

#define KEYMANGER_PUBLIC_KEY_FILE "key/serverpub.key"

class KeyClient {
private:
    CryptoPrimitive* cryptoObj_;
    messageQueue<Data_t>* inputMQ_;
#if ENCODER_MODULE_ENABLED == 1
    Encoder* encoderObj_;
#else
    Sender* senderObj_;
#endif
    int keyBatchSize_;
    ssl* keySecurityChannel_;
    SSL* sslConnection_;
    int sendShortHashMaskBitNumber;
#if SYSTEM_BREAK_DOWN == 1
    double keySocketRecvTime = 0;
    double keySocketSendTime = 0;
#endif
    int keyGenNumber_;

public:
#if ENCODER_MODULE_ENABLED == 1
    KeyClient(Encoder* encoderObjTemp);
#else
    KeyClient(Sender* senderObjTemp);
#endif
    KeyClient(uint64_t keyGenNumber);
    ~KeyClient();
    void run();
    void runKeyGenSimulator();
    bool insertMQ(Data_t& newChunk);
    bool extractMQ(Data_t& newChunk);
    bool editJobDoneFlag();
    bool setJobDoneFlag();
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber);
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection);
};

#endif //TEDSTORE_KEYCLIENT_HPP
