#ifndef TEDSTORE__ENCODER_HPP
#define TEDSTORE__ENCODER_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "sender.hpp"
#include "ssl.hpp"

class Encoder {
private:
    messageQueue<Data_t>* inputMQ_;
    Sender* senderObj_;
    CryptoPrimitive* cryptoObj_;

public:
    Encoder(Sender* senderObjTemp);
    ~Encoder();
    void run();
    bool encodeChunk(Data_t& newChunk);
    bool insertMQFromKeyClient(Data_t& newChunk);
    bool extractMQFromKeyClient(Data_t& newChunk);
    bool insertMQToSender(Data_t& newChunk);
    bool editJobDoneFlag();
    bool setJobDoneFlag();
};

#endif //TEDSTORE__ENCODER_HPP