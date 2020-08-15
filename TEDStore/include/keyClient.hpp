#ifndef TEDSTORE_KEYCLIENT_HPP
#define TEDSTORE_KEYCLIENT_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "messageQueue.hpp"
#include "murmurHash3.hpp"
#include "sender.hpp"
#include "ssl.hpp"
#include "lruCache.hpp"
#include "hHash.hpp"
#include <vector>
#include <map>
#include <utility>
#include <gmp.h>

#define KEYMANGER_PUBLIC_KEY_FILE "key/serverpub.key"


// for different routing scheme
#define BASIC_SCHEME 1
#define ENHANCE_SCHEME 2
#define FP_SCHEME 3
#define RR_SCHEME 4
#define ROUTE_APPROACH 4


using namespace std;
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
    int keyGenNumber_;

    // for multiple key manager configure
    uint32_t keyManNum_;
    vector<pair<string, int>> keyManagerIPList_;
    uint32_t deivationThreshold_ = 5000;
    uint32_t totalProcessedChunk_ = 0;
    cache::lru_cache<std::string, uint32_t>* recordCache_;

    // for multiple key managers
    ssl** keySecurityChannelArray_;
    SSL** sslConnectionArray_;
    u_char** chunkHashArray_;
    u_char** chunkKeyArray_;
    uint32_t* counterArray_;
    
    /**
     * @brief xor two buffer 
     * 
     * @param buffer1 store the result in buffer1
     * @param buffer2 
     * @param bufferSize the size of buffer in byte
     */
    inline void XORTwoBuffers(uint64_t* buffer1, uint64_t* buffer2, size_t bufferSize) {
        size_t length = bufferSize / sizeof(uint64_t);
        for (size_t i = 0; i < length; i ++) {
            buffer1[i] = buffer1[i] ^ buffer2[i];
        }
    }

    // for recover secret share 
    HHash* hHash_;
    mpz_t share_[K_PARA];
    mpz_t sharePara_[K_PARA];
    mpz_t finalSecret_;

    u_char* shareIndexArrayBuffer_;

public:
    keyClient(Sender* senderObjTemp);
    keyClient(uint64_t keyGenNumber);
    ~keyClient();
    void run();
    // for multiple key managers 
    void runSimple();
    void runSS();
    // 
    void runKeyGenSimulator();
    bool encodeChunk(Data_t& newChunk);
    bool insertMQFromChunker(Data_t& newChunk);
    bool extractMQFromChunker(Data_t& newChunk);
    bool insertMQToSender(Data_t& newChunk);
    bool editJobDoneFlag();
    bool setJobDoneFlag();
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber);
    bool keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection);
    // for multiple key managers
    bool keyExchangeSimple(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection);
    bool keyExchangeSimpleAll(u_char** batchHashList, int batchNumber, u_char** chunkKeyArray_, int& batchkeyNumber, 
        ssl** securityChannel, SSL** sslConnection);

    

    /**
     * @brief convert the chunk fp to a value
     * 
     * @param newChunk the reference to the chunk
     * @return uint32_t the value of chunk fp
     */
    uint32_t convertFPtoValue(Data_t& newChunk);
    
    /**
     * @brief fingerprint-based approach
     * 
     * @param fpValue the value of fingerprint
     * @return uint32_t the index of the target key manager
     */
    uint32_t keyAssignment(uint32_t fpValue);

    /**
     * @brief RR-based approach
     * 
     * @param totalCounter the total counter of processed chunks
     * @return uint32_t the index of the target key manager
     */
    uint32_t keyAssignment(uint32_t fpValue, uint32_t totalCounter);

    /**
     * @brief tunable assignment approach (basic)
     * 
     * @param fpValue the chunk fp value
     * @param counterArray current counter array
     * @return uint32_t the index of target key manager
     */
    uint32_t keyAssignment(uint32_t fpValue, uint32_t* counterArray);


    /**
     * @brief tunable assignment approach (enhanced)
     * 
     * @param fpValue the chunk fp value
     * @param counterArray current counter array
     * @param fp the chunk fingerprint
     * @return uint32_t the index of target key manager
     */
    uint32_t keyAssignment(uint32_t fpValue, uint32_t* counterArray, string fp);

    /**
     * @brief check current counter distribution
     * 
     * @param counterArray the current counter distribution
     * @return uint32_t the key manager with the minimum key manager
     */
    uint32_t checkKeyMangerStatus(uint32_t* counterArray);

    /**
     * @brief get the maximum index of counter array
     * 
     * @param counterArray the current counter distribution
     * @return uint32_t the key manager with the maximum key manager
     */
    uint32_t GetMaxIndex(uint32_t* counterArray);
};

#endif //TEDSTORE_KEYCLIENT_HPP
