#include "keyClient.hpp"
#include "openssl/rsa.h"
#include <sys/time.h>

extern Configure config;

struct timeval timestartKey;
struct timeval timeendKey;
struct timeval timestartKeySocket;
struct timeval timeendKeySocket;

keyClient::keyClient(Sender* senderObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    senderObj_ = senderObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    sendShortHashMaskBitNumber = config.getSendShortHashMaskBitNumber();

    // for multiple key managers
    this->keyManNum_ = config.getKeyManagerNumber();
    this->keyManagerIPList_ = config.getKeyManagerIPList();
    keySecurityChannelArray_ = new ssl*[this->keyManNum_];
    sslConnectionArray_ = new SSL*[this->keyManNum_];
    chunkHashArray_ = new u_char*[this->keyManNum_];
    counterArray_ = new uint32_t[this->keyManNum_];
    for (size_t i = 0; i < keyManNum_; i++) {
        string ip = keyManagerIPList_[i].first;
        int port = keyManagerIPList_[i].second;
        keySecurityChannelArray_[i] = new ssl(ip, port, CLIENTSIDE);
        sslConnectionArray_[i] = keySecurityChannelArray_[i]->sslConnect().second;
        chunkHashArray_[i] = new u_char[sizeof(keyGenEntry_t) * this->keyBatchSize_];
        counterArray_[i] = 0;
    }
    this->recordCache_ = new cache::lru_cache<string, uint32_t>(1000000);
}

keyClient::keyClient(uint64_t keyGenNumber)
{
    inputMQ_ = new messageQueue<Data_t>;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keyGenNumber_ = keyGenNumber;
    sendShortHashMaskBitNumber = config.getSendShortHashMaskBitNumber();
}

keyClient::~keyClient()
{   
    if (cryptoObj_ != NULL) {
        delete cryptoObj_;
    }
    inputMQ_->~messageQueue();
    delete inputMQ_;
    // for (size_t i = 0; i < this->keyManNum_; i++) {
    //     delete keySecurityChannelArray_[i];
    //     delete sslConnectionArray_[i];
    // }

    // for multiple key managers 
    for(int i = 0; i < this->keyManNum_; ++i) {
        delete [] this->chunkHashArray_[i];
        this->chunkHashArray_[i] = nullptr;
    }   

    delete [] this->chunkHashArray_;
    delete [] this->counterArray_;
    delete this->recordCache_;
    cerr << "KeyClient: Destory the key client successfully.\n" << endl;
}

void keyClient::runKeyGenSimulator()
{

#if BREAK_DOWN_DEFINE == 1
    double keyGenTime = 0;
    double shortHashTime = 0;
    double keyDerivationTime = 0;
    double keyExchangeTime = 0;
    long diff;
    double second;
    struct timeval timestartKeySimulator;
    struct timeval timeendKeySimulator;
#endif
    ssl* keySecurityChannel = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    SSL* sslConnection = keySecurityChannel->sslConnect().second;
    int batchNumber = 0;
    uint64_t currentKeyGenNumber = 0;
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_];
    int singleChunkHashSize = 4 * sizeof(int);
    u_char chunkHash[singleChunkHashSize * keyBatchSize_];
    uint32_t maskInt = 0;
    for (int i = 0; i < sendShortHashMaskBitNumber; i++) {
        maskInt &= ~(1 << (32 - i));
    }
    int hashInt[4];
    bool JobDoneFlag = false;
    while (true) {

        if (currentKeyGenNumber < keyGenNumber_) {

            u_char chunkTemp[5 * CHUNK_HASH_SIZE];
            memset(chunkTemp, currentKeyGenNumber, 5 * CHUNK_HASH_SIZE);
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKeySimulator, NULL);
#endif
            char hash[16];
            MurmurHash3_x64_128((void const*)chunkTemp, 5 * CHUNK_HASH_SIZE, 0, (void*)hash);
            for (int i = 0; i < 4; i++) {
                memcpy(&hashInt[i], hash + i * sizeof(int), sizeof(int));
            }
            for (int i = 0; i < 4; i++) {
                hashInt[i] &= maskInt;
                memcpy(chunkHash + batchNumber * singleChunkHashSize + i * sizeof(int), &hashInt[i], sizeof(int));
            }
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKeySimulator, NULL);
            diff = 1000000 * (timeendKeySimulator.tv_sec - timestartKeySimulator.tv_sec) + timeendKeySimulator.tv_usec - timestartKeySimulator.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
            shortHashTime += second;
#endif
            batchNumber++;
            currentKeyGenNumber++;
        } else {
            JobDoneFlag = true;
        }

        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
            int batchedKeySize = 0;
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKeySimulator, NULL);
#endif
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize, keySecurityChannel, sslConnection);
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKeySimulator, NULL);
            diff = 1000000 * (timeendKeySimulator.tv_sec - timestartKeySimulator.tv_sec) + timeendKeySimulator.tv_usec - timestartKeySimulator.tv_usec;
            second = diff / 1000000.0;
            keyExchangeTime += second;
            keyGenTime += second;
#endif
            memset(chunkHash, 0, singleChunkHashSize * keyBatchSize_);
            memset(chunkKey, 0, CHUNK_HASH_SIZE * keyBatchSize_);
            batchNumber = 0;
            if (!keyExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                u_char newKeyBuffer[CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE];
                for (int i = 0; i < batchNumber; i++) {
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timestartKeySimulator, NULL);
#endif
                    u_char tempKey[32];
                    memset(newKeyBuffer, 1, CHUNK_HASH_SIZE);
                    memcpy(newKeyBuffer + CHUNK_HASH_SIZE, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
                    cryptoObj_->generateHash(newKeyBuffer, CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE, tempKey);
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timeendKeySimulator, NULL);
                    diff = 1000000 * (timeendKeySimulator.tv_sec - timestartKeySimulator.tv_sec) + timeendKeySimulator.tv_usec - timestartKeySimulator.tv_usec;
                    second = diff / 1000000.0;
                    keyGenTime += second;
                    keyDerivationTime += second;
#endif
                }
            }
        }
        if (JobDoneFlag) {
            break;
        }
    }
#if BREAK_DOWN_DEFINE == 1
    cerr << "KeyClient : key exchange work time = " << keyGenTime << " s, total key generated is " << currentKeyGenNumber << endl;
    cerr << "KeyClient : Short hash time = " << shortHashTime << " s" << endl;
    cerr << "KeyClient : key exchange time = " << keyExchangeTime << " s" << endl;
    cerr << "KeyClient : key derivation time = " << keyDerivationTime << " s" << endl;
#endif
    return;
}

void keyClient::run()
{
#if BREAK_DOWN_DEFINE == 1
    double keyGenTime = 0;
    double shortHashTime = 0;
    double keyDerivationTime = 0;
    double encryptionTime = 0;
    double keyExchangeTime = 0;
    long diff;
    double second;
#endif
    vector<Data_t> batchList;
    batchList.reserve(keyBatchSize_);
    int batchNumber = 0;
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_];
    int singleChunkHashSize = 4 * sizeof(int);
    u_char chunkHash[singleChunkHashSize * keyBatchSize_];
    bool JobDoneFlag = false;
    uint32_t maskInt = 0;
    for (int i = 0; i < sendShortHashMaskBitNumber; i++) {
        maskInt &= ~(1 << (32 - i));
    }
    int hashInt[4];
    while (true) {

        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            cerr << "KeyClient : Chunker jobs done, queue is empty" << endl;
            JobDoneFlag = true;
        }
        if (extractMQFromChunker(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                insertMQToSender(tempChunk);
                continue;
            }
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKey, NULL);
#endif
            batchList.push_back(tempChunk);
            char hash[16];
            MurmurHash3_x64_128((void const*)tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, 0, (void*)hash);
            for (int i = 0; i < 4; i++) {
                memcpy(&hashInt[i], hash + i * sizeof(int), sizeof(int));
            }
            for (int i = 0; i < 4; i++) {
                hashInt[i] &= maskInt;
                memcpy(chunkHash + batchNumber * singleChunkHashSize + i * sizeof(int), &hashInt[i], sizeof(int));
            }
            batchNumber++;
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
            shortHashTime += second;
#endif
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKey, NULL);
#endif
            int batchedKeySize = 0;
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize);
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
            keyExchangeTime += second;
#endif
            if (!keyExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                u_char newKeyBuffer[CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE];
                for (int i = 0; i < batchNumber; i++) {
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    memcpy(newKeyBuffer, batchList[i].chunk.chunkHash, CHUNK_HASH_SIZE);
                    memcpy(newKeyBuffer + CHUNK_HASH_SIZE, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
                    cryptoObj_->generateHash(newKeyBuffer, CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE, batchList[i].chunk.encryptKey);
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    keyGenTime += second;
                    keyDerivationTime += second;
#endif
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    bool encodeChunkStatus = encodeChunk(batchList[i]);
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    encryptionTime += second;
#endif
                    if (encodeChunkStatus) {
                        insertMQToSender(batchList[i]);
                    } else {
                        cerr << "KeyClient : encode chunk error, exiting" << endl;
                        return;
                    }
                }
                batchList.clear();
                batchList.reserve(keyBatchSize_);
                memset(chunkHash, 0, singleChunkHashSize * keyBatchSize_);
                memset(chunkKey, 0, CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_);
                batchNumber = 0;
            }
        }
        if (JobDoneFlag) {
            if (!senderObj_->editJobDoneFlag()) {
                cerr << "KeyClient : error to set job done flag for sender" << endl;
            } else {
                cerr << "KeyClient : key exchange thread job done, exit now" << endl;
            }
            break;
        }
    }
#if BREAK_DOWN_DEFINE == 1
    cerr << "KeyClient : keyGen total work time = " << keyGenTime << " s" << endl;
    cerr << "KeyClient : short hash compute work time = " << shortHashTime << " s" << endl;
    cerr << "KeyClient : key exchange work time = " << keyExchangeTime << " s" << endl;
    cerr << "KeyClient : key derivation work time = " << keyDerivationTime << " s" << endl;
    cerr << "KeyClient : encryption work time = " << encryptionTime << " s" << endl;
    cerr << "KeyClient : socket send time = " << keySocketSendTime << " s" << endl;
    cerr << "KeyClient : socket recv time = " << keySocketRecvTime << " s" << endl;
#endif
    return;
}

bool keyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber)
{
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartKeySocket, NULL);
#endif
    if (!keySecurityChannel_->send(sslConnection_, (char*)batchHashList, 4 * sizeof(uint32_t) * batchNumber)) {
        cerr << "keyClient: send socket error" << endl;
        return false;
    }
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendKeySocket, NULL);
    keySocketSendTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
#endif
    char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber];
    int recvSize;
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartKeySocket, NULL);
#endif
    if (!keySecurityChannel_->recv(sslConnection_, recvBuffer, recvSize)) {
        cerr << "keyClient: recv socket error" << endl;
        return false;
    }
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendKeySocket, NULL);
    keySocketRecvTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
#endif
    if (recvSize % CHUNK_ENCRYPT_KEY_SIZE != 0) {
        cerr << "keyClient: recv size % CHUNK_ENCRYPT_KEY_SIZE not equal to 0" << endl;
        return false;
    }
    batchkeyNumber = recvSize / CHUNK_ENCRYPT_KEY_SIZE;
    if (batchkeyNumber == batchNumber) {
        memcpy(batchKeyList, recvBuffer, recvSize);
        return true;
    } else {
        return false;
    }
}

bool keyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection)
{
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartKeySocket, NULL);
#endif
    if (!securityChannel->send(sslConnection, (char*)batchHashList, sizeof(keyGenEntry_t) * batchNumber)) {
    // if (!securityChannel->send(sslConnection, (char*)batchHashList, 4 * sizeof(uint32_t)  * batchNumber)) {
        cerr << "keyClient: send socket error" << endl;
        return false;
    }
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendKeySocket, NULL);
    keySocketSendTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
#endif
    char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber];
    int recvSize;
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartKeySocket, NULL);
#endif
    if (!securityChannel->recv(sslConnection, recvBuffer, recvSize)) {
        cerr << "keyClient: recv socket error" << endl;
        return false;
    }
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendKeySocket, NULL);
    keySocketRecvTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
#endif
    if (recvSize % CHUNK_ENCRYPT_KEY_SIZE != 0) {
        cerr << "keyClient: recv size % CHUNK_ENCRYPT_KEY_SIZE not equal to 0" << endl;
        return false;
    }
    batchkeyNumber = recvSize / CHUNK_ENCRYPT_KEY_SIZE;
    if (batchkeyNumber == batchNumber) {
        memcpy(batchKeyList, recvBuffer, recvSize);
        return true;
    } else {
        return false;
    }
}

bool keyClient::encodeChunk(Data_t& newChunk)
{
    bool statusChunk = cryptoObj_->encryptChunk(newChunk.chunk);
    bool statusHash = cryptoObj_->generateHash(newChunk.chunk.logicData, newChunk.chunk.logicDataSize, newChunk.chunk.chunkHash);
    if (!statusChunk) {
        cerr << "KeyClient : error encrypt chunk" << endl;
        return false;
    } else if (!statusHash) {
        cerr << "KeyClient : error compute hash" << endl;
        return false;
    } else {
        return true;
    }
}

bool keyClient::insertMQFromChunker(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool keyClient::extractMQFromChunker(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool keyClient::insertMQToSender(Data_t& newChunk)
{
    return senderObj_->insertMQFromKeyClient(newChunk);
}

bool keyClient::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}

/**
 * @brief fingerprint-based approach
 * 
 * @param fpValue the value of fingerprint
 * @return uint32_t the index of the key manager
 */
uint32_t keyClient::keyAssignment(uint32_t fpValue) {
    return fpValue % this->keyManNum_;
}


/**
 * @brief RR-based approach
 * 
 * @param totalCounter the total counter of processed chunks
 * @return uint32_t the index of the target key manager
 */
uint32_t keyClient::keyAssignment(uint32_t fpValue, uint32_t totalCounter) {
    return totalCounter % this->keyManNum_;
}

/**
 * @brief tunable assignment approach
 * 
 * @param fpValue the chunk fp value
 * @param counterArray current counter array
 * @return uint32_t the index of target key manager
 */
uint32_t keyClient::keyAssignment(uint32_t fpValue, uint32_t* counterArray) {
    uint32_t currentKeyID;
    uint32_t status;
    status = this->checkKeyMangerStatus(counterArray);
    if (status == this->keyManNum_) {
        // lower than threshold
        currentKeyID = fpValue % this->keyManNum_;
    } else {
        // higher than threshold
        currentKeyID = status;
    }
    return currentKeyID;
}

/**
 * @brief check current counter distribution
 * 
 * @param counterArray the current counter distribution
 * @return uint32_t the key manager with the minimum key manager
 */
uint32_t keyClient::checkKeyMangerStatus(uint32_t* counterArray) {
    std::vector<uint32_t> counterVec;
    for (size_t i = 0; i < this->keyManNum_; i++) {
        counterVec.push_back(counterArray[i]);
    }

    uint32_t min;
    min = *std::min_element(counterVec.begin(), counterVec.end());
    uint32_t minIndex = std::min_element(counterVec.begin(), counterVec.end()) - counterVec.begin();

    uint32_t max;
    max = *std::max_element(counterVec.begin(), counterVec.end());

    if ((max - min) <= this->deivationThreshold_) {
        return this->keyManNum_;
    } else {
        return minIndex;
    }
}

/**
 * @brief tunable assignment approach (enhanced)
 * 
 * @param fpValue the chunk fp value
 * @param counterArray current counter array
 * @param fp the chunk fingerprint
 * @return uint32_t the index of target key manager
 */
uint32_t keyClient::keyAssignment(uint32_t fpValue, uint32_t* counterArray, string fp) {
    uint32_t status;
    uint32_t tmpRes;
    uint32_t currentKeyID;
    status = this->checkKeyMangerStatus(counterArray);
    if (status == this->keyManNum_) {
        // lower than threshold
        tmpRes = fpValue;
        currentKeyID = tmpRes % this->keyManNum_;
    } else {
        bool cacheStatus = this->recordCache_->exists(fp);
        // bool cacheStatus = this->lastKeyManager_.contains(keyStr);
        if (cacheStatus) {
            // exists
            currentKeyID = this->recordCache_->get(fp);    
            if (currentKeyID == this->GetMaxIndex(counterArray)) {
                currentKeyID = status;
                this->recordCache_->put(fp, currentKeyID);
            }    
        } else {
            // not exists
            currentKeyID = status;
            this->recordCache_->put(fp, currentKeyID);   
        }
        
    }
    return currentKeyID;
}


/**
 * @brief get the maximum index of counter array
 * 
 * @param counterArray the current counter distribution
 * @return uint32_t the key manager with the maximum key manager
 */
uint32_t keyClient::GetMaxIndex(uint32_t* counterArray) {
    std::vector<uint64_t> counterVec;
    for (size_t i = 0; i < this->keyManNum_; i++) {
        counterVec.push_back(counterArray[i]);
    }
    uint32_t maxIndex = std::max_element(counterVec.begin(), counterVec.end()) - counterVec.begin();
    return maxIndex;
}

uint32_t keyClient::convertFPtoValue(Data_t& newChunk) 
{
    uint32_t res = 0;
    for (size_t i = 0; i < CHUNK_HASH_SIZE; i++) {
        res += static_cast<uint8_t>(newChunk.chunk.chunkHash[i]);
    }
    return res;
}

void keyClient::runSimple() {
#if BREAK_DOWN_DEFINE == 1
    double keyGenTime = 0;
    double shortHashTime = 0;
    double keyDerivationTime = 0;
    double encryptionTime = 0;
    double keyExchangeTime = 0;
    long diff;
    double second;
#endif
    vector<Data_t> batchList;
    batchList.reserve(keyBatchSize_);
    int batchNumber = 0;
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_];
    int singleChunkHashSize = 4 * sizeof(int);
    // u_char chunkHash[singleChunkHashSize * keyBatchSize_];
    // TODO: here we define the keyGenEntry_t to define whether using this hash to count
    u_char chunkHash[sizeof(keyGenEntry_t) * keyBatchSize_];
    bool JobDoneFlag = false;
    uint32_t maskInt = 0;
    for (int i = 0; i < sendShortHashMaskBitNumber; i++) {
        maskInt &= ~(1 << (32 - i));
    }
    int hashInt[4];
    
    while (true) {
        keyGenEntry_t tempKeyGenEntry;
        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            cerr << "KeyClient : Chunker jobs done, queue is empty" << endl;
            JobDoneFlag = true;
        }
        if (extractMQFromChunker(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                insertMQToSender(tempChunk);
                continue;
            }
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKey, NULL);
#endif
            batchList.push_back(tempChunk);
            char hash[16];

            // for multiple key manager
            uint32_t fpValue;
            uint32_t keyManagerIndex = 0;
            fpValue = convertFPtoValue(tempChunk);

            // assign the key manager here 
            if (ROUTE_APPROACH == FP_SCHEME) {
                keyManagerIndex = this->keyAssignment(fpValue);
            } else if (ROUTE_APPROACH == RR_SCHEME) {
                keyManagerIndex = this->keyAssignment(fpValue, this->totalProcessedChunk_);
            } else if (ROUTE_APPROACH == BASIC_SCHEME) {
                keyManagerIndex = this->keyAssignment(fpValue, counterArray_);
            } else if (ROUTE_APPROACH == ENHANCE_SCHEME) {
                string fp((char*)tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
                keyManagerIndex = this->keyAssignment(fpValue, counterArray_, fp);
            } else {
                fprintf(stderr, "keyClient: Error type.\n");
                exit(EXIT_FAILURE);
            }
            fprintf(stderr, "Choose key manager index: %u\n", keyManagerIndex);

            MurmurHash3_x64_128((void const*)tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, 0, (void*)hash);
            for (int i = 0; i < 4; i++) {
                memcpy(&hashInt[i], hash + i * sizeof(int), sizeof(int));
            }
            for (int i = 0; i < 4; i++) {
                hashInt[i] &= maskInt;
                // for multiple key managers 
                memcpy(&tempKeyGenEntry.singleChunkHash + i * sizeof(int), &hashInt[i], sizeof(int));
                // memcpy(chunkHash + batchNumber * singleChunkHashSize + i * sizeof(int), &hashInt[i], sizeof(int));
            }
            for (size_t i = 0; i < this->keyManNum_; i++) {
                tempKeyGenEntry.usingCount = false;
                if (i == keyManagerIndex) {
                    tempKeyGenEntry.usingCount = true;
                    // memcpy(chunkHash + batchNumber * sizeof(keyGenEntry_t) , &tempKeyGenEntry, sizeof(keyGenEntry_t));
                    memcpy(chunkHashArray_[i] + batchNumber * sizeof(keyGenEntry_t) , &tempKeyGenEntry, sizeof(keyGenEntry_t));
                } 
            }
            batchNumber++;
            counterArray_[keyManagerIndex]++; 
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
            shortHashTime += second;
#endif
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timestartKey, NULL);
#endif
            int batchedKeySize = 0;
            // bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize);
            // bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize, 
            //     this->keySecurityChannel_, this->sslConnection_);
            // TODO: add mutiple thread here 
            bool keyExchangeStatus[this->keyManNum_];
            for (size_t i = 0; i < this->keyManNum_; i++) {
                keyExchangeStatus[i] = keyExchange(chunkHashArray_[i], batchNumber, chunkKey, batchedKeySize, 
                    this->keySecurityChannelArray_[i], this->sslConnectionArray_[i]);
            }
#if BREAK_DOWN_DEFINE == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
            keyExchangeTime += second;
#endif
            bool wholeExchangeStatus = true;
            for (size_t i = 0; i < this->keyManNum_; i++) {
                wholeExchangeStatus = wholeExchangeStatus && keyExchangeStatus[i];
            }
            cout << wholeExchangeStatus << endl;
            if (!wholeExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                u_char newKeyBuffer[CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE];
                for (int i = 0; i < batchNumber; i++) {
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    memcpy(newKeyBuffer, batchList[i].chunk.chunkHash, CHUNK_HASH_SIZE);
                    memcpy(newKeyBuffer + CHUNK_HASH_SIZE, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
                    cryptoObj_->generateHash(newKeyBuffer, CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE, batchList[i].chunk.encryptKey);
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    keyGenTime += second;
                    keyDerivationTime += second;
#endif
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    bool encodeChunkStatus = encodeChunk(batchList[i]);
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    encryptionTime += second;
#endif
                    if (encodeChunkStatus) {
                        insertMQToSender(batchList[i]);
                    } else {
                        cerr << "KeyClient : encode chunk error, exiting" << endl;
                        return;
                    }
                }
                batchList.clear();
                batchList.reserve(keyBatchSize_);
                memset(chunkHash, 0, singleChunkHashSize * keyBatchSize_);
                memset(chunkKey, 0, CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_);
                batchNumber = 0;
            }
        }
        if (JobDoneFlag) {
            if (!senderObj_->editJobDoneFlag()) {
                cerr << "KeyClient : error to set job done flag for sender" << endl;
            } else {
                cerr << "KeyClient : key exchange thread job done, exit now" << endl;
            }
            break;
        }
    }
#if BREAK_DOWN_DEFINE == 1
    cerr << "KeyClient : keyGen total work time = " << keyGenTime << " s" << endl;
    cerr << "KeyClient : short hash compute work time = " << shortHashTime << " s" << endl;
    cerr << "KeyClient : key exchange work time = " << keyExchangeTime << " s" << endl;
    cerr << "KeyClient : key derviation work time = " << keyDerivationTime << " s" << endl;
    cerr << "KeyClient : encryption work time = " << encryptionTime << " s" << endl;
    cerr << "KeyClient : socket send time = " << keySocketSendTime << " s" << endl;
    cerr << "KeyClient : socket recv time = " << keySocketRecvTime << " s" << endl;
#endif
    return;
}


void keyClient::runSS() {

}