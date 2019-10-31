#include "keyClient.hpp"
#include "openssl/rsa.h"
#include <sys/time.h>

extern Configure config;

struct timeval timestartKey;
struct timeval timeendKey;
struct timeval timestartKeySocket;
struct timeval timeendKeySocket;

void PRINT_BYTE_ARRAY_KEY_CLIENT(
    FILE* file, void* mem, uint32_t len)
{
    if (!mem || !len) {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t* array = (uint8_t*)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        fprintf(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

keyClient::keyClient(Sender* senderObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    senderObj_ = senderObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    sendShortHashMaskBitNumber = config.getSendShortHashMaskBitNumber();
}

keyClient::~keyClient()
{
    if (cryptoObj_ != NULL) {
        delete cryptoObj_;
    }
    inputMQ_->~messageQueue();
    delete keySecurityChannel_;
    delete inputMQ_;
}

void keyClient::run()
{
    double keyGenTime = 0;
    double shortHashTime = 0;
    double keyDerivationTime = 0;
    double encryptionTime = 0;
    double keyExchangeTime = 0;
    long diff;
    double second;
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
            if (BREAK_DOWN_DEFINE) {
                gettimeofday(&timestartKey, NULL);
            }
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
            if (BREAK_DOWN_DEFINE) {
                gettimeofday(&timeendKey, NULL);
                diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                second = diff / 1000000.0;
                keyGenTime += second;
                shortHashTime += second;
            }
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
            if (BREAK_DOWN_DEFINE) {
                gettimeofday(&timestartKey, NULL);
            }
            int batchedKeySize = 0;
            bool keyExchangeStatus = keyExchange(chunkHash, batchNumber, chunkKey, batchedKeySize);
            if (BREAK_DOWN_DEFINE) {
                gettimeofday(&timeendKey, NULL);
                diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                second = diff / 1000000.0;
                keyGenTime += second;
                keyExchangeTime += second;
            }
            if (!keyExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                u_char newKeyBuffer[CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE];
                for (int i = 0; i < batchNumber; i++) {
                    if (BREAK_DOWN_DEFINE) {
                        gettimeofday(&timestartKey, NULL);
                    }
                    memcpy(newKeyBuffer, batchList[i].chunk.chunkHash, CHUNK_HASH_SIZE);
                    memcpy(newKeyBuffer + CHUNK_HASH_SIZE, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
                    cryptoObj_->generateHash(newKeyBuffer, CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE, batchList[i].chunk.encryptKey);
                    memcpy(batchList[i].chunk.encryptKey, batchList[i].chunk.chunkHash, CHUNK_HASH_SIZE);
                    if (BREAK_DOWN_DEFINE) {
                        gettimeofday(&timeendKey, NULL);
                        diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                        second = diff / 1000000.0;
                        keyGenTime += second;
                        keyDerivationTime += second;
                    }
                    if (BREAK_DOWN_DEFINE) {
                        gettimeofday(&timestartKey, NULL);
                    }
                    bool encodeChunkStatus = encodeChunk(batchList[i]);
                    if (BREAK_DOWN_DEFINE) {
                        gettimeofday(&timeendKey, NULL);
                        diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                        second = diff / 1000000.0;
                        encryptionTime += second;
                    }
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
    if (BREAK_DOWN_DEFINE) {
        cout << "KeyClient : keyGen total work time = " << keyGenTime << " s" << endl;
        cout << "KeyClient : short hash compute work time = " << shortHashTime << " s" << endl;
        cout << "KeyClient : key exchange work time = " << keyExchangeTime << " s" << endl;
        cout << "KeyClient : key derviation work time = " << keyDerivationTime << " s" << endl;
        cout << "KeyClient : encryption work time = " << encryptionTime << " s" << endl;
        cout << "KeyClient : socket send time = " << keySocketSendTime << " s" << endl;
        cout << "KeyClient : socket recv time = " << keySocketRecvTime << " s" << endl;
    }
    return;
}

bool keyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber)
{
    if (BREAK_DOWN_DEFINE) {
        gettimeofday(&timestartKeySocket, NULL);
    }
    if (!keySecurityChannel_->send(sslConnection_, (char*)batchHashList, 4 * sizeof(uint32_t) * batchNumber)) {
        cerr << "keyClient: send socket error" << endl;
        return false;
    }
    if (BREAK_DOWN_DEFINE) {
        gettimeofday(&timeendKeySocket, NULL);
        keySocketSendTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
    }
    char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber];
    int recvSize;
    if (BREAK_DOWN_DEFINE) {
        gettimeofday(&timestartKeySocket, NULL);
    }
    if (!keySecurityChannel_->recv(sslConnection_, recvBuffer, recvSize)) {
        cerr << "keyClient: recv socket error" << endl;
        return false;
    }
    if (BREAK_DOWN_DEFINE) {
        gettimeofday(&timeendKeySocket, NULL);
        keySocketRecvTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
    }
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
