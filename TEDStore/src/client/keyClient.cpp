#include "keyClient.hpp"
#include "openssl/rsa.h"
#include <sys/time.h>

extern Configure config;

struct timeval timestartKey;
struct timeval timeendKey;
struct timeval timestartKeySocket;
struct timeval timeendKeySocket;

#if ENCODER_MODULE_ENABLED == 1

KeyClient::KeyClient(Encoder* encoderObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    encoderObj_ = encoderObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    sendShortHashMaskBitNumber = config.getSendShortHashMaskBitNumber();
}

#else

KeyClient::KeyClient(Sender* senderObjTemp)
{
    inputMQ_ = new messageQueue<Data_t>;
    senderObj_ = senderObjTemp;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keySecurityChannel_ = new ssl(config.getKeyServerIP(), config.getKeyServerPort(), CLIENTSIDE);
    sslConnection_ = keySecurityChannel_->sslConnect().second;
    sendShortHashMaskBitNumber = config.getSendShortHashMaskBitNumber();
}
#endif

KeyClient::KeyClient(uint64_t keyGenNumber)
{
    inputMQ_ = new messageQueue<Data_t>;
    cryptoObj_ = new CryptoPrimitive();
    keyBatchSize_ = (int)config.getKeyBatchSize();
    keyGenNumber_ = keyGenNumber;
    sendShortHashMaskBitNumber = config.getSendShortHashMaskBitNumber();
}

KeyClient::~KeyClient()
{
    if (cryptoObj_ != NULL) {
        delete cryptoObj_;
    }
#if QUEUE_TYPE == QUEUE_TYPE_LOCKFREE_SPSC_QUEUE || QUEUE_TYPE == QUEUE_TYPE_LOCKFREE_QUEUE
    inputMQ_->~messageQueue();
    delete inputMQ_;
#endif
}

void KeyClient::runKeyGenSimulator()
{

#if SYSTEM_BREAK_DOWN == 1
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
    u_char chunkShortHash[singleChunkHashSize * keyBatchSize_];
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
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartKeySimulator, NULL);
#endif
            char hash[16];
            MurmurHash3_x64_128((void const*)chunkTemp, 5 * CHUNK_HASH_SIZE, 0, (void*)hash);
            for (int i = 0; i < 4; i++) {
                memcpy(&hashInt[i], hash + i * sizeof(int), sizeof(int));
            }
            for (int i = 0; i < 4; i++) {
                hashInt[i] &= maskInt;
                memcpy(chunkShortHash + batchNumber * singleChunkHashSize + i * sizeof(int), &hashInt[i], sizeof(int));
            }
#if SYSTEM_BREAK_DOWN == 1
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
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartKeySimulator, NULL);
#endif
            bool keyExchangeStatus = keyExchange(chunkShortHash, batchNumber, chunkKey, batchedKeySize, keySecurityChannel, sslConnection);
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendKeySimulator, NULL);
            diff = 1000000 * (timeendKeySimulator.tv_sec - timestartKeySimulator.tv_sec) + timeendKeySimulator.tv_usec - timestartKeySimulator.tv_usec;
            second = diff / 1000000.0;
            keyExchangeTime += second;
            keyGenTime += second;
#endif
            memset(chunkShortHash, 0, singleChunkHashSize * keyBatchSize_);
            memset(chunkKey, 0, CHUNK_HASH_SIZE * keyBatchSize_);
            batchNumber = 0;
            if (!keyExchangeStatus) {
                cerr << "KeyClient : error get key for " << setbase(10) << batchNumber << " chunks" << endl;
                return;
            } else {
                u_char newKeyBuffer[CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE];
                for (int i = 0; i < batchNumber; i++) {
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartKeySimulator, NULL);
#endif
                    u_char tempKey[32];
                    memset(newKeyBuffer, 1, CHUNK_HASH_SIZE);
                    memcpy(newKeyBuffer + CHUNK_HASH_SIZE, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
                    cryptoObj_->generateHash(newKeyBuffer, CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE, tempKey);
#if SYSTEM_BREAK_DOWN == 1
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
#if SYSTEM_BREAK_DOWN == 1
    cerr << "KeyClient : key exchange work time = " << keyGenTime << " s, total key generated is " << currentKeyGenNumber << endl;
    cerr << "KeyClient : Short hash time = " << shortHashTime << " s" << endl;
    cerr << "KeyClient : key exchange time = " << keyExchangeTime << " s" << endl;
    cerr << "KeyClient : key derivation time = " << keyDerivationTime << " s" << endl;
#endif
    return;
}

void KeyClient::run()
{
#if SYSTEM_BREAK_DOWN == 1
    double keyGenTime = 0;
    double shortHashTime = 0;
    double keyDerivationTime = 0;
    double keyExchangeTime = 0;
    // double generatePlainChunkHashTime = 0;
    double chunkContentEncryptionTime = 0;
    double generateCipherChunkHashTime = 0;
    long diff;
    double second;
#endif
    vector<Data_t> batchList;
    batchList.reserve(keyBatchSize_);
    int batchNumber = 0;
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_];
    int singleChunkHashSize = 4 * sizeof(int);
    u_char chunkShortHash[singleChunkHashSize * keyBatchSize_];
    bool JobDoneFlag = false;
    uint32_t maskInt = 0;
    for (int i = 0; i < sendShortHashMaskBitNumber; i++) {
        maskInt &= ~(1 << (32 - i));
    }
    int hashInt[4];
    while (true) {

        Data_t tempChunk;
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            JobDoneFlag = true;
        }
        if (extractMQ(tempChunk)) {
            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
#if ENCODER_MODULE_ENABLED == 1
                encoderObj_->insertMQ(tempChunk);
#else
                senderObj_->insertMQ(tempChunk);
#endif
                continue;
            }
#if SYSTEM_BREAK_DOWN == 1
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
                memcpy(chunkShortHash + batchNumber * singleChunkHashSize + i * sizeof(int), &hashInt[i], sizeof(int));
            }
            batchNumber++;
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendKey, NULL);
            diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
            second = diff / 1000000.0;
            keyGenTime += second;
            shortHashTime += second;
#endif
        }
        if (batchNumber == keyBatchSize_ || JobDoneFlag) {
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartKey, NULL);
#endif
            int batchedKeySize = 0;
            bool keyExchangeStatus = keyExchange(chunkShortHash, batchNumber, chunkKey, batchedKeySize);
#if SYSTEM_BREAK_DOWN == 1
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
// #if SYSTEM_BREAK_DOWN == 1
//                     gettimeofday(&timestartKey, NULL);
// #endif
//                     cryptoObj_->generateHash(batchList[i].chunk.logicData, batchList[i].chunk.logicDataSize, batchList[i].chunk.chunkHash);
// #if SYSTEM_BREAK_DOWN == 1
//                     gettimeofday(&timeendKey, NULL);
//                     diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
//                     second = diff / 1000000.0;
//                     keyGenTime += second;
//                     generatePlainChunkHashTime += second;
// #endif
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    memcpy(newKeyBuffer, batchList[i].chunk.chunkHash, CHUNK_HASH_SIZE);
                    memcpy(newKeyBuffer + CHUNK_HASH_SIZE, chunkKey + i * CHUNK_ENCRYPT_KEY_SIZE, CHUNK_ENCRYPT_KEY_SIZE);
                    cryptoObj_->generateHash(newKeyBuffer, CHUNK_ENCRYPT_KEY_SIZE + CHUNK_ENCRYPT_KEY_SIZE, batchList[i].chunk.encryptKey);
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    keyGenTime += second;
                    keyDerivationTime += second;
#endif
#if ENCODER_MODULE_ENABLED == 1
                    encoderObj_->insertMQ(batchList[i]);
#else
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartKey, NULL);
#endif
                    u_char ciphertext[batchList[i].chunk.logicDataSize];
                    bool encryptChunkContentStatus = cryptoObj_->encryptWithKey(batchList[i].chunk.logicData, batchList[i].chunk.logicDataSize, batchList[i].chunk.encryptKey, ciphertext);
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendKey, NULL);
                    diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                    second = diff / 1000000.0;
                    chunkContentEncryptionTime += second;
#endif
                    if (!encryptChunkContentStatus) {
                        cerr << "KeyClient : cryptoPrimitive error, encrypt chunk logic data error" << endl;
                        return;
                    } else {
                        memcpy(batchList[i].chunk.logicData, ciphertext, batchList[i].chunk.logicDataSize);
#if SYSTEM_BREAK_DOWN == 1
                        gettimeofday(&timestartKey, NULL);
#endif
                        bool generateCipherChunkHashStatus = cryptoObj_->generateHash(batchList[i].chunk.logicData, batchList[i].chunk.logicDataSize, batchList[i].chunk.chunkHash);
#if SYSTEM_BREAK_DOWN == 1
                        gettimeofday(&timeendKey, NULL);
                        diff = 1000000 * (timeendKey.tv_sec - timestartKey.tv_sec) + timeendKey.tv_usec - timestartKey.tv_usec;
                        second = diff / 1000000.0;
                        generateCipherChunkHashTime += second;
#endif
                        if (!generateCipherChunkHashStatus) {
                            cerr << "KeyClient : cryptoPrimitive error, generate cipher chunk hash error" << endl;
                            return;
                        } else {
                            senderObj_->insertMQ(batchList[i]);
                        }
                    }
#endif
                }
                batchList.clear();
                batchList.reserve(keyBatchSize_);
                memset(chunkShortHash, 0, singleChunkHashSize * keyBatchSize_);
                memset(chunkKey, 0, CHUNK_ENCRYPT_KEY_SIZE * keyBatchSize_);
                batchNumber = 0;
            }
        }
        if (JobDoneFlag) {
#if ENCODER_MODULE_ENABLED == 1
            bool editJobDoneFlagStatus = encoderObj_->editJobDoneFlag();
#else
            bool editJobDoneFlagStatus = senderObj_->editJobDoneFlag();
#endif
            if (!editJobDoneFlagStatus) {
                cerr << "KeyClient : error to set job done flag for encoder" << endl;
            }
            break;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
    cerr << "KeyClient : chunk short hash compute work time = " << shortHashTime << " s" << endl;
    cerr << "KeyClient : key exchange work time = " << keyExchangeTime << " s" << endl;
    cerr << "KeyClient : key derviation work time = " << keyDerivationTime << " s" << endl;
    // cerr << "KeyClient : socket send time = " << keySocketSendTime << " s" << endl;
    // cerr << "KeyClient : socket recv time = " << keySocketRecvTime << " s" << endl;
    cerr << "KeyClient : keyGen total work time = " << keyGenTime << " s" << endl;
    cerr << "KeyClient : encrypt chunk content work time = " << chunkContentEncryptionTime << " s" << endl;
    cerr << "KeyClient : cipher chunk crypto hash generate work time = " << generateCipherChunkHashTime << " s" << endl;
#endif
    return;
}

bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber)
{
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKeySocket, NULL);
#endif
    if (!keySecurityChannel_->send(sslConnection_, (char*)batchHashList, 4 * sizeof(uint32_t) * batchNumber)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKeySocket, NULL);
    keySocketSendTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
#endif
    char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber];
    int recvSize;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartKeySocket, NULL);
#endif
    if (!keySecurityChannel_->recv(sslConnection_, recvBuffer, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendKeySocket, NULL);
    keySocketRecvTime += (1000000 * (timeendKeySocket.tv_sec - timestartKeySocket.tv_sec) + timeendKeySocket.tv_usec - timestartKeySocket.tv_usec) / 1000000.0;
#endif
    if (recvSize % CHUNK_ENCRYPT_KEY_SIZE != 0) {
        cerr << "KeyClient: recv size % CHUNK_ENCRYPT_KEY_SIZE not equal to 0" << endl;
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

bool KeyClient::keyExchange(u_char* batchHashList, int batchNumber, u_char* batchKeyList, int& batchkeyNumber, ssl* securityChannel, SSL* sslConnection)
{

    if (!securityChannel->send(sslConnection, (char*)batchHashList, 4 * sizeof(uint32_t) * batchNumber)) {
        cerr << "KeyClient: send socket error" << endl;
        return false;
    }

    char recvBuffer[CHUNK_ENCRYPT_KEY_SIZE * batchNumber];
    int recvSize;

    if (!securityChannel->recv(sslConnection, recvBuffer, recvSize)) {
        cerr << "KeyClient: recv socket error" << endl;
        return false;
    }

    if (recvSize % CHUNK_ENCRYPT_KEY_SIZE != 0) {
        cerr << "KeyClient: recv size % CHUNK_ENCRYPT_KEY_SIZE not equal to 0" << endl;
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

bool KeyClient::insertMQ(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool KeyClient::extractMQ(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool KeyClient::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}
