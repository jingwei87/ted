#include "recvDecode.hpp"

extern Configure config;

struct timeval timestartRecvDecode;
struct timeval timeendRecvDecode;

RecvDecode::RecvDecode(string fileName)
{
    clientID_ = config.getClientID();
    outPutMQ_ = new messageQueue<RetrieverData_t>;
    cryptoObj_ = new CryptoPrimitive();
    socket_.init(CLIENT_TCP, config.getStorageServerIP(), config.getStorageServerPort());
    cryptoObj_->generateHash((u_char*)&fileName[0], fileName.length(), fileNameHash_);
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
    gettimeofday(&timestartRecvDecode, NULL);
#endif
    bool processRecipeStatus = processRecipe(fileRecipe_, fileRecipeList_, fileNameHash_);
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendRecvDecode, NULL);
    diff = 1000000 * (timeendRecvDecode.tv_sec - timestartRecvDecode.tv_sec) + timeendRecvDecode.tv_usec - timestartRecvDecode.tv_usec;
    second = diff / 1000000.0;
    cerr << "RecvDecode : process file recipes time = " << second << " s" << endl;
#endif
    if (processRecipeStatus) {
        cerr << "RecvDecode : recv file recipe head, file size = " << fileRecipe_.fileRecipeHead.fileSize << ", total chunk number = " << fileRecipe_.fileRecipeHead.totalChunkNumber << endl;
    } else {
        cerr << "RecvDecode : recv file recipe error" << endl;
        exit(0);
    }
}

RecvDecode::~RecvDecode()
{
    socket_.finish();
    if (cryptoObj_ != nullptr) {
        delete cryptoObj_;
    }
#if QUEUE_TYPE == QUEUE_TYPE_LOCKFREE_SPSC_QUEUE || QUEUE_TYPE == QUEUE_TYPE_LOCKFREE_QUEUE
    outPutMQ_->~messageQueue();
    delete outPutMQ_;
#endif
}

bool RecvDecode::processRecipe(Recipe_t& recipeHead, RecipeList_t& recipeList, u_char* fileNameHash)
{
    NetworkHeadStruct_t request, respond;
    request.messageType = CLIENT_DOWNLOAD_ENCRYPTED_RECIPE;
    request.dataSize = FILE_NAME_HASH_SIZE;
    request.clientID = clientID_;

    int sendSize = sizeof(NetworkHeadStruct_t) + FILE_NAME_HASH_SIZE;
    u_char requestBuffer[sendSize];

    memcpy(requestBuffer, &request, sizeof(NetworkHeadStruct_t));
    memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), fileNameHash, FILE_NAME_HASH_SIZE);
    // PRINT_BYTE_ARRAY_RECV(stdout, fileNameHash, FILE_NAME_HASH_SIZE);

    if (!socket_.Send(requestBuffer, sendSize)) {
        cerr << "RecvDecode : storage server closed" << endl;
        return false;
    }
    u_char respondBuffer[sizeof(NetworkHeadStruct_t)];
    int recvSize;
    if (!socket_.Recv(respondBuffer, recvSize)) {
        cerr << "RecvDecode : storage server closed" << endl;
        return false;
    }
    memcpy(&respond, respondBuffer, sizeof(NetworkHeadStruct_t));
    if (respond.messageType == ERROR_CLOSE) {
        cerr << "RecvDecode : Server reject download request!" << endl;
        return false;
    }
    if (respond.messageType == ERROR_FILE_NOT_EXIST) {
        cerr << "RecvDecode : Server reject download request, file not exist in server!" << endl;
        return false;
    }
    if (respond.messageType == ERROR_CHUNK_NOT_EXIST) {
        cerr << "RecvDecode : Server reject download request, chunk not exist in server!" << endl;
        return false;
    }
    if (respond.messageType == SUCCESS) {
        uint64_t recipeLength = respond.dataSize;
        cerr << "RecvDecode : recv recipe size = " << recipeLength << endl;
        u_char* encryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeLength + sizeof(NetworkHeadStruct_t));
        u_char* decryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeLength);

        if (!socket_.Recv(encryptedRecipeBuffer, recvSize)) {
            cerr << "RecvDecode : storage server closed" << endl;
            return false;
        } else {
            cerr << "RecvDecode : recv encrypted file recipes, message size = " << recvSize << endl;
        }
        memcpy(&respond, encryptedRecipeBuffer, sizeof(NetworkHeadStruct_t));
        if (recvSize != respond.dataSize + sizeof(NetworkHeadStruct_t)) {
            cerr << "RecvDecode : recv encrypted file recipe size error" << endl;
        } else {
            // cerr << "RecvDecode : recv encrypted file recipe size =" << respond.dataSize << endl;
            u_char clientKey[32];
            memset(clientKey, 1, 32);
            memcpy(&recipeHead, encryptedRecipeBuffer + sizeof(NetworkHeadStruct_t), sizeof(Recipe_t));
            // cerr << "RecvDecode : recv encrypted file recipes done, file size = " << recipeHead.fileRecipeHead.fileSize << endl;
            cryptoObj_->decryptWithKey(encryptedRecipeBuffer + sizeof(NetworkHeadStruct_t) + sizeof(Recipe_t), recipeLength - sizeof(Recipe_t), clientKey, decryptedRecipeBuffer);
            u_char* requestChunkList = (u_char*)malloc(sizeof(u_char) * sizeof(RecipeEntry_t) * recipeHead.fileRecipeHead.totalChunkNumber + sizeof(NetworkHeadStruct_t));
            for (uint64_t i = 0; i < recipeHead.fileRecipeHead.totalChunkNumber; i++) {
                RecipeEntry_t newRecipeEntry;
                memcpy(&newRecipeEntry, decryptedRecipeBuffer + i * sizeof(RecipeEntry_t), sizeof(RecipeEntry_t));
                recipeList.push_back(newRecipeEntry);
                memset(newRecipeEntry.chunkKey, 0, CHUNK_ENCRYPT_KEY_SIZE);
                memcpy(requestChunkList + sizeof(NetworkHeadStruct_t) + i * sizeof(RecipeEntry_t), &newRecipeEntry, sizeof(RecipeEntry_t));
                // cerr << "RecvDecode : recv chunk id = " << newRecipeEntry.chunkID << ", chunk size = " << newRecipeEntry.chunkSize << endl;
            }
            free(encryptedRecipeBuffer);
            free(decryptedRecipeBuffer);

            request.messageType = CLIENT_UPLOAD_DECRYPTED_RECIPE;
            request.dataSize = sizeof(uint64_t);
            uint64_t recipeListSize = recipeHead.fileRecipeHead.totalChunkNumber * sizeof(RecipeEntry_t);
            sendSize = sizeof(NetworkHeadStruct_t) + sizeof(uint64_t);
            u_char sendDecryptedRecipeSizeBuffer[sizeof(NetworkHeadStruct_t) + sizeof(uint64_t)];
            memcpy(sendDecryptedRecipeSizeBuffer, &request, sizeof(NetworkHeadStruct_t));
            memcpy(sendDecryptedRecipeSizeBuffer + sizeof(NetworkHeadStruct_t), &recipeListSize, sizeof(uint64_t));
            if (!socket_.Send(sendDecryptedRecipeSizeBuffer, sendSize)) {
                cerr << "RecvDecode : storage server closed" << endl;
                return false;
            } else {
                // cerr << "RecvDecode : process recipe done, send recipe size = " << recipeListSize << " to server" << endl;
                request.messageType = CLIENT_UPLOAD_DECRYPTED_RECIPE;
                request.dataSize = recipeHead.fileRecipeHead.totalChunkNumber * sizeof(RecipeEntry_t);
                sendSize = recipeHead.fileRecipeHead.totalChunkNumber * sizeof(RecipeEntry_t) + sizeof(NetworkHeadStruct_t);
                memcpy(requestChunkList, &request, sizeof(NetworkHeadStruct_t));
                if (!socket_.Send(requestChunkList, sendSize)) {
                    free(requestChunkList);
                    cerr << "RecvDecode : storage server closed" << endl;
                    return false;
                } else {
                    free(requestChunkList);
                    // cerr << "RecvDecode : process recipe done, send to server done, send size = " << sendSize << endl;
                    return true;
                }
            }
        }
    } else {
        return false;
    }
}

Recipe_t RecvDecode::getFileRecipeHead()
{
    return fileRecipe_;
}

bool RecvDecode::insertMQToRetriever(RetrieverData_t& newData)
{
    return outPutMQ_->push(newData);
}
bool RecvDecode::extractMQToRetriever(RetrieverData_t& newData)
{
    return outPutMQ_->pop(newData);
}

void RecvDecode::run()
{
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
    double decryptChunkTime = 0;
#endif
    int recvChunkBatchSize = config.getSendChunkBatchSize();
    NetworkHeadStruct_t request, respond;
    request.messageType = CLIENT_DOWNLOAD_CHUNK_WITH_RECIPE;
    request.dataSize = FILE_NAME_HASH_SIZE + 2 * sizeof(uint32_t);
    request.clientID = clientID_;
    int sendSize = sizeof(NetworkHeadStruct_t) + FILE_NAME_HASH_SIZE;
    u_char requestBuffer[sendSize];
    u_char respondBuffer[NETWORK_MESSAGE_DATA_SIZE];
    int recvSize;

    memcpy(requestBuffer, &request, sizeof(NetworkHeadStruct_t));
    memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), fileNameHash_, FILE_NAME_HASH_SIZE);

    if (!socket_.Send(requestBuffer, sendSize)) {
        cerr << "RecvDecode : storage server closed" << endl;
        return;
    }
    while (totalRecvChunks < fileRecipe_.fileRecipeHead.totalChunkNumber) {
        memset(respondBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
        if (!socket_.Recv(respondBuffer, recvSize)) {
            cerr << "RecvDecode : storage server closed" << endl;
            return;
        }
        memcpy(&respond, respondBuffer, sizeof(NetworkHeadStruct_t));
        if (respond.messageType == ERROR_RESEND)
            continue;
        if (respond.messageType == ERROR_CLOSE) {
            cerr << "RecvDecode : Server reject download request!" << endl;
            return;
        }
        if (respond.messageType == SUCCESS) {
            int totalRecvSize = sizeof(int);
            int chunkSize;
            uint32_t chunkID;
            int chunkNumber;
            u_char chunkPlaintData[MAX_CHUNK_SIZE];
            memcpy(&chunkNumber, respondBuffer + sizeof(NetworkHeadStruct_t), sizeof(int));
            for (int i = 0; i < chunkNumber; i++) {
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartRecvDecode, NULL);
#endif
                memcpy(&chunkID, respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, sizeof(uint32_t));
                totalRecvSize += sizeof(uint32_t);
                memcpy(&chunkSize, respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, sizeof(int));
                totalRecvSize += sizeof(int);
                cryptoObj_->decryptChunk(respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, chunkSize, fileRecipeList_[chunkID].chunkKey, chunkPlaintData);
                RetrieverData_t newData;
                newData.ID = chunkID;
                newData.logicDataSize = chunkSize;
                memcpy(newData.logicData, chunkPlaintData, chunkSize);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendRecvDecode, NULL);
                diff = 1000000 * (timeendRecvDecode.tv_sec - timestartRecvDecode.tv_sec) + timeendRecvDecode.tv_usec - timestartRecvDecode.tv_usec;
                second = diff / 1000000.0;
                decryptChunkTime += second;
#endif
                if (!insertMQToRetriever(newData)) {
                    cerr << "RecvDecode : Error insert chunk data into retriever" << endl;
                }
                totalRecvSize = totalRecvSize + chunkSize;
            }
            totalRecvChunks += chunkNumber;
        }
    }
    cerr << "RecvDecode : download job done, exit now" << endl;
#if SYSTEM_BREAK_DOWN == 1
    cerr << "RecvDecode : chunk decrypt time = " << decryptChunkTime << " s" << endl;
#endif
    return;
}