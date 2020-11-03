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
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
    gettimeofday(&timestartRecvDecode, NULL);
#endif
    cryptoObj_->generateHash((u_char*)&fileName[0], fileName.length(), fileNameHash_);

    bool initDownloadStatus = processRecipe(fileRecipe_, fileRecipeList_, fileNameHash_);
    if (initDownloadStatus) {
        cout << "RecvDecode : init download infomation success:\n\t  Total file size = " << fileRecipe_.fileRecipeHead.fileSize << " Byte\n\t  Total chunk number = " << fileRecipe_.fileRecipeHead.totalChunkNumber << endl;
    } else {
        cerr << "RecvDecode : recv file recipe error" << endl;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendRecvDecode, NULL);
        diff = 1000000 * (timeendRecvDecode.tv_sec - timestartRecvDecode.tv_sec) + timeendRecvDecode.tv_usec - timestartRecvDecode.tv_usec;
        second = diff / 1000000.0;
        cout << "RecvDecode : init download time = " << second << " s" << endl;
#endif
        exit(0);
    }

#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendRecvDecode, NULL);
    diff = 1000000 * (timeendRecvDecode.tv_sec - timestartRecvDecode.tv_sec) + timeendRecvDecode.tv_usec - timestartRecvDecode.tv_usec;
    second = diff / 1000000.0;
    cout << "RecvDecode : init download time = " << second << " s" << endl;
#endif  

}

RecvDecode::~RecvDecode()
{
    socket_.finish();
    if (cryptoObj_ != nullptr) {
        delete cryptoObj_;
    }
    outPutMQ_->~messageQueue();
    delete outPutMQ_;
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
#if SYSTEM_DEBUG_FLAG == 1
    PRINT_BYTE_ARRAY_RECV(stderr, fileNameHash, FILE_NAME_HASH_SIZE);
#endif
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
#if SYSTEM_DEBUG_FLAG == 1
        cerr << "RecvDecode : recv encrypted recipe size = " << recipeLength << endl;
#endif
        u_char* encryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeLength + sizeof(NetworkHeadStruct_t));
        u_char* decryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeLength);

        if (!socket_.Recv(encryptedRecipeBuffer, recvSize)) {
            cerr << "RecvDecode : storage server closed" << endl;
            return false;
        }
        memcpy(&respond, encryptedRecipeBuffer, sizeof(NetworkHeadStruct_t));
        if (recvSize != respond.dataSize + (int)sizeof(NetworkHeadStruct_t)) {
            cerr << "RecvDecode : recv encrypted file recipe size error" << endl;
            return false;
        } else {
            memcpy(&recipeHead, encryptedRecipeBuffer + sizeof(NetworkHeadStruct_t), sizeof(Recipe_t));
            cryptoObj_->decryptWithKey(encryptedRecipeBuffer + sizeof(NetworkHeadStruct_t) + sizeof(Recipe_t), recipeLength - sizeof(Recipe_t), cryptoObj_->chunkKeyEncryptionKey_, decryptedRecipeBuffer);
            u_char* requestChunkList = (u_char*)malloc(sizeof(u_char) * (CHUNK_HASH_SIZE + sizeof(int)) * recipeHead.fileRecipeHead.totalChunkNumber + sizeof(NetworkHeadStruct_t));
            for (uint64_t i = 0; i < recipeHead.fileRecipeHead.totalChunkNumber; i++) {
                RecipeEntry_t newRecipeEntry;
                memcpy(&newRecipeEntry, decryptedRecipeBuffer + i * sizeof(RecipeEntry_t), sizeof(RecipeEntry_t));
                recipeList.push_back(newRecipeEntry);
                memset(newRecipeEntry.chunkKey, 0, CHUNK_ENCRYPT_KEY_SIZE);
                memcpy(requestChunkList + sizeof(NetworkHeadStruct_t) + i * (CHUNK_HASH_SIZE + sizeof(int)), &newRecipeEntry.chunkSize, sizeof(int));
                memcpy(requestChunkList + sizeof(NetworkHeadStruct_t) + i * (CHUNK_HASH_SIZE + sizeof(int)) + sizeof(int), newRecipeEntry.chunkHash, CHUNK_HASH_SIZE);
            }
            free(encryptedRecipeBuffer);
            free(decryptedRecipeBuffer);

            request.messageType = CLIENT_UPLOAD_DECRYPTED_RECIPE;
            request.dataSize = sizeof(uint64_t);
            uint64_t recipeListSize = recipeHead.fileRecipeHead.totalChunkNumber * (CHUNK_HASH_SIZE + sizeof(int));
            sendSize = sizeof(NetworkHeadStruct_t) + sizeof(uint64_t);
            u_char sendDecryptedRecipeSizeBuffer[sizeof(NetworkHeadStruct_t) + sizeof(uint64_t)];
            memcpy(sendDecryptedRecipeSizeBuffer, &request, sizeof(NetworkHeadStruct_t));
            memcpy(sendDecryptedRecipeSizeBuffer + sizeof(NetworkHeadStruct_t), &recipeListSize, sizeof(uint64_t));
            if (!socket_.Send(sendDecryptedRecipeSizeBuffer, sendSize)) {
                cerr << "RecvDecode : storage server closed" << endl;
                return false;
            } else {
                request.messageType = CLIENT_UPLOAD_DECRYPTED_RECIPE;
                request.dataSize = recipeListSize;
                sendSize = recipeListSize + sizeof(NetworkHeadStruct_t);
                memcpy(requestChunkList, &request, sizeof(NetworkHeadStruct_t));
                if (!socket_.Send(requestChunkList, sendSize)) {
                    free(requestChunkList);
                    cerr << "RecvDecode : storage server closed" << endl;
                    return false;
                } else {
                    free(requestChunkList);
#if SYSTEM_DEBUG_FLAG == 1
                    cout << "RecvDecode : process recipe done, send to server done, send size = " << sendSize << endl;
#endif
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

bool RecvDecode::insertMQ(RetrieverData_t& newData)
{
    return outPutMQ_->push(newData);
}
bool RecvDecode::extractMQ(RetrieverData_t& newData)
{
    return outPutMQ_->pop(newData);
}

bool RecvDecode::getJobDoneFlag()
{
    return outPutMQ_->done_;
}

void RecvDecode::run()
{
#if SYSTEM_BREAK_DOWN == 1
    long diff;
    double second;
    double decryptChunkTime = 0;
    double recvChunkTime = 0;
#endif
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
    uint32_t totalRecvChunks = 0;
    while (totalRecvChunks < fileRecipe_.fileRecipeHead.totalChunkNumber) {
        memset(respondBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartRecvDecode, NULL);
#endif
        bool recvDataChunkStatus = socket_.Recv(respondBuffer, recvSize);
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendRecvDecode, NULL);
        diff = 1000000 * (timeendRecvDecode.tv_sec - timestartRecvDecode.tv_sec) + timeendRecvDecode.tv_usec - timestartRecvDecode.tv_usec;
        second = diff / 1000000.0;
        recvChunkTime += second;
#endif
        if (!recvDataChunkStatus) {
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
                cryptoObj_->decryptWithKey((u_char*)respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, chunkSize, fileRecipeList_[chunkID].chunkKey, chunkPlaintData);
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
                if (!insertMQ(newData)) {
                    cerr << "RecvDecode : Error insert chunk data into retriever" << endl;
                }
                totalRecvSize = totalRecvSize + chunkSize;
            }
            totalRecvChunks += chunkNumber;
        }
    }
#if SYSTEM_BREAK_DOWN == 1
    cout << "RecvDecode : chunk download time = " << recvChunkTime << " s" << endl;
    cout << "RecvDecode : chunk decrypt time = " << decryptChunkTime << " s" << endl;
    outPutMQ_->done_ = true;
#endif
    return;
}