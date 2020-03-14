#include "recvDecode.hpp"

extern Configure config;

RecvDecode::RecvDecode(string fileName)
{
    clientID_ = config.getClientID();
    outPutMQ_ = new messageQueue<RetrieverData_t>;
    cryptoObj_ = new CryptoPrimitive();
    socket_.init(CLIENT_TCP, config.getStorageServerIP(), config.getStorageServerPort());
    cryptoObj_->generateHash((u_char*)&fileName[0], fileName.length(), fileNameHash_);
    if (processRecipe(fileRecipe_, fileRecipeList_ fileNameHash_)) {
        cerr << "RecvDecode : recv file recipe head, file size = " << fileRecipe_.fileRecipeHead.fileSize << ", total chunk number = " << fileRecipe_.fileRecipeHead.totalChunkNumber << endl;
    } else {
        cerr << "RecvDecode : recv file recipe error" << endl;
        exit(0);
    }
}

RecvDecode::~RecvDecode()
{
    socket_.finish();
    socketPow_.finish();
    if (cryptoObj_ != nullptr) {
        delete cryptoObj_;
    }
    outPutMQ_->~messageQueue();
    delete outPutMQ_;
}

bool RecvDecode::processRecipe(Recipe_t& recipeHead, RecipeList_t recipeList, u_char* fileNameHash)
{
    NetworkHeadStruct_t request, respond;
    request.messageType = CLIENT_DOWNLOAD_RECIPE_SIZE;
    request.dataSize = FILE_NAME_HASH_SIZE;
    request.clientID = clientID_;

    int sendSize = sizeof(NetworkHeadStruct_t) + FILE_NAME_HASH_SIZE;
    u_char requestBuffer[sendSize];

    memcpy(requestBuffer, &request, sizeof(NetworkHeadStruct_t));
    memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), fileNameHash, FILE_NAME_HASH_SIZE);

    while (true) {
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
        if (respond.messageType == ERROR_RESEND) {
            cerr << "RecvDecode : Server send resend flag!" << endl;
            continue;
        }
        if (respond.messageType == ERROR_CLOSE) {
            cerr << "RecvDecode : Server reject download request!" << endl;
            exit(1);
        }
        if (respond.messageType == ERROR_FILE_NOT_EXIST) {
            cerr << "RecvDecode : Server reject download request, file not exist in server!" << endl;
            exit(1);
        }
        if (respond.messageType == ERROR_CHUNK_NOT_EXIST) {
            cerr << "RecvDecode : Server reject download request, chunk not exist in server!" << endl;
            exit(1);
        }
        if (respond.messageType == SUCCESS) {
            uint64_t recipeLength = respond.dataSize;
            u_char* encryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeLength + sizeof(NetworkHeadStruct_t));
            u_char* decryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeLength);
            request.messageType = CLIENT_DOWNLOAD_ENCRYPTED_RECIPE;
            request.dataSize = FILE_NAME_HASH_SIZE;
            request.clientID = clientID_;
            sendSize = sizeof(NetworkHeadStruct_t) + FILE_NAME_HASH_SIZE;
            memcpy(requestBuffer, &request, sizeof(NetworkHeadStruct_t));
            memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), fileNameHash, FILE_NAME_HASH_SIZE);

            if (!socket_.Send(requestBuffer, sendSize)) {
                cerr << "RecvDecode : storage server closed" << endl;
                return false;
            }

            if (!socket_.Recv(encryptedRecipeBuffer, recvSize)) {
                cerr << "RecvDecode : storage server closed" << endl;
                return false;
            }
            if (recvSize != respond.dataSize + sizeof(NetworkHeadStruct_t)) {
                cerr << "RecvDecode : recv encrypted file recipe size error" << endl;
            } else {
                u_char clientKey[32];
                memset(clientKey, 1, 32);
                cryptoObj_->decryptWithKey(encryptedRecipeBuffer + sizeof(NetworkHeadStruct_t), respond.dataSize, clientKey, decryptedRecipeBuffer);
                memcpy(&recipeHead, decryptedRecipeBuffer, sizeof(Recipe_t));
                u_char* requestChunkList = (u_char*)malloc(sizeof(u_char) * CHUNK_FINGER_PRINT_SIZE * recipeHead.fileRecipeHead.totalChunkNumber + sizeof(NetworkHeadStruct_t));
                for (uint64_t i = 0; i < recipeHead.fileRecipeHead.totalChunkNumber; i++) {
                    RecipeEntry_t newRecipeEntry;
                    memcpy(&newRecipeEntry, decryptedRecipeBuffer + sizeof(Recipe_t) + i * sizeof(RecipeEntry_t), sizeof(RecipeEntry_t));
                    recipeList.push_back(newRecipeEntry);
                    memcpy(requestChunkList + sizeof(NetworkHeadStruct_t) + i * CHUNK_FINGER_PRINT_SIZE, newRecipeEntry.chunkHash, CHUNK_FINGER_PRINT_SIZE);
                }
                free(encryptedRecipeBuffer);
                free(decryptedRecipeBuffer);

                request.messageType = CLIENT_UPLOAD_DECRYPTED_RECIPE;
                request.dataSize = recipeHead.fileRecipeHead.totalChunkNumber * CHUNK_FINGER_PRINT_SIZE;
                sendSize = CHUNK_FINGER_PRINT_SIZE * recipeHead.fileRecipeHead.totalChunkNumber + sizeof(NetworkHeadStruct_t);
                memcpy(requestChunkList, &request, sizeof(NetworkHeadStruct_t));
                if (!socket_.Send(requestChunkList, sendSize)) {
                    free(requestChunkList);
                    cerr << "RecvDecode : storage server closed" << endl;
                    return false;
                } else {
                    free(requestChunkList);
                    cerr << "RecvDecode : process recipe done, send to server done" << endl;
                    break;
                }
            }
        }
    }
    return true;
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
                memcpy(&chunkID, respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, sizeof(uint32_t));
                totalRecvSize += sizeof(uint32_t);
                memcpy(&chunkSize, respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, sizeof(int));
                totalRecvSize += sizeof(int);
                cryptoObj_->decryptChunk(respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize, chunkSize, respondBuffer + sizeof(NetworkHeadStruct_t) + totalRecvSize + chunkSize, chunkPlaintData);

                RetrieverData_t newData;
                newData.ID = chunkID;
                newData.logicDataSize = chunkSize;
                memcpy(newData.logicData, chunkPlaintData, chunkSize);
                if (!insertMQToRetriever(newData)) {
                    cerr << "RecvDecode : Error insert chunk data into retriever" << endl;
                }
                totalRecvSize = totalRecvSize + chunkSize + CHUNK_ENCRYPT_KEY_SIZE;
            }
            totalRecvChunks += chunkNumber;
        }
    }
    cout << "RecvDecode : download job done, exit now" << endl;
    return;
}