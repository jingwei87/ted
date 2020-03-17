#include "sender.hpp"
#include <sys/time.h>

extern Configure config;

struct timeval timestartSender;
struct timeval timeendSender;
struct timeval timestartSenderReadMQ;
struct timeval timeendSenderReadMQ;
struct timeval timestartSenderRecipe;
struct timeval timeendSenderRecipe;

void PRINT_BYTE_ARRAY_SENDER(
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

Sender::Sender()
{
    inputMQ_ = new messageQueue<Data_t>;
    socket_.init(CLIENT_TCP, config.getStorageServerIP(), config.getStorageServerPort());
    cryptoObj_ = new CryptoPrimitive();
    clientID_ = config.getClientID();
}

Sender::~Sender()
{
    socket_.finish();
    if (cryptoObj_ != NULL) {
        delete cryptoObj_;
    }
    inputMQ_->~messageQueue();
    delete inputMQ_;
}

bool Sender::sendRecipe(Recipe_t request, RecipeList_t recipeList, int& status)
{
    int totalRecipeNumber = recipeList.size();
    int totalRecipeSize = totalRecipeNumber * sizeof(RecipeEntry_t) + sizeof(Recipe_t);
    u_char* recipeBuffer = (u_char*)malloc(sizeof(u_char) * totalRecipeNumber * sizeof(RecipeEntry_t));
    PRINT_BYTE_ARRAY_SENDER(stdout, &request.fileRecipeHead.fileNameHash, FILE_NAME_HASH_SIZE);
    for (int i = 0; i < totalRecipeNumber; i++) {
        memcpy(recipeBuffer + i * sizeof(RecipeEntry_t), &recipeList[i], sizeof(RecipeEntry_t));
        // cerr << "DataSR : recv chunk id = " << recipeList[i].chunkID << ", chunk size = " << recipeList[i].chunkSize << endl;
        // PRINT_BYTE_ARRAY_SENDER(stdout, recipeList[i].chunkKey, CHUNK_ENCRYPT_KEY_SIZE);
    }
    u_char clientKey[32];
    memset(clientKey, 1, 32);

    NetworkHeadStruct_t requestBodySize;
    requestBodySize.clientID = clientID_;
    requestBodySize.messageType = CLIENT_UPLOAD_ENCRYPTED_RECIPE;
    int sendSize = sizeof(NetworkHeadStruct_t);
    requestBodySize.dataSize = totalRecipeSize;
    u_char* requestBufferFirst = (u_char*)malloc(sizeof(u_char) * sendSize);
    memcpy(requestBufferFirst, &requestBodySize, sizeof(NetworkHeadStruct_t));
    if (!socket_.Send(requestBufferFirst, sendSize)) {
        free(requestBufferFirst);
        cerr << "Sender : error sending file resipces size, peer may close" << endl;
        return false;
    } else {
        free(requestBufferFirst);
        NetworkHeadStruct_t requestBodyRecipe;
        requestBodyRecipe.clientID = clientID_;
        requestBodyRecipe.messageType = CLIENT_UPLOAD_ENCRYPTED_RECIPE;
        int sendSize = sizeof(NetworkHeadStruct_t) + totalRecipeSize;
        requestBodyRecipe.dataSize = totalRecipeSize;
        u_char* requestBuffer = (u_char*)malloc(sizeof(u_char) * sendSize);
        memcpy(requestBuffer, &requestBodyRecipe, sizeof(NetworkHeadStruct_t));
        memcpy(requestBuffer + sizeof(NetworkHeadStruct_t), &request, sizeof(Recipe_t));
        cryptoObj_->encryptWithKey(recipeBuffer, totalRecipeNumber * sizeof(RecipeEntry_t), clientKey, requestBuffer + sizeof(NetworkHeadStruct_t) + sizeof(Recipe_t));
        if (!socket_.Send(requestBuffer, sendSize)) {
            free(requestBuffer);
            cerr << "Sender : error sending file resipces, peer may close" << endl;
            return false;
        } else {
            free(requestBuffer);
            cerr << "Sender : send recipe done" << endl;
        }
    }

    return true;
}

bool Sender::sendChunkList(char* requestBufferIn, int sendBufferSize, int sendChunkNumber, int& status)
{
    NetworkHeadStruct_t requestBody;
    requestBody.clientID = clientID_;
    requestBody.messageType = CLIENT_UPLOAD_CHUNK;
    u_char requestBuffer[NETWORK_MESSAGE_DATA_SIZE];
    int sendSize = sizeof(NetworkHeadStruct_t) + sizeof(int) + sendBufferSize;
    memcpy(requestBufferIn + sizeof(NetworkHeadStruct_t), &sendChunkNumber, sizeof(int));
    requestBody.dataSize = sendBufferSize + sizeof(int);
    memcpy(requestBufferIn, &requestBody, sizeof(NetworkHeadStruct_t));
    if (!socket_.Send((u_char*)requestBufferIn, sendSize)) {
        return false;
    } else {
        return true;
    }
}

bool Sender::sendData(u_char* request, int requestSize, u_char* respond, int& respondSize, bool recv)
{
    std::lock_guard<std::mutex> locker(mutexSocket_);
    if (!socket_.Send(request, requestSize)) {
        cerr << "Sender : send data error peer closed" << endl;
        return false;
    }
    if (recv) {
        if (!socket_.Recv(respond, respondSize)) {
            cerr << "Sender : recv data error peer closed" << endl;
            return false;
        }
    }
    return true;
}

bool Sender::sendEndFlag()
{
    NetworkHeadStruct_t requestBody;
    requestBody.messageType = CLIENT_EXIT;
    requestBody.clientID = clientID_;
    int sendSize = sizeof(NetworkHeadStruct_t);
    requestBody.dataSize = 0;
    u_char requestBuffer[sendSize];
    memcpy(requestBuffer, &requestBody, sizeof(NetworkHeadStruct_t));
    if (!socket_.Send(requestBuffer, sendSize)) {
        cerr << "Sender : send data error peer closed" << endl;
        return false;
    }
    return true;
}

void Sender::run()
{
    double totalSendTime = 0;
    double totalExtractMQTime = 0;
    long diff;
    double second;
    Data_t tempChunk;
    RecipeList_t recipeList;
    Recipe_t fileRecipe;
    int sendBatchSize = config.getSendChunkBatchSize();
    int status;
#if SEND_CHUNK_LIST_METHOD == 0
    char* sendChunkBatchBuffer = (char*)malloc(sizeof(NetworkHeadStruct_t) + sizeof(int) + sizeof(char) * sendBatchSize * (CHUNK_HASH_SIZE + MAX_CHUNK_SIZE + sizeof(int)));
#else
    char* sendChunkBatchBuffer = (char*)malloc(sizeof(NetworkHeadStruct_t) + sizeof(int) + sizeof(Chunk_t) * sendBatchSize);
#endif
    bool jobDoneFlag = false;
    int currentChunkNumber = 0;
    int currentSendRecipeNumber = 0;
    int currentSendChunkBatchBufferSize = sizeof(NetworkHeadStruct_t) + sizeof(int);
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartSender, NULL);
#endif
    while (!jobDoneFlag) {
        if (inputMQ_->done_ && inputMQ_->isEmpty()) {
            jobDoneFlag = true;
        }
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timestartSenderReadMQ, NULL);
#endif
        bool extractChunkStatus = extractMQFromKeyClient(tempChunk);
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timeendSenderReadMQ, NULL);
        diff = 1000000 * (timeendSenderReadMQ.tv_sec - timestartSenderReadMQ.tv_sec) + timeendSenderReadMQ.tv_usec - timestartSenderReadMQ.tv_usec;
        second = diff / 1000000.0;
        totalExtractMQTime += second;
#endif

        if (extractChunkStatus) {

            if (tempChunk.dataType == DATA_TYPE_RECIPE) {
                memcpy(&fileRecipe, &tempChunk.recipe, sizeof(Recipe_t));
                continue;
            } else {
#if SEND_CHUNK_LIST_METHOD == 0
                memcpy(sendChunkBatchBuffer + currentSendChunkBatchBufferSize, tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
                currentSendChunkBatchBufferSize += CHUNK_HASH_SIZE;
                memcpy(sendChunkBatchBuffer + currentSendChunkBatchBufferSize, &tempChunk.chunk.logicDataSize, sizeof(int));
                currentSendChunkBatchBufferSize += sizeof(int);
                memcpy(sendChunkBatchBuffer + currentSendChunkBatchBufferSize, tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize);
                currentSendChunkBatchBufferSize += tempChunk.chunk.logicDataSize;
#else
                memcpy(sendChunkBatchBuffer + sizeof(NetworkHeadStruct_t) + sizeof(int) + currentChunkNumber * sizeof(Chunk_t), &tempChunk.chunk, sizeof(Chunk_t));
                currentChunkNumber++;
                currentSendChunkBatchBufferSize += sizeof(Chunk_t);
                // PRINT_BYTE_ARRAY_SENDER(stdout, tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize);
#endif
                RecipeEntry_t newRecipeEntry;
                newRecipeEntry.chunkID = tempChunk.chunk.ID;
                newRecipeEntry.chunkSize = tempChunk.chunk.logicDataSize;
                memcpy(newRecipeEntry.chunkHash, tempChunk.chunk.chunkHash, CHUNK_HASH_SIZE);
                memcpy(newRecipeEntry.chunkKey, tempChunk.chunk.encryptKey, CHUNK_ENCRYPT_KEY_SIZE);
                recipeList.push_back(newRecipeEntry);
                currentSendRecipeNumber++;
            }
        }
        if (currentChunkNumber == sendBatchSize || jobDoneFlag) {
            if (this->sendChunkList(sendChunkBatchBuffer, currentSendChunkBatchBufferSize, currentChunkNumber, status)) {
                currentSendChunkBatchBufferSize = sizeof(NetworkHeadStruct_t) + sizeof(int);
                memset(sendChunkBatchBuffer, 0, sizeof(NetworkHeadStruct_t) + sizeof(int) + sizeof(char) * sendBatchSize * (CHUNK_HASH_SIZE + MAX_CHUNK_SIZE + sizeof(int)));
                currentChunkNumber = 0;
            } else {
                cerr << "Sender : send " << setbase(10) << currentChunkNumber << " chunk error" << endl;
                break;
            }
        }
    }
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendSender, NULL);
    diff = 1000000 * (timeendSender.tv_sec - timestartSender.tv_sec) + timeendSender.tv_usec - timestartSender.tv_usec;
    second = diff / 1000000.0;
    cerr << "Sender : send chunk time = " << second - totalExtractMQTime << " s" << endl;
#endif
// printf("Sender send chunk list time is %lf s\n", totalSendTime);
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartSenderRecipe, NULL);
#endif
    cerr << "Sender : start send file recipes" << endl;
    if (!this->sendRecipe(fileRecipe, recipeList, status)) {
        cerr << "Sender : send recipe list error, upload fail " << endl;
        free(sendChunkBatchBuffer);
        sendEndFlag();
        return;
    }
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendSenderRecipe, NULL);
    diff = 1000000 * (timeendSenderRecipe.tv_sec - timestartSenderRecipe.tv_sec) + timeendSenderRecipe.tv_usec - timestartSenderRecipe.tv_usec;
    second = diff / 1000000.0;
    cerr << "Sender : send recipe list time = " << second << " s" << endl;
#endif
    free(sendChunkBatchBuffer);
    sendEndFlag();
    return;
}

bool Sender::insertMQFromKeyClient(Data_t& newChunk)
{
    return inputMQ_->push(newChunk);
}

bool Sender::extractMQFromKeyClient(Data_t& newChunk)
{
    return inputMQ_->pop(newChunk);
}

bool Sender::editJobDoneFlag()
{
    inputMQ_->done_ = true;
    if (inputMQ_->done_) {
        return true;
    } else {
        return false;
    }
}
