
#include <dataSR.hpp>
#include <sys/times.h>

struct timeval timestartDataSR;
struct timeval timeendDataSR;

extern Configure config;

DataSR::DataSR(StorageCore* storageObj, DedupCore* dedupCoreObj)
{
    restoreChunkBatchSize = config.getSendChunkBatchSize();
    storageObj_ = storageObj;
    dedupCoreObj_ = dedupCoreObj;
}

void DataSR::run(Socket socket)
{
    int recvSize = 0;
    int sendSize = 0;
    u_char recvBuffer[NETWORK_MESSAGE_DATA_SIZE];
    u_char sendBuffer[NETWORK_MESSAGE_DATA_SIZE];
    // double totalstoreChunkTime = 0;
    uint32_t startID = 0;
    uint32_t endID = 0;
    Recipe_t restoredFileRecipe;
    uint32_t totalRestoredChunkNumber = 0;
    uint64_t recipeSize = 0;
    u_char* recipeBuffer;
    while (true) {
        if (!socket.Recv(recvBuffer, recvSize)) {
            cerr << "DataSR : client closed socket connect, fd = " << socket.fd_ << " Thread exit now" << endl;
            return;
        } else {
            NetworkHeadStruct_t netBody;
            memcpy(&netBody, recvBuffer, sizeof(NetworkHeadStruct_t));
            cout << "DataSR : recv message type " << netBody.messageType << ", message size = " << netBody.dataSize << endl;
            switch (netBody.messageType) {
            case CLIENT_EXIT: {
                return;
            }
            case CLIENT_UPLOAD_CHUNK: {
                if (!storageObj_->storeChunks(netBody, (char*)recvBuffer + sizeof(NetworkHeadStruct_t))) {
                    cerr << "DedupCore : dedup stage 2 report error" << endl;
                    return;
                }
                break;
            }
            case CLIENT_UPLOAD_ENCRYPTED_RECIPE: {
                int recipeListSize = netBody.dataSize;
                cout << "DataSR : recv file recipe size = " << recipeListSize << endl;
                u_char* recipeListBuffer = (u_char*)malloc(sizeof(u_char) * recipeListSize + sizeof(NetworkHeadStruct_t));
                if (!socket.Recv(recipeListBuffer, recvSize)) {
                    cerr << "DataSR : client closed socket connect, recipe store failed,  fd = " << socket.fd_ << " Thread exit now" << endl;
                    return;
                }
                char fileNameHash[FILE_NAME_HASH_SIZE];
                memcpy(fileNameHash, recipeListBuffer + sizeof(NetworkHeadStruct_t), FILE_NAME_HASH_SIZE);
                storageObj_->storeRecipes(fileNameHash, recipeListBuffer + sizeof(NetworkHeadStruct_t) + FILE_NAME_HASH_SIZE, recipeListSize);
                break;
            }
            case CLIENT_UPLOAD_DECRYPTED_RECIPE: {
                cout << "DataSR : recv file recipe" << endl;
                u_char* recvDecryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeSize + sizeof(NetworkHeadStruct_t));
                decryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeBufferSize) break;
            }
            case CLIENT_DOWNLOAD_ENCRYPTED_RECIPE: {

                if (storageObj_->restoreRecipes((char*)recvBuffer + sizeof(NetworkHeadStruct_t), recipeBuffer, recipeSize)) {
                    cout << "StorageCore : restore file size = " << recipeSize << endl;
                    netBody.messageType = SUCCESS;
                    netBody.dataSize = recipeSize;
                    u_char* sendRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeSize + sizeof(NetworkHeadStruct_t));
                    memcpy(sendRecipeBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    memcpy(sendRecipeBuffer + sizeof(NetworkHeadStruct_t), recipeBuffer, recipeSize);
                    sendSize = sizeof(NetworkHeadStruct_t) + recipeSize;
                } else {
                    netBody.messageType = ERROR_FILE_NOT_EXIST;
                    netBody.dataSize = 0;
                    memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    sendSize = sizeof(NetworkHeadStruct_t);
                }
                socket.Send(sendBuffer, sendSize);
                break;
            }
            case CLIENT_DOWNLOAD_CHUNK_WITH_RECIPE: {
                if (restoredFileRecipe.fileRecipeHead.totalChunkNumber < config.getSendChunkBatchSize()) {
                    endID = restoredFileRecipe.fileRecipeHead.totalChunkNumber - 1;
                }
                while (totalRestoredChunkNumber != restoredFileRecipe.fileRecipeHead.totalChunkNumber) {
                    ChunkList_t restoredChunkList;
                    gettimeofday(&timestartDataSR, NULL);
                    if (storageObj_->restoreRecipeAndChunk((char*)recvBuffer + sizeof(NetworkHeadStruct_t), startID, endID, restoredChunkList)) {
                        netBody.messageType = SUCCESS;
                        int currentChunkNumber = restoredChunkList.size();
                        int totalSendSize = sizeof(int);
                        memcpy(sendBuffer + sizeof(NetworkHeadStruct_t), &currentChunkNumber, sizeof(int));
                        for (int i = 0; i < currentChunkNumber; i++) {
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].ID, sizeof(uint32_t));
                            totalSendSize += sizeof(uint32_t);
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].logicDataSize, sizeof(int));
                            totalSendSize += sizeof(int);
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].logicData, restoredChunkList[i].logicDataSize);
                            totalSendSize += restoredChunkList[i].logicDataSize;
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].encryptKey, CHUNK_ENCRYPT_KEY_SIZE);
                            totalSendSize += CHUNK_ENCRYPT_KEY_SIZE;
                        }
                        netBody.dataSize = totalSendSize;
                        memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                        sendSize = sizeof(NetworkHeadStruct_t) + totalSendSize;
                        totalRestoredChunkNumber += restoredChunkList.size();
                        startID = endID;
                        if (restoredFileRecipe.fileRecipeHead.totalChunkNumber - totalRestoredChunkNumber < restoreChunkBatchSize) {
                            endID += restoredFileRecipe.fileRecipeHead.totalChunkNumber - totalRestoredChunkNumber;
                        } else {
                            endID += config.getSendChunkBatchSize();
                        }
                    } else {
                        netBody.dataSize = 0;
                        netBody.messageType = ERROR_CHUNK_NOT_EXIST;
                        memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                        sendSize = sizeof(NetworkHeadStruct_t);
                        return;
                    }
                    gettimeofday(&timeendDataSR, NULL);
                    int diff = 1000000 * (timeendDataSR.tv_sec - timestartDataSR.tv_sec) + timeendDataSR.tv_usec - timestartDataSR.tv_usec;
                    double second = diff / 1000000.0;
                    cout << "DataSR : restore chunk time  = " << second << endl;
                    socket.Send(sendBuffer, sendSize);
                }
                break;
            }
            default:
                continue;
            }
        }
    }
    return;
}
