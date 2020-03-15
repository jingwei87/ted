
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
    // double totalSaveChunkTime = 0;
    uint32_t startID = 0;
    uint32_t endID = 0;
    Recipe_t restoredFileRecipe;
    uint32_t totalRestoredChunkNumber = 0;
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
                if (!storageObj_->saveChunks(netBody, (char*)recvBuffer + sizeof(NetworkHeadStruct_t))) {
                    cerr << "DedupCore : dedup stage 2 report error" << endl;
                    return;
                }
                break;
            }
            case CLIENT_UPLOAD_ENCRYPTED_RECIPE: {
                cout << "DataSR : recv file recipe" << endl;
                storageObj_->checkRecipeStatus(tempRecipeHead, tempRecipeEntryList);
                break;
            }
            case CLIENT_UPLOAD_DECRYPTED_RECIPE: {
                cout << "DataSR : recv file recipe" << endl;
                storageObj_->checkRecipeStatus(tempRecipeHead, tempRecipeEntryList);
                break;
            }
            case CLIENT_UPLOAD_DECRYPTED_RECIPE: {
                cout << "DataSR : recv file recipe" << endl;
                storageObj_->checkRecipeStatus(tempRecipeHead, tempRecipeEntryList);
                break;
            }
            case CLIENT_DOWNLOAD_ENCRYPTED_RECIPE: {

                if (storageObj_->restoreRecipeHead((char*)recvBuffer + sizeof(NetworkHeadStruct_t), restoredFileRecipe)) {
                    cout << "StorageCore : restore file size = " << restoredFileRecipe.fileRecipeHead.fileSize << " chunk number = " << restoredFileRecipe.fileRecipeHead.totalChunkNumber << endl;
                    netBody.messageType = SUCCESS;
                    netBody.dataSize = sizeof(Recipe_t);
                    memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    memcpy(sendBuffer + sizeof(NetworkHeadStruct_t), &restoredFileRecipe, sizeof(Recipe_t));
                    sendSize = sizeof(NetworkHeadStruct_t) + sizeof(Recipe_t);
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
