
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
    RecipeList_t restoredRecipeList;
    uint32_t totalRestoredChunkNumber = 0;
    uint64_t recipeSize = 0;
    while (true) {
        memset(recvBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
        if (!socket.Recv(recvBuffer, recvSize)) {
            cerr << "DataSR : client closed socket connect, fd = " << socket.fd_ << " Thread exit now" << endl;
            return;
        } else {
            NetworkHeadStruct_t netBody;
            memcpy(&netBody, recvBuffer, sizeof(NetworkHeadStruct_t));
            // cerr << "DataSR : recv message type " << netBody.messageType << ", message size = " << netBody.dataSize << endl;
            switch (netBody.messageType) {
            case CLIENT_EXIT: {
                cerr << "DataSR : client send job done check flag, server side job over, thread exit now" << endl;
                netBody.messageType = SERVER_JOB_DONE_EXIT_PERMIT;
                netBody.dataSize = 0;
                sendSize = sizeof(NetworkHeadStruct_t);
                memset(sendBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
                memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                socket.Send(sendBuffer, sendSize);
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
                if (recipeListSize <= 0) {
                    cerr << "Sender : file resipces size error, stop recving" << endl;
                    break;
                }
                u_char* recipeListBuffer = (u_char*)malloc(sizeof(u_char) * recipeListSize + sizeof(NetworkHeadStruct_t));
                if (!socket.Recv(recipeListBuffer, recvSize)) {
                    cout << "DataSR : client closed socket connect, recipe store failed, Thread exit now" << endl;
                    cerr << "DataSR : data thread exit now due to client connection lost" << endl;
                    free(recipeListBuffer);
                    break;
                }
                Recipe_t newFileRecipe;
                memcpy(&newFileRecipe, recipeListBuffer + sizeof(NetworkHeadStruct_t), sizeof(Recipe_t));
                storageObj_->storeRecipes((char*)newFileRecipe.fileRecipeHead.fileNameHash, recipeListBuffer + sizeof(NetworkHeadStruct_t), recipeListSize);
                free(recipeListBuffer);
                break;
            }
            case CLIENT_UPLOAD_DECRYPTED_RECIPE: {
                // cerr << "DataSR : current recipe size = " << recipeSize << ", toatl chunk number = " << restoredFileRecipe.fileRecipeHead.totalChunkNumber << endl;
                uint64_t decryptedRecipeListSize = 0;
                memcpy(&decryptedRecipeListSize, recvBuffer + sizeof(NetworkHeadStruct_t), sizeof(uint64_t));
                // cerr << "DataSR : process recipe list size = " << decryptedRecipeListSize << endl;
                u_char* recvDecryptedRecipeBuffer = (u_char*)malloc(sizeof(u_char) * decryptedRecipeListSize + sizeof(NetworkHeadStruct_t));
                if (socket.Recv(recvDecryptedRecipeBuffer, recvSize)) {
                    NetworkHeadStruct_t tempHeader;
                    memcpy(&tempHeader, recvDecryptedRecipeBuffer, sizeof(NetworkHeadStruct_t));
                    // cerr << "DataSR : CLIENT_UPLOAD_DECRYPTED_RECIPE, recv message type " << tempHeader.messageType << ", message size = " << tempHeader.dataSize << endl;
                } else {
                    cerr << "DataSR : recv decrypted file recipe error " << endl;
                }
                int restoreChunkNumber = restoredFileRecipe.fileRecipeHead.totalChunkNumber;
                // cerr << "DataSR : target restore chunk number = " << restoreChunkNumber << endl;
                // memcpy(&restoredFileRecipe, recvDecryptedRecipeBuffer + sizeof(NetworkHeadStruct_t), sizeof(Recipe_t));
                for (int i = 0; i < restoreChunkNumber; i++) {
                    RecipeEntry_t newRecipeEntry;
                    memcpy(&newRecipeEntry, recvDecryptedRecipeBuffer + sizeof(NetworkHeadStruct_t) + i * sizeof(RecipeEntry_t), sizeof(RecipeEntry_t));
                    // cerr << "DataSR : recv chunk id = " << newRecipeEntry.chunkID << ", chunk size = " << newRecipeEntry.chunkSize << endl;
                    restoredRecipeList.push_back(newRecipeEntry);
                }
                free(recvDecryptedRecipeBuffer);
                cerr << "DataSR : process recipe list done" << endl;
                break;
            }
            case CLIENT_DOWNLOAD_ENCRYPTED_RECIPE: {

                if (storageObj_->restoreRecipesSize((char*)recvBuffer + sizeof(NetworkHeadStruct_t), recipeSize)) {
                    // cerr << "StorageCore : restore file size = " << recipeSize << endl;
                    netBody.messageType = SUCCESS;
                    netBody.dataSize = recipeSize;
                    sendSize = sizeof(NetworkHeadStruct_t);
                    memset(sendBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
                    memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    socket.Send(sendBuffer, sendSize);
                    // cerr << "StorageCore : send recipe size done" << endl;
                    u_char* recipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeSize);
                    storageObj_->restoreRecipes((char*)recvBuffer + sizeof(NetworkHeadStruct_t), recipeBuffer, recipeSize);
                    u_char* sendRecipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeSize + sizeof(NetworkHeadStruct_t));
                    memcpy(sendRecipeBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    memcpy(sendRecipeBuffer + sizeof(NetworkHeadStruct_t), recipeBuffer, recipeSize);
                    sendSize = sizeof(NetworkHeadStruct_t) + recipeSize;
                    socket.Send(sendRecipeBuffer, sendSize);
                    memcpy(&restoredFileRecipe, recipeBuffer, sizeof(Recipe_t));
                    // cerr << "StorageCore : send recipe list done, file size = " << restoredFileRecipe.fileRecipeHead.fileSize << ", total chunk number = " << restoredFileRecipe.fileRecipeHead.totalChunkNumber << endl;
                    free(sendRecipeBuffer);
                    free(recipeBuffer);
                } else {
                    netBody.messageType = ERROR_FILE_NOT_EXIST;
                    netBody.dataSize = 0;
                    memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    sendSize = sizeof(NetworkHeadStruct_t);
                    socket.Send(sendBuffer, sendSize);
                }
                break;
            }
            case CLIENT_DOWNLOAD_CHUNK_WITH_RECIPE: {
                cerr << "DataSR : start retrive chunks " << endl;
                if (restoredFileRecipe.fileRecipeHead.totalChunkNumber < config.getSendChunkBatchSize()) {
                    endID = restoredFileRecipe.fileRecipeHead.totalChunkNumber - 1;
                }
                while (totalRestoredChunkNumber != restoredFileRecipe.fileRecipeHead.totalChunkNumber) {
                    ChunkList_t restoredChunkList;
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timestartDataSR, NULL);
#endif
                    if (storageObj_->restoreRecipeAndChunk(restoredRecipeList, startID, endID, restoredChunkList)) {
                        netBody.messageType = SUCCESS;
                        int currentChunkNumber = restoredChunkList.size();
                        int totalSendSize = sizeof(int);
                        memset(sendBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
                        memcpy(sendBuffer + sizeof(NetworkHeadStruct_t), &currentChunkNumber, sizeof(int));
                        for (int i = 0; i < currentChunkNumber; i++) {
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].ID, sizeof(uint32_t));
                            totalSendSize += sizeof(uint32_t);
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].logicDataSize, sizeof(int));
                            totalSendSize += sizeof(int);
                            memcpy(sendBuffer + sizeof(NetworkHeadStruct_t) + totalSendSize, &restoredChunkList[i].logicData, restoredChunkList[i].logicDataSize);
                            totalSendSize += restoredChunkList[i].logicDataSize;
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
#if BREAK_DOWN_DEFINE == 1
                    gettimeofday(&timeendDataSR, NULL);
                    int diff = 1000000 * (timeendDataSR.tv_sec - timestartDataSR.tv_sec) + timeendDataSR.tv_usec - timestartDataSR.tv_usec;
                    double second = diff / 1000000.0;
                    cout << "DataSR : restore " << restoredChunkList.size() << "  chunk time  = " << second << " s" << endl;
#endif
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
