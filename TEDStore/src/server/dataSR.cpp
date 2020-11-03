
#include <dataSR.hpp>
#include <sys/times.h>

struct timeval timestartDataSR;
struct timeval timeendDataSR;

extern Configure config;

DataSR::DataSR(StorageCore* storageObj, DedupCore* dedupCoreObj)
{
    restoreChunkBatchNumber_ = config.getSendChunkBatchSize();
    storageObj_ = storageObj;
    dedupCoreObj_ = dedupCoreObj;
}

void DataSR::run(Socket socket)
{
    bool uploadFlag = false;
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
    char* restoredRecipeList;
#if SYSTEM_BREAK_DOWN == 1
    struct timeval timestartDataSR;
    struct timeval timeendDataSR;
    double saveChunkTime = 0;
    double saveRecipeTime = 0;
    double restoreChunkTime = 0;
    long diff;
    double second;
#endif

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
                uploadFlag = true;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartDataSR, NULL);
#endif
                bool storeChunkStatus = storageObj_->storeChunks(netBody, (char*)recvBuffer + sizeof(NetworkHeadStruct_t));
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendDataSR, NULL);
                diff = 1000000 * (timeendDataSR.tv_sec - timestartDataSR.tv_sec) + timeendDataSR.tv_usec - timestartDataSR.tv_usec;
                second = diff / 1000000.0;
                saveChunkTime += second;
#endif
                if (!storeChunkStatus) {
                    cerr << "DedupCore : store chunks report error, server may incur internal error, thread exit" << endl;
#if SYSTEM_BREAK_DOWN == 1
                    if (uploadFlag == true) {
                        cout << "DataSR : total save chunk time = " << saveChunkTime << " s" << endl;
                        cout << "DataSR : total save recipe time = " << saveRecipeTime << " s" << endl;
                    } else {
                        cout << "DataSR : total restore chunk time = " << restoreChunkTime << " s" << endl;
                    }
                    storageObj_->clientExitSystemStatusOutput(uploadFlag);
#endif
                    cerr << "DataSR : data thread exit now due to client connection lost" << endl;
                    if (restoredRecipeList != nullptr) {
                        free(restoredRecipeList);
                    }
                    return;
                }
                break;
            }
            case CLIENT_UPLOAD_ENCRYPTED_RECIPE: {
                uploadFlag = true;
                int recipeListSize = netBody.dataSize;
                cout << "DataSR : recv file recipe size = " << recipeListSize << endl;
                char* recipeListBuffer = (char*)malloc(sizeof(char) * recipeListSize + sizeof(NetworkHeadStruct_t));
                if (!socket.Recv((u_char*)recipeListBuffer, recvSize)) {
                    cout << "DataSR : client closed socket connect, recipe store failed, Thread exit now" << endl;
#if SYSTEM_BREAK_DOWN == 1
                    if (uploadFlag == true) {
                        cout << "DataSR : total save chunk time = " << saveChunkTime << " s" << endl;
                        cout << "DataSR : total save recipe time = " << saveRecipeTime << " s" << endl;
                    } else {
                        cout << "DataSR : total restore chunk time = " << restoreChunkTime << " s" << endl;
                    }
                    storageObj_->clientExitSystemStatusOutput(uploadFlag);
#endif
                    cerr << "DataSR : data thread exit now due to client connection lost" << endl;
                    if (restoredRecipeList != nullptr) {
                        free(restoredRecipeList);
                    }
                    return;
                }
                Recipe_t newFileRecipe;
                memcpy(&newFileRecipe, recipeListBuffer + sizeof(NetworkHeadStruct_t), sizeof(Recipe_t));
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartDataSR, NULL);
#endif
                storageObj_->storeRecipes((char*)newFileRecipe.fileRecipeHead.fileNameHash, (u_char*)recipeListBuffer + sizeof(NetworkHeadStruct_t), recipeListSize);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendDataSR, NULL);
                diff = 1000000 * (timeendDataSR.tv_sec - timestartDataSR.tv_sec) + timeendDataSR.tv_usec - timestartDataSR.tv_usec;
                second = diff / 1000000.0;
                saveRecipeTime += second;
#endif
                free(recipeListBuffer);
                break;
            }
            case CLIENT_UPLOAD_DECRYPTED_RECIPE: {
                // cout << "DataSR : current recipe size = " << recipeSize << ", toatl chunk number = " << restoredFileRecipe.fileRecipeHead.totalChunkNumber << endl;
                uint64_t decryptedRecipeListSize = 0;
                memcpy(&decryptedRecipeListSize, recvBuffer + sizeof(NetworkHeadStruct_t), sizeof(uint64_t));
                // cout << "DataSR : process recipe list size = " << decryptedRecipeListSize << endl;
                restoredRecipeList = (char*)malloc(sizeof(char) * decryptedRecipeListSize + sizeof(NetworkHeadStruct_t));
                if (socket.Recv((u_char*)restoredRecipeList, recvSize)) {
                    NetworkHeadStruct_t tempHeader;
                    memcpy(&tempHeader, restoredRecipeList, sizeof(NetworkHeadStruct_t));
                    // cout << "DataSR : CLIENT_UPLOAD_DECRYPTED_RECIPE, recv message type " << tempHeader.messageType << ", message size = " << tempHeader.dataSize << endl;
                } else {
                    cerr << "DataSR : recv decrypted file recipe error " << endl;
                }
                cerr << "DataSR : process recipe list done" << endl;
                break;
            }
            case CLIENT_DOWNLOAD_ENCRYPTED_RECIPE: {

#if MULTI_CLIENT_UPLOAD_TEST == 1
                mutexRestore_.lock();
#endif
                bool restoreRecipeSizeStatus = storageObj_->restoreRecipesSize((char*)recvBuffer + sizeof(NetworkHeadStruct_t), recipeSize);
#if MULTI_CLIENT_UPLOAD_TEST == 1
                mutexRestore_.unlock();
#endif
                if (restoreRecipeSizeStatus) {
                    netBody.messageType = SUCCESS;
                    netBody.dataSize = recipeSize;
                    sendSize = sizeof(NetworkHeadStruct_t);
                    memset(sendBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
                    memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    socket.Send(sendBuffer, sendSize);
                    u_char* recipeBuffer = (u_char*)malloc(sizeof(u_char) * recipeSize);
#if MULTI_CLIENT_UPLOAD_TEST == 1
                    mutexRestore_.lock();
#endif
                    storageObj_->restoreRecipes((char*)recvBuffer + sizeof(NetworkHeadStruct_t), recipeBuffer, recipeSize);
#if MULTI_CLIENT_UPLOAD_TEST == 1
                    mutexRestore_.unlock();
#endif
                    char* sendRecipeBuffer = (char*)malloc(sizeof(char) * recipeSize + sizeof(NetworkHeadStruct_t));
                    memcpy(sendRecipeBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                    memcpy(sendRecipeBuffer + sizeof(NetworkHeadStruct_t), recipeBuffer, recipeSize);
                    sendSize = sizeof(NetworkHeadStruct_t) + recipeSize;
                    socket.Send((u_char*)sendRecipeBuffer, sendSize);
                    memcpy(&restoredFileRecipe, recipeBuffer, sizeof(Recipe_t));
#if SYSTEM_DEBUG_FLAG == 1
                    cout << "StorageCore : send encrypted recipe list done, file size = " << restoredFileRecipe.fileRecipeHead.fileSize << ", total chunk number = " << restoredFileRecipe.fileRecipeHead.totalChunkNumber << endl;
#endif
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
                cerr << "DataSR : start retrive chunks, chunk number = " << restoredFileRecipe.fileRecipeHead.totalChunkNumber << endl;
                if (restoredFileRecipe.fileRecipeHead.totalChunkNumber < restoreChunkBatchNumber_) {
                    endID = restoredFileRecipe.fileRecipeHead.totalChunkNumber - 1;
                }
                while (totalRestoredChunkNumber != restoredFileRecipe.fileRecipeHead.totalChunkNumber) {
                    memset(sendBuffer, 0, NETWORK_MESSAGE_DATA_SIZE);
                    int restoredChunkNumber = 0, restoredChunkSize = 0;
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartDataSR, NULL);
#endif
#if MULTI_CLIENT_UPLOAD_TEST == 1
                    mutexRestore_.lock();
#endif
                    bool restoreChunkStatus = storageObj_->restoreRecipeAndChunk(restoredRecipeList + sizeof(NetworkHeadStruct_t) + startID * (CHUNK_HASH_SIZE + sizeof(int)), startID, endID, (char*)sendBuffer + sizeof(NetworkHeadStruct_t) + sizeof(int), restoredChunkNumber, restoredChunkSize);
#if MULTI_CLIENT_UPLOAD_TEST == 1
                    mutexRestore_.unlock();
#endif
                    if (restoreChunkStatus) {
                        netBody.messageType = SUCCESS;
                        memcpy(sendBuffer + sizeof(NetworkHeadStruct_t), &restoredChunkNumber, sizeof(int));
                        netBody.dataSize = sizeof(int) + restoredChunkSize;
                        memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                        sendSize = sizeof(NetworkHeadStruct_t) + sizeof(int) + restoredChunkSize;
                        totalRestoredChunkNumber += restoredChunkNumber;
                        startID = endID;
                        uint32_t remainChunkNumber = restoredFileRecipe.fileRecipeHead.totalChunkNumber - totalRestoredChunkNumber;
                        // cout << "DataSR : wait for restore chunk number = " << remainChunkNumber << ", current restored chunk number = " << restoredChunkNumber << endl;
                        if (remainChunkNumber < restoreChunkBatchNumber_) {
                            endID += restoredFileRecipe.fileRecipeHead.totalChunkNumber - totalRestoredChunkNumber;
                        } else {
                            endID += restoreChunkBatchNumber_;
                        }
                    } else {
                        netBody.dataSize = 0;
                        netBody.messageType = ERROR_CHUNK_NOT_EXIST;
                        memcpy(sendBuffer, &netBody, sizeof(NetworkHeadStruct_t));
                        sendSize = sizeof(NetworkHeadStruct_t);
#if SYSTEM_BREAK_DOWN == 1
                        if (uploadFlag == true) {
                            cout << "DataSR : total save chunk time = " << saveChunkTime << " s" << endl;
                            cout << "DataSR : total save recipe time = " << saveRecipeTime << " s" << endl;
                        } else {
                            cout << "DataSR : total restore chunk time = " << restoreChunkTime << " s" << endl;
                        }
                        storageObj_->clientExitSystemStatusOutput(uploadFlag);
#endif
                        cerr << "DataSR : data thread exit now due to client connection lost" << endl;
                        if (restoredRecipeList != nullptr) {
                            free(restoredRecipeList);
                        }
                        return;
                    }
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendDataSR, NULL);
                    diff = 1000000 * (timeendDataSR.tv_sec - timestartDataSR.tv_sec) + timeendDataSR.tv_usec - timestartDataSR.tv_usec;
                    second = diff / 1000000.0;
                    restoreChunkTime += second;
#endif
                    socket.Send(sendBuffer, sendSize);
                    cerr << "DataSR : send back chunks last ID = " << startID << endl;
                    // cerr << "DataSR : new start ID = " << startID << ", end ID = " << endID << endl;
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
