#include "storageCore.hpp"
#include <sys/time.h>

struct timeval timestartStorage;
struct timeval timeendStorage;

extern Configure config;
extern Database fp2ChunkDB;
extern Database fileName2metaDB;

StorageCore::StorageCore()
{
    RecipeNamePrefix_ = config.getRecipeRootPath();
    containerNamePrefix_ = config.getContainerRootPath();
    maxContainerSize_ = config.getMaxContainerSize();
    RecipeNameTail_ = ".recipe";
    containerNameTail_ = ".container";
    ifstream fin;
    fin.open(".StorageConfig", ifstream::in);
    if (fin.is_open()) {
        fin >> lastContainerFileName_;
        fin >> currentContainer_.used_;
        fin.close();

        //read last container
        fin.open(containerNamePrefix_ + lastContainerFileName_ + containerNameTail_, ifstream::in | ifstream::binary);
        fin.read(currentContainer_.body_, currentContainer_.used_);
        fin.close();

    } else {
        lastContainerFileName_ = "abcdefghijklmno";
        currentContainer_.used_ = 0;
    }
    cryptoObj_ = new CryptoPrimitive();
}

StorageCore::~StorageCore()
{
    ofstream fout;
    fout.open(".StorageConfig", ofstream::out);
    fout << lastContainerFileName_ << endl;
    fout << currentContainer_.used_ << endl;
    fout.close();

    string writeContainerName = containerNamePrefix_ + lastContainerFileName_ + containerNameTail_;
    currentContainer_.saveTOFile(writeContainerName);
#if BREAK_DOWN_DEFINE == 1
    cout << "Upload query DB time = " << queryDBTimeUpload << " s, write Container time = " << writeContainerTime << " s, insert DB time = " << insertDBTimeUpload << " s, unique chunk number = " << uniqueChunkNumber << endl;
    cout << "Restore chunks DB time = " << queryDBTime << " s, Read Container time = " << readContainerTime << " s, Current read container number = " << readContainerNumber << endl;
#endif
    delete cryptoObj_;
}

bool StorageCore::saveChunks(NetworkHeadStruct_t& networkHead, char* data)
{
    // gettimeofday(&timestartStorage, NULL);
    int chunkNumber;
    memcpy(&chunkNumber, data, sizeof(int));
    int readSize = sizeof(int);
    u_char hash[CHUNK_HASH_SIZE];
    string tmpdata;
#if SEND_CHUNK_LIST_METHOD == 0
    for (int i = 0; i < chunkNumber; i++) {
        int currentChunkSize;
        string originHash(data + readSize, CHUNK_HASH_SIZE);
        // cout << "save chunk hash" << endl;
        readSize += CHUNK_HASH_SIZE;
        memcpy(&currentChunkSize, data + readSize, sizeof(int));
        readSize += sizeof(int);
        if (fp2ChunkDB.query(originHash, tmpdata)) {
            continue;
        } else {
            if (!saveChunk(originHash, data + readSize, currentChunkSize)) {
                return false;
            }
        }
        readSize += currentChunkSize;
    }
#else
    for (int i = 0; i < chunkNumber; i++) {
        int currentChunkSize;
        Chunk_t newChunk;
        memcpy(&newChunk, data + sizeof(int) + i * sizeof(Chunk_t), sizeof(Chunk_t));
        string originHash((char*)newChunk.chunkHash, CHUNK_HASH_SIZE);
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timestartStorage, NULL);
#endif
        bool chunkStatus = fp2ChunkDB.query(originHash, tmpdata);
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timeendStorage, NULL);
        queryDBTimeUpload += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
        if (chunkStatus) {
            continue;
        } else {
            uniqueChunkNumber++;
            if (!saveChunk(originHash, (char*)newChunk.logicData, newChunk.logicDataSize)) {
                return false;
            }
        }
    }
#endif
    return true;
}

bool StorageCore::restoreRecipeHead(char* fileNameHash, Recipe_t& restoreRecipe)
{
    string recipeName;
    string DBKey(fileNameHash, FILE_NAME_HASH_SIZE);
    if (fileName2metaDB.query(DBKey, recipeName)) {
        ifstream RecipeIn;
        string readRecipeName;
        readRecipeName = RecipeNamePrefix_ + recipeName + RecipeNameTail_;
        RecipeIn.open(readRecipeName, ifstream::in | ifstream::binary);
        if (!RecipeIn.is_open()) {
            std::cerr << "StorageCore : Can not open Recipe file : " << readRecipeName;
            return false;
        } else {
            Recipe_t tempRecipeHead;
            char recipeHeadBuffer[sizeof(Recipe_t)];
            memset(recipeHeadBuffer, 0, sizeof(Recipe_t));
            RecipeIn.seekg(ios::beg);
            RecipeIn.read(recipeHeadBuffer, sizeof(Recipe_t));
            RecipeIn.close();
            memcpy(&restoreRecipe, recipeHeadBuffer, sizeof(Recipe_t));
            return true;
        }
    } else {
        return false;
    }
    return true;
}

bool StorageCore::saveRecipe(std::string recipeName, Recipe_t recipeHead, RecipeList_t recipeList, bool status)
{
    ofstream RecipeOut;
    string writeRecipeName, buffer;

    writeRecipeName = RecipeNamePrefix_ + recipeName + RecipeNameTail_;
    RecipeOut.open(writeRecipeName, ios::app | ios::binary);
    if (!RecipeOut.is_open()) {
        std::cerr << "Can not open Recipe file: " << writeRecipeName << endl;
        return false;
    }
    int recipeListSize = recipeList.size();
    if (status) {
        for (int i = 0; i < recipeListSize; i++) {
            RecipeOut.write((char*)&recipeList[i], sizeof(RecipeEntry_t));
        }
    } else {
        char tempHeadBuffer[sizeof(Recipe_t)];
        memcpy(tempHeadBuffer, &recipeHead, sizeof(Recipe_t));
        RecipeOut.write(tempHeadBuffer, sizeof(Recipe_t));
        cout << "StorageCore : save recipe head over, total chunk number = " << recipeHead.fileRecipeHead.totalChunkNumber << " file size = " << recipeHead.fileRecipeHead.fileSize << endl;
        char tempBuffer[sizeof(RecipeEntry_t)];
        for (int i = 0; i < recipeListSize; i++) {
            RecipeOut.write((char*)&recipeList[i], sizeof(RecipeEntry_t));
        }
    }
    RecipeOut.close();
    return true;
}

bool StorageCore::restoreRecipeAndChunk(char* fileNameHash, uint32_t startID, uint32_t endID, ChunkList_t& restoredChunkList)
{
    ifstream RecipeIn;
    string readRecipeName;
    string recipeName;
    string DBKey(fileNameHash, FILE_NAME_HASH_SIZE);
    if (fileName2metaDB.query(DBKey, recipeName)) {
        ifstream RecipeIn;
        string readRecipeName;
        readRecipeName = RecipeNamePrefix_ + recipeName + RecipeNameTail_;
        RecipeIn.open(readRecipeName, ifstream::in | ifstream::binary);
        if (!RecipeIn.is_open()) {
            std::cerr << "StorageCore : Can not open Recipe file : " << readRecipeName;
            return false;
        }

        char readBuffer[sizeof(RecipeEntry_t) * (endID - startID)];
        RecipeIn.seekg(sizeof(Recipe_t) + startID * sizeof(RecipeEntry_t));
        RecipeIn.read(readBuffer, sizeof(RecipeEntry_t) * (endID - startID));
        RecipeIn.close();
        for (int i = 0; i < (endID - startID); i++) {
            RecipeEntry_t newRecipeEntry;
            memcpy(&newRecipeEntry, readBuffer + i * sizeof(RecipeEntry_t), sizeof(RecipeEntry_t));
            string chunkHash((char*)newRecipeEntry.chunkHash, CHUNK_HASH_SIZE);
            string chunkData;
            if (restoreChunk(chunkHash, chunkData)) {
                if (chunkData.length() != newRecipeEntry.chunkSize) {
                    cerr << "StorageCore : restore chunk logic data size error" << endl;
                    return false;
                } else {
                    Chunk_t newChunk;
                    newChunk.ID = newRecipeEntry.chunkID;
                    newChunk.logicDataSize = newRecipeEntry.chunkSize;
                    memcpy(newChunk.chunkHash, newRecipeEntry.chunkHash, CHUNK_HASH_SIZE);
                    memcpy(newChunk.encryptKey, newRecipeEntry.chunkKey, CHUNK_ENCRYPT_KEY_SIZE);
                    memcpy(newChunk.logicData, &chunkData[0], newChunk.logicDataSize);
                    restoredChunkList.push_back(newChunk);
                }

            } else {
                cerr << "StorageCore : can not restore chunk" << endl;
                return false;
            }
        }
        return true;
    } else {
        return false;
    }
}

bool StorageCore::saveChunk(std::string chunkHash, char* chunkData, int chunkSize)
{
    keyForChunkHashDB_t key;
    key.length = chunkSize;
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartStorage, NULL);
#endif
    bool status = writeContainer(key, chunkData);
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendStorage, NULL);
    writeContainerTime += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
    if (!status) {
        std::cerr << "StorageCore : Error write container" << endl;
        return status;
    }

#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartStorage, NULL);
#endif
    string dbValue;
    dbValue.resize(sizeof(keyForChunkHashDB_t));
    memcpy(&dbValue[0], &key, sizeof(keyForChunkHashDB_t));
    status = fp2ChunkDB.insert(chunkHash, dbValue);
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendStorage, NULL);
    insertDBTimeUpload += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
    if (!status) {
        std::cerr << "StorageCore : Can't insert chunk to database" << endl;
        return false;
    } else {
        currentContainer_.used_ += key.length;
        return true;
    }
}

bool StorageCore::restoreChunk(std::string chunkHash, std::string& chunkDataStr)
{
    keyForChunkHashDB_t key;
    string ans;
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timestartStorage, NULL);
#endif

    bool status = fp2ChunkDB.query(chunkHash, ans);
#if BREAK_DOWN_DEFINE == 1
    gettimeofday(&timeendStorage, NULL);
    int diff = 1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec;
    double second = diff / 1000000.0;
    queryDBTime += second;
#endif
    if (status) {
        memcpy(&key, &ans[0], sizeof(keyForChunkHashDB_t));
        char chunkData[key.length];
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timestartStorage, NULL);
#endif

        bool readContainerStatus = readContainer(key, chunkData);
#if BREAK_DOWN_DEFINE == 1
        gettimeofday(&timeendStorage, NULL);
        readContainerTime += (1000000 * (timeendStorage.tv_sec - timestartStorage.tv_sec) + timeendStorage.tv_usec - timestartStorage.tv_usec) / 1000000.0;
#endif
        if (readContainerStatus) {
            chunkDataStr.resize(key.length);
            memcpy(&chunkDataStr[0], chunkData, key.length);
            return true;
        } else {
            cerr << "StorageCore : can not read container for chunk" << endl;
            return false;
        }
    } else {
        cerr << "StorageCore : chunk not in database" << endl;
        return false;
    }
}

bool StorageCore::checkRecipeStatus(Recipe_t recipeHead, RecipeList_t recipeList)
{
    string recipeName;
    string DBKey((char*)recipeHead.fileRecipeHead.fileNameHash, FILE_NAME_HASH_SIZE);
    if (fileName2metaDB.query(DBKey, recipeName)) {
        cout << "StorageCore : current file's recipe exist, add data back, recipe file name = " << recipeName << endl;
        if (!this->saveRecipe(recipeName, recipeHead, recipeList, true)) {
            std::cerr << "StorageCore : save recipe failed " << endl;
            return false;
        }
    } else {
        char recipeNameBuffer[FILE_NAME_HASH_SIZE * 2 + 1];
        for (int i = 0; i < FILE_NAME_HASH_SIZE; i++) {
            sprintf(recipeNameBuffer + 2 * i, "%02X", recipeHead.fileRecipeHead.fileNameHash[i]);
        }
        cout << "StorageCore : current file's recipe not exist, new recipe file name = " << recipeNameBuffer << endl;
        string recipeNameNew(recipeNameBuffer, FILE_NAME_HASH_SIZE * 2);
        fileName2metaDB.insert(DBKey, recipeNameNew);
        if (!this->saveRecipe(recipeNameNew, recipeHead, recipeList, false)) {
            std::cerr << "StorageCore : save recipe failed " << endl;
            return false;
        }
    }
    cout << "StorageCore : save recipe number = " << recipeList.size() << endl;
    return true;
}

bool StorageCore::writeContainer(keyForChunkHashDB_t& key, char* data)
{
    if (key.length + currentContainer_.used_ < maxContainerSize_) {
        memcpy(&currentContainer_.body_[currentContainer_.used_], data, key.length);
        memcpy(key.containerName, &lastContainerFileName_[0], lastContainerFileName_.length());
    } else {
        string writeContainerName = containerNamePrefix_ + lastContainerFileName_ + containerNameTail_;
        currentContainer_.saveTOFile(writeContainerName);
        next_permutation(lastContainerFileName_.begin(), lastContainerFileName_.end());
        currentContainer_.used_ = 0;
        memcpy(&currentContainer_.body_[currentContainer_.used_], data, key.length);
        memcpy(key.containerName, &lastContainerFileName_[0], lastContainerFileName_.length());
    }
    key.offset = currentContainer_.used_;
    return true;
}

bool StorageCore::readContainer(keyForChunkHashDB_t key, char* data)
{
    ifstream containerIn;
    string containerNameStr((char*)key.containerName, lastContainerFileName_.length());
    string readName = containerNamePrefix_ + containerNameStr + containerNameTail_;
    if (containerNameStr.compare(currentReadContainerFileName_) == 0) {
        memcpy(data, currentReadContainer_.body_ + key.offset, key.length);
        return true;
    } else if (containerNameStr.compare(lastContainerFileName_) == 0) {
        memcpy(data, currentContainer_.body_ + key.offset, key.length);
        return true;
    } else {
        readContainerNumber++;
        containerIn.open(readName, std::ifstream::in | std::ifstream::binary);
        if (!containerIn.is_open()) {
            std::cerr << "StorageCore : Can not open Container: " << readName << endl;
            return false;
        }
        containerIn.seekg(0, ios_base::end);
        int containerSize = containerIn.tellg();
        containerIn.seekg(0, ios_base::beg);
        containerIn.read(currentReadContainer_.body_, containerSize);
        if (containerIn.gcount() != containerSize) {
            cerr << "StorageCore : read container error" << endl;
            return false;
        }
        containerIn.close();
        currentReadContainer_.used_ = containerSize;
        memcpy(data, currentReadContainer_.body_ + key.offset, key.length);
        currentReadContainerFileName_ = containerNameStr;
        return true;
    }
}

bool Container::saveTOFile(string fileName)
{
    ofstream containerOut;
    containerOut.open(fileName, std::ofstream::out | std::ofstream::binary);
    if (!containerOut.is_open()) {
        cerr << "Can not open Container file : " << fileName << endl;
        return false;
    }
    containerOut.write(this->body_, this->used_);
    cout << "Container : save " << setbase(10) << this->used_ << " bytes to file system" << endl;
    containerOut.close();
    return true;
}
