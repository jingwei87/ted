#ifndef TEDSTORE_STORAGECORE_HPP
#define TEDSTORE_STORAGECORE_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "database.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include "socket.hpp"
#include <bits/stdc++.h>

using namespace std;

class Container {
public:
    uint32_t used_ = 0;
    char body_[2 << 23]; //8 M container size
    Container() {}
    ~Container() {}
    bool saveTOFile(string fileName);
};

class StorageCore {
private:
    std::string lastContainerFileName_;
    std::string currentReadContainerFileName_;
    std::string containerNamePrefix_;
    std::string containerNameTail_;
    std::string RecipeNamePrefix_;
    std::string RecipeNameTail_;
    CryptoPrimitive* cryptoObj_;
    Container currentContainer_;
    Container currentReadContainer_;
    uint64_t maxContainerSize_;
    bool writeContainer(keyForChunkHashDB_t& key, char* data);
    bool readContainer(keyForChunkHashDB_t key, char* data);
    double queryDBTime = 0;
    double readContainerTime = 0;
    int readContainerNumber = 0;
    double queryDBTimeUpload = 0;
    double insertDBTimeUpload = 0;
    double writeContainerTime = 0;
    int uniqueChunkNumber = 0;

public:
    StorageCore();
    ~StorageCore();

    bool restoreChunks(NetworkHeadStruct_t& networkHead, char* data);
    bool storeRecipes(char* fileNameHash, u_char* recipeContent, uint64_t recipeSize);
    bool restoreRecipeAndChunk(u_char* recipeBuffer, uint32_t startID, uint32_t endID, ChunkList_t& restoredChunkList);
    bool storeChunk(string chunkHash, char* chunkData, int chunkSize);
    bool storeChunks(NetworkHeadStruct_t& networkHead, char* data);
    bool restoreChunk(std::string chunkHash, std::string& chunkDataStr);
    bool restoreRecipes(char* fileNameHash, u_char* recipeContent, uint64_t& recipeSize);
};

#endif
