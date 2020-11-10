#ifndef TEDSTORE_CHUNK_HPP
#define TEDSTORE_CHUNK_HPP

#include "configure.hpp"
#include <bits/stdc++.h>

using namespace std;

typedef struct {
    u_char hash[CHUNK_HASH_SIZE];
} Hash_t;
// system basic data structures
typedef struct {
    uint32_t ID;
    int type;
    int logicDataSize;
    u_char logicData[MAX_CHUNK_SIZE];
    u_char chunkHash[CHUNK_HASH_SIZE];
    u_char encryptKey[CHUNK_ENCRYPT_KEY_SIZE];
} Chunk_t;

typedef struct {
    u_char chunkHash[CHUNK_HASH_SIZE];
} ChunkHash_t;

typedef struct {
    vector<ChunkHash_t> hash_;
} HashList_t;

// HIGH - 16460 LOW - 16428

typedef struct {
    int logicDataSize;
    char logicData[MAX_CHUNK_SIZE];
    char chunkHash[CHUNK_HASH_SIZE];
} StorageCoreData_t;

typedef struct {
    uint32_t ID;
    int logicDataSize;
    char logicData[MAX_CHUNK_SIZE];
} RetrieverData_t;

typedef struct {
    uint32_t chunkID;
    int chunkSize;
    u_char chunkHash[CHUNK_HASH_SIZE];
    u_char chunkKey[CHUNK_ENCRYPT_KEY_SIZE];
} RecipeEntry_t;

typedef struct {
    uint64_t fileSize;
    u_char fileNameHash[FILE_NAME_HASH_SIZE];
    uint64_t totalChunkNumber;
} FileRecipeHead_t;

typedef struct {
    uint64_t fileSize;
    u_char fileNameHash[FILE_NAME_HASH_SIZE];
    uint64_t totalChunkKeyNumber;
} KeyRecipeHead_t;

typedef struct {
    FileRecipeHead_t fileRecipeHead;
    KeyRecipeHead_t keyRecipeHead;
} Recipe_t;

typedef struct {
    union {
        Chunk_t chunk;
        Recipe_t recipe;
    };
    int dataType;
} Data_t;

typedef struct {
    u_char originHash[CHUNK_HASH_SIZE];
    u_char key[CHUNK_ENCRYPT_KEY_SIZE];
} KeyGenEntry_t;

typedef struct {
    int fd;
    int epfd;
    u_char hash[CHUNK_HASH_SIZE];
    u_char key[CHUNK_ENCRYPT_KEY_SIZE];
} Message_t;

typedef struct {
    int messageType;
    int clientID;
    int dataSize;
} NetworkHeadStruct_t;

// database data structures
typedef struct {
    u_char containerName[16];
    uint32_t offset;
    uint32_t length;
} keyForChunkHashDB_t;

typedef struct {
    char RecipeFileName[FILE_NAME_HASH_SIZE];
    uint32_t version;
} keyForFilenameDB_t;

typedef vector<uint32_t> RequiredChunk_t;

typedef vector<Chunk_t> ChunkList_t;

typedef vector<RecipeEntry_t> RecipeList_t;

typedef struct {
    uint32_t nonce;
    bool isShare;
    u_char singleChunkHash[4 * sizeof(int)];
} keyGenEntry_t;

typedef struct {
    u_char shaKeySeed[CHUNK_ENCRYPT_KEY_SIZE];
} SimpleKeySeed_t;

typedef struct {
    u_char hhashKeySeed[HHASH_KEY_SEED];
} HHashKeySeed_t;

typedef struct {
    bool isShare = false;
    union {
        SimpleKeySeed_t simpleKeySeed;
        HHashKeySeed_t hhashKeySeed;
    };
} KeySeedReturnEntry_t;

typedef struct {
    int tedSeedIndex;
    int shareIndexArray[K_PARA - 1];
} ShareIndexEntry_t;


#endif //TEDSTORE_CHUNK_HPP
