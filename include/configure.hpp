#ifndef TEDSTORE_CONFIGURE_HPP
#define TEDSTORE_CONFIGURE_HPP

#include <bits/stdc++.h>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace std;

// macro for system running types
#define BREAK_DOWN_DEFINE 0 // 0:breakdown disable| 1:breakdown enable
#define SINGLE_THREAD_KEY_MANAGER 0 // 0:dual thread key server| 1:single thread key server
#define SEND_CHUNK_LIST_METHOD 1 //0:reduce structure overhead | 1:fix second upload error on some platform

//macro for the type of chunker
#define CHUNKER_FIX_SIZE_TYPE 0
#define CHUNKER_VAR_SIZE_TYPE 1
#define CHUNKER_TRACE_DRIVEN_TYPE_FSL 2
#define CHUNKER_TRACE_DRIVEN_TYPE_UBC 3

#define MIN_CHUNK_SIZE 4096 //macro for the min size of variable-size chunker
#define AVG_CHUNK_SIZE 8192 //macro for the average size of variable-size chunker
#define MAX_CHUNK_SIZE 16384 //macro for the max size of variable-size chunker

#define CHUNK_FINGER_PRINT_SIZE 32
#define CHUNK_HASH_SIZE 32
#define CHUNK_ENCRYPT_KEY_SIZE 32
#define FILE_NAME_HASH_SIZE 32

#define DATA_TYPE_RECIPE 1
#define DATA_TYPE_CHUNK 2

#define NETWORK_MESSAGE_DATA_SIZE 18 * 1000 * 1000
#define CRYPTO_BLOCK_SZIE 16

#define KEY_SERVER_UNIFORM_INT_RAND 1
#define KEY_SERVER_POISSON_RAND 2
#define KEY_SERVER_NORMAL_RAND 3
#define KEY_SERVER_GEOMETRIC_RAND 4
#define KEY_SERVER_NO_RAND 5
#define KEY_SERVER_RANDOM_TYPE KEY_SERVER_UNIFORM_INT_RAND

class Configure {
private:
    // following settings configure by macro set
    uint64_t _runningType; // localDedup \ serverDedup

    // chunking settings
    uint64_t _chunkingType; // varSize \ fixedSize \ simple
    uint64_t _maxChunkSize;
    uint64_t _minChunkSize;
    uint64_t _averageChunkSize;
    uint64_t _slidingWinSize;
    uint64_t _segmentSize; // if exist segment function
    uint64_t _ReadSize; //128M per time

    // key management settings
    uint64_t _keyServerNumber;
    std::string _keyServerIP;
    int _keyServerPort;
    int _keyBatchSize;
    uint64_t _sketchTableWidth;
    double _storageBlowPercent;
    int _optimalSolverComputeItemNumberThreshold;

    // storage management settings
    uint64_t _storageServerNumber;
    std::string _storageServerIP;
    int _storageServerPort;
    uint64_t _maxContainerSize;

    //server setting
    std::string _RecipeRootPath;
    std::string _containerRootPath;
    std::string _fp2ChunkDBName;
    std::string _fp2MetaDBame;

    //client settings
    int _clientID;
    int _sendChunkBatchSize;
    int _sendRecipeBatchSize;
    int _sendShortHashMaskBitNumber;

public:
    //  Configure(std::ifstream& confFile); // according to setting json to init configure class
    Configure(std::string path);

    Configure();

    ~Configure();

    void readConf(std::string path);

    uint64_t getRunningType();

    // chunking settings
    uint64_t getChunkingType();
    uint64_t getMaxChunkSize();
    uint64_t getMinChunkSize();
    uint64_t getAverageChunkSize();
    uint64_t getSlidingWinSize();
    uint64_t getSegmentSize();
    uint64_t getReadSize();

    // key management settings
    std::string getKeyServerIP();
    int getKeyServerPort();
    int getkeyServerRArequestPort();
    int getKeyBatchSize();
    uint64_t getSketchTableWidth();
    int getOptimalSolverComputeItemNumberThreshold();
    double getStorageBlowPercent();

    //message queue size setting
    int get_Data_t_MQSize();
    int get_RetrieverData_t_MQSize();
    int get_StorageData_t_MQSize();

    // storage management settings
    std::string getStorageServerIP();
    int getStorageServerPort();
    uint64_t getMaxContainerSize();
    std::string getRecipeRootPath();
    std::string getContainerRootPath();
    std::string getFp2ChunkDBName();
    std::string getFp2MetaDBame();

    //client settings
    int getClientID();
    int getSendChunkBatchSize();
    int getSendRecipeBatchSize();
    int getSendShortHashMaskBitNumber();
};

#endif //TEDSTORE_CONFIGURE_HPP
