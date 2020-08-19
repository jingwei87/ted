#include "configure.hpp"

Configure::~Configure() {}
Configure::Configure() {}
Configure::Configure(std::string path)
{
    this->readConf(path);
}

void Configure::readConf(std::string path)
{
    using namespace boost;
    using namespace boost::property_tree;
    ptree root;
    read_json<ptree>(path, root);

    //Chunker Configure
    _chunkingType = root.get<uint64_t>("ChunkerConfig._chunkingType");
    _maxChunkSize = root.get<uint64_t>("ChunkerConfig._maxChunkSize");
    _minChunkSize = root.get<uint64_t>("ChunkerConfig._minChunkSize");
    _slidingWinSize = root.get<uint64_t>("ChunkerConfig._slidingWinSize");
    _averageChunkSize = root.get<uint64_t>("ChunkerConfig._avgChunkSize");
    _ReadSize = root.get<uint64_t>("ChunkerConfig._ReadSize");

    //Key Server Configure
    _keyBatchSize = root.get<uint64_t>("KeyServerConfig._keyBatchSize");
    _keyServerIP = root.get<string>("KeyServerConfig._keyServerIP");
    _keyServerPort = root.get<int>("KeyServerConfig._keyServerPort");
    _sketchTableWidth = root.get<uint64_t>("KeyServerConfig._sketchTableWidth");
    _optimalSolverComputeItemNumberThreshold = root.get<int>("KeyServerConfig._optimalSolverComputeItemNumberThreshold");
    _storageBlowPercent = root.get<double>("KeyServerConfig._storageBlowPercent");
    _secretShare = root.get<uint64_t>("KeyServerConfig._secretShare");

    //Storage Server Configure
    _maxContainerSize = root.get<uint64_t>("SPConfig._maxContainerSize");
    _storageServerIP = root.get<string>("SPConfig._storageServerIP");
    _storageServerPort = root.get<int>("SPConfig._storageServerPort");

    //server Configure
    _RecipeRootPath = root.get<std::string>("SPConfig._RecipeRootPath");
    _containerRootPath = root.get<std::string>("SPConfig._containerRootPath");
    _fp2ChunkDBName = root.get<std::string>("SPConfig._fp2ChunkDBName");
    _fp2MetaDBame = root.get<std::string>("SPConfig._fp2MetaDBame");

    //client Configure
    _clientID = root.get<int>("client._clientID");
    _sendChunkBatchSize = root.get<int>("client._sendChunkBatchSize");
    _sendRecipeBatchSize = root.get<int>("client._sendRecipeBatchSize");
    _sendShortHashMaskBitNumber = root.get<int>("client._sendShortHashMaskBitNumber");

    // key manager ip list
    _keyManagerNum = 0;
    ptree keyIpList = root.get_child("client").get_child("_keyManagerIPList");
    for(ptree::iterator iter = keyIpList.begin(); iter != keyIpList.end(); iter++) {
        string ip = iter->first;
        int port = atoi(iter->second.data().c_str());
        fprintf(stdout, "IP: %s\n", ip.c_str());
        fprintf(stdout, "Port: %d\n", port);
        _keyManagerIpArray.push_back(make_pair(ip, port));
    }
    _keyManagerNum = _keyManagerIpArray.size();
    fprintf(stdout, "Key Manager Num: %d\n", _keyManagerNum);
}

// chunking settings
uint64_t Configure::getChunkingType()
{

    return _chunkingType;
}

uint64_t Configure::getMaxChunkSize()
{

    return _maxChunkSize;
}

uint64_t Configure::getMinChunkSize()
{

    return _minChunkSize;
}

uint64_t Configure::getAverageChunkSize()
{

    return _averageChunkSize;
}

uint64_t Configure::getSlidingWinSize()
{

    return _slidingWinSize;
}

uint64_t Configure::getReadSize()
{
    return _ReadSize;
}

// key management settings
int Configure::getKeyBatchSize()
{

    return _keyBatchSize;
}

uint64_t Configure::getSketchTableWidth()
{
    return _sketchTableWidth;
}
double Configure::getStorageBlowPercent()
{
    return _storageBlowPercent;
}
std::string Configure::getKeyServerIP()
{
    return _keyServerIP;
}

int Configure::getKeyServerPort()
{
    return _keyServerPort;
}

int Configure::getOptimalSolverComputeItemNumberThreshold()
{
    return _optimalSolverComputeItemNumberThreshold;
}

std::string Configure::getStorageServerIP()
{

    return _storageServerIP;
}

int Configure::getStorageServerPort()
{

    return _storageServerPort;
}

uint64_t Configure::getMaxContainerSize()
{

    return _maxContainerSize;
}

// client settings
int Configure::getClientID()
{
    return _clientID;
}

int Configure::getSendChunkBatchSize()
{
    return _sendChunkBatchSize;
}

std::string Configure::getRecipeRootPath()
{
    return _RecipeRootPath;
}

std::string Configure::getContainerRootPath()
{
    return _containerRootPath;
}

std::string Configure::getFp2ChunkDBName()
{
    return _fp2ChunkDBName;
}

std::string Configure::getFp2MetaDBame()
{
    return _fp2MetaDBame;
}

int Configure::getSendRecipeBatchSize()
{
    return _sendRecipeBatchSize;
}

int Configure::getSendShortHashMaskBitNumber()
{
    return _sendShortHashMaskBitNumber;
}

uint32_t Configure::getKeyManagerNumber() {
    return static_cast<uint32_t>(_keyManagerNum);
}

vector<pair<string, int>> Configure::getKeyManagerIPList() {
    return _keyManagerIpArray;
}

uint64_t Configure::getSecretShare() {
    return _secretShare;
} 