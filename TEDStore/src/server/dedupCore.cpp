#include "dedupCore.hpp"

extern Database fp2ChunkDB;
extern Configure config;

DedupCore::DedupCore()
{
    cryptoObj_ = new CryptoPrimitive();
}

DedupCore::~DedupCore()
{
    if (cryptoObj_ != nullptr)
        delete cryptoObj_;
}

bool DedupCore::dedupByHash(HashList_t in, RequiredChunk_t& out)
{
    out.clear();
    string tmpdata;
    int size = in.hash_.size();
    for (int i = 0; i < size; i++) {
        string key((char*)in.hash_[i].chunkHash, CHUNK_HASH_SIZE);
        if (fp2ChunkDB.query(key, tmpdata)) {
            continue;
        } else {
            out.push_back(i);
        }
    }
    return true;
}
