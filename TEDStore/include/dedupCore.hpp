#ifndef TEDSTORE_DEDUPCORE_HPP
#define TEDSTORE_DEDUPCORE_HPP

#include "configure.hpp"
#include "cryptoPrimitive.hpp"
#include "dataStructure.hpp"
#include "database.hpp"
#include "messageQueue.hpp"
#include "protocol.hpp"
#include <bits/stdc++.h>

using namespace std;

class DedupCore {
private:
    CryptoPrimitive* cryptoObj_;

public:
    DedupCore();
    ~DedupCore();
    bool dedupByHash(HashList_t in, RequiredChunk_t& out);
};

#endif //TEDSTORE_DEDUPCORE_HPP
