#ifndef TEDSTORE_DATABASE_HPP
#define TEDSTORE_DATABASE_HPP

#include "dataStructure.hpp"
#include "configure.hpp"
#include "leveldb/db.h"
#include "leveldb/cache.h"
#include <bits/stdc++.h>
#include <boost/thread.hpp>

using namespace std;
class Database {
private:
    leveldb::DB* levelDBObj_ = nullptr;
    std::mutex mutexDataBase_;
    std::string dbName_;
    leveldb::Options options;

public:
    Database() {};
    Database(std::string dbName);
    ~Database();
    bool openDB(std::string dbName);
    bool query(std::string key, std::string& value);
    bool insert(std::string key, std::string value);
    uint64_t getDBSize();
};

#endif //TEDSTORE_DATABASE_HPP
