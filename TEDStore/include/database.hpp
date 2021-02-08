#ifndef TEDSTORE_DATABASE_HPP
#define TEDSTORE_DATABASE_HPP

#include "dataStructure.hpp"
#include "configure.hpp"
#if DATABASE_TYPE == ROCKSDB
#include <rocksdb/db.h>
#elif DATABASE_TYPE == LEVELDB
#include "leveldb/db.h"
#include "leveldb/cache.h"
#elif DATABASE_TYPE == PEBBLESDB
#include "pebblesdb/db.h"
#include "pebblesdb/cache.h"
#endif
#include <bits/stdc++.h>
#include <boost/thread.hpp>

using namespace std;

#if DATABASE_TYPE == ROCKSDB

class Database {
private:
    rocksdb::DB* rocksDBObj_ = nullptr;
    std::string dbName_;

public:
    Database(){};
    Database(std::string dbName);
    ~Database();
    bool openDB(std::string dbName);
    bool query(std::string key, std::string& value);
    bool insert(std::string key, std::string value);
};

#elif ((DATABASE_TYPE == LEVELDB) || (DATABASE_TYPE == PEBBLESDB))

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

#endif

#endif //TEDSTORE_DATABASE_HPP
