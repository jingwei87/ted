#ifndef TEDSTORE_DATABASE_HPP
#define TEDSTORE_DATABASE_HPP

#include "dataStructure.hpp"
#include <rocksdb/db.h>
#include <bits/stdc++.h>
#include <boost/thread.hpp>
using namespace std;

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

#endif //TEDSTORE_DATABASE_HPP
