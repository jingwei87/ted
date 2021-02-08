#include "database.hpp"

#if DATABASE_TYPE == ROCKSDB

bool Database::query(std::string key, std::string& value)
{
    rocksdb::Status queryStatus = this->rocksDBObj_->Get(rocksdb::ReadOptions(), key, &value);
    return queryStatus.ok();
}

bool Database::insert(std::string key, std::string value)
{
    rocksdb::Status insertStatus = this->rocksDBObj_->Put(rocksdb::WriteOptions(), key, value);
    return insertStatus.ok();
}

bool Database::openDB(std::string dbName)
{
    fstream dbLock;
    dbLock.open("." + dbName + ".lock", std::fstream::in);
    if (dbLock.is_open()) {
        dbLock.close();
        std::cerr << "Database locked" << endl;
        return false;
    }
    dbName_ = dbName;

    rocksdb::Options options;
    options.create_if_missing = true;
    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();
    options.OptimizeForPointLookup(128);
    rocksdb::Status status = rocksdb::DB::Open(options, dbName, &this->rocksDBObj_);
    assert(status.ok());
    if (status.ok()) {
        return true;
    } else {
        return false;
    }
}

Database::Database(std::string dbName)
{
    this->openDB(dbName);
}

Database::~Database()
{
    std::string name = "." + dbName_ + ".lock";
    remove(name.c_str());
}

#elif DATABASE_TYPE == LEVELDB

bool Database::query(std::string key, std::string& value)
{
    leveldb::Status queryStatus = this->levelDBObj_->Get(leveldb::ReadOptions(), key, &value);
    return queryStatus.ok();
}

bool Database::insert(std::string key, std::string value)
{
    leveldb::Status insertStatus = this->levelDBObj_->Put(leveldb::WriteOptions(), key, value);
    return insertStatus.ok();
}

uint64_t Database::getDBSize()
{
    std::lock_guard<std::mutex> locker(this->mutexDataBase_);
    leveldb::Iterator* it = this->levelDBObj_->NewIterator(leveldb::ReadOptions());
    uint64_t counter = 0;
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        counter++;
    }
    return counter;
}

bool Database::openDB(std::string dbName)
{
    fstream dbLock;
    dbLock.open("." + dbName + ".lock", std::fstream::in);
    if (dbLock.is_open()) {
        dbLock.close();
        std::cerr << "Database : database locked" << endl;
        return false;
    }
    dbName_ = dbName;

    options.create_if_missing = true;
    options.block_cache = leveldb::NewLRUCache(128 * 1024 * 1024);
    leveldb::Status status = leveldb::DB::Open(options, dbName, &this->levelDBObj_);
    assert(status.ok());
    if (status.ok()) {
        return true;
    } else {
        return false;
    }
}

Database::Database(std::string dbName)
{
    this->openDB(dbName);
}

Database::~Database()
{
    std::string name = "." + dbName_ + ".lock";
    remove(name.c_str());
    delete this->levelDBObj_;
    delete options.block_cache;
}

#endif