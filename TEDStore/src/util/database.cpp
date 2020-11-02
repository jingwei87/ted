#include "database.hpp"

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