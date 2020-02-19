/// \file sim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in sim.h
/// \version 0.1
/// \date 2019-06-28
///
/// \copyright Copyright (c) 2019
///

#include "../../include/sim.h"

/// \brief count statistic information by leveldb
///
/// \param name - the db file of leveldb
/// \return leveldb::DB* - the instance of leveldb
leveldb::DB *Simulator::InitStat(const char * name) {
    leveldb::DB *pDb = NULL;
    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, name, &pDb);
    assert(status.ok() && pDb != NULL);
    return pDb;
}



/// \brief Construct a new Simulator object
///
Simulator::Simulator() {
    mdb_ = InitStat("mstat");
    cdb_ = InitStat("cstat");

    if (!CryptoPrimitive::opensslLockSetup()) {
        fprintf(stderr, "fail to set up OpenSSL locks\n");
        exit(1);
    }
    
    /**default using SHA256 and AES-256*/
    cryptoObj_ = new CryptoPrimitive(HIGH_SEC_PAIR_TYPE); 
    fprintf(stderr, "Initialize the base simulator.\n");


    currentUniqueChunk_ = 0;

    currentLogicalChunk_ = 0;

    if (SKETCH_ENABLE) {
        fprintf(stderr, "Using Sketch to count.\n");
    } else {
        fprintf(stderr, "Using Hashtable to count.\n");
    }
}

/// \brief Destroy the Simulator object
///
Simulator::~Simulator() {
    fprintf(stderr, "Start to destory base simulator\n");
    fprintf(stderr, "Start to destory the levelDB\n");
    delete mdb_;
    delete cdb_;
    delete cryptoObj_;
    leveldb::Options optionsMDB;
    leveldb::Options optionsCDB;
    leveldb::Status statusMDB = leveldb::DestroyDB("mstat", optionsMDB);
    leveldb::Status statusCDB = leveldb::DestroyDB("cstat", optionsCDB);
    assert(statusMDB.ok() && statusCDB.ok());
}


/// \brief pseudo encryption via hashing the (fingerprint + key)
///
/// \param msg - input fingerprint
/// \param msgLen - input message length
/// \param key - encryption key
/// \param keyLen - encryption key length
/// \param output - the corresponding ciphertext
void Simulator::Encrypt(uint8_t* const msg, int const msgLen, uint8_t* const key, 
    int const keyLen, uint8_t output[CIPHER_SIZE+1]) {
    uint8_t in[msgLen + keyLen];
    memset(in, 0, msgLen + keyLen);
    memcpy(in, msg, msgLen);
    memcpy(in + msgLen, key, keyLen);
    uint8_t out[CIPHER_SIZE];
    cryptoObj_->generateHash(in, (msgLen + keyLen), out);
    memcpy(output, out, CIPHER_SIZE);
    output[CIPHER_SIZE + 1] = '\0';
}



/// \brief count the frequency of chunks
///
/// \param chunkHash - the hash of this chunk
/// \param chunkSize - the size of this chunk
/// \param flag - 0: count original backup, 1: count encrypted backup
void Simulator::CountChunk(uint8_t* const chunkHash, size_t chunkHashLen,
    uint64_t const chunkSize, bool const flag) {
    std::string exs = "";
    std::string countString;
    uint64_t count;

    /**conver the chunkhash to the string as the key */
    std::string key = std::string((const char*) chunkHash, chunkHashLen);

    leveldb::DB* db;
    if (flag == 0) {
        db = mdb_;
        /**count stat of the original backup */
        mLogicalChunks_++;
        mLogicalSize_ += chunkSize;
    } else {
        db = cdb_;
        /**count stat of the encrypted back */
        cLogicalChunks_++;
        cLogicalSize_ += chunkSize;
    }

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &exs);

    /**check if it is duplicated */
    if (status.ok() == 0) {
        /**unique chunk */
        count = 1;
        countString = "1";
        status = db->Put(leveldb::WriteOptions(), key, countString);

        if (flag == 0) {
            /**for the original backup */
            mUniqueChunks_++;
            mUniqueSize_ += chunkSize;
        } else if (flag == 1) {
            /**for the encrypted backup */
            cUniqueChunks_++;
            cUniqueSize_ += chunkSize;
        } else {
            fprintf(stderr, "the flag setting is wrong, %s:%d\n", FILE_NAME, CURRENT_LIEN);
            exit(1);
        }

    } else {
        /**duplicate chunk */
        count = atol((const char*) exs.c_str());
        count++;
        countString = std::to_string(count);
        status = db->Put(leveldb::WriteOptions(), key, countString);
    }
}

/// \brief print the statistic information of this backup
///
/// \param flag - 0:plaintext, 1:ciphertext
void Simulator::PrintBackupStat() {
    printf("============== Original Backup =============\n");
    printf("Logical original chunks number: %lu\n", mLogicalChunks_);
    printf("Logical original chunks size: %lfGB\n", 
       static_cast<double>(mLogicalSize_) / (B_TO_GB));
    printf("Unique original chunks number: %lu\n", mUniqueChunks_);
    printf("Unique original chunks size: %lfGB\n",
       static_cast<double>(mUniqueSize_) / (B_TO_GB));

    printf("============== Encrypted Backup ============\n");
    printf("Logical encrypted chunks size: %lu\n", cLogicalSize_);
    printf("Logical encrypted chunks number: %lu\n", cLogicalChunks_);
    printf("Logical encrypted chunks size: %lfGB\n",
       static_cast<double>(cLogicalSize_) / (B_TO_GB));
    printf("Unique encrypted chunks size: %lu\n", cUniqueSize_);
    printf("Unique encrypted chunks number: %lu\n", cUniqueChunks_);
    printf("Unique encrypted chunks size: %lfGB\n", 
       static_cast<double>(cUniqueSize_) / (B_TO_GB));

    printf("============== Storage Saving Ratio ========\n");
    double oriSaveSizeRatio = 
        static_cast<double>(mLogicalSize_ - mUniqueSize_) / mLogicalSize_;
    printf("Original Storage Saving (Size): %lf\n", oriSaveSizeRatio);

    double oriSaveChunkRatio = 
        static_cast<double>(mLogicalChunks_ - mUniqueChunks_) / mLogicalChunks_;
    printf("Original Storage Saving (Chunk): %lf\n", oriSaveChunkRatio);

    double encryptSaveSizeRatio = 
        static_cast<double>(cLogicalSize_ - cUniqueSize_) / cLogicalSize_;
    printf("Encrypted Storage Saving (Size): %lf\n", encryptSaveSizeRatio);

    double encryptSaveChunkRatio = 
        static_cast<double>(cLogicalChunks_ - cUniqueChunks_) / cLogicalChunks_;
    printf("Encrypted Storage Saving (Chunk): %lf\n", encryptSaveChunkRatio);

    printf("============== Comparsion Loss ==============\n");
    printf("Storage Blowup (Size): %.6lf\n",
       static_cast<double>(cUniqueSize_ - mUniqueSize_) / mUniqueSize_);
    printf("Storage Blowup (Chunk): %.6lf\n",
       static_cast<double>(cUniqueChunks_ - mUniqueChunks_) / mUniqueChunks_);
    printf("Storage Ration Loss Rate (Size): %.6lf\n",
       (oriSaveSizeRatio - encryptSaveSizeRatio) / oriSaveSizeRatio);
    printf("Storage Ration Loss Rate (Chunk): %.6lf\n",
       (oriSaveChunkRatio - encryptSaveChunkRatio) / oriSaveChunkRatio);    
}


/// \brief print accumulate frequencies of chunks
///
/// \param fileName - the output file name
/// \param FpLength - the length of message
/// \param flag - 0: original backup 1: encrypted backup
void Simulator::PrintChunkFreq(std::string const fileName, size_t FpLength, 
    bool const flag) {
    leveldb::DB* db;
    std::string name;
    FILE* fp;
    if (flag == 0) {
        /**print the frequency of the original backup */
        fprintf(stderr, "print the frequency of the original backup\n");
        db = mdb_;
        //name = RESULT_DIR + fileName + ".pfreq";
        name = fileName + ".pfreq";

    } else if (flag == 1) {
        /**print the frequency of the encrypted backup */
        fprintf(stderr, "print the frequency of the encrypted backup\n");
        db = cdb_;
        //name = RESULT_DIR + fileName + ".cfreq";
        name = fileName + ".cfreq";

    } else {
        fprintf(stderr, "Error: flag setting is wrong, %s:%d\n", FILE_NAME, CURRENT_LIEN);
        exit(1);
    }

    fp = fopen(name.c_str(), "w");
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());

    size_t i = 0;   

    /**iterate in the leveldb */
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string keyStr = it->key().ToString();
        std::string valueStr = it->value().ToString();

        for (i = 0; i < FpLength - 1; i++) {
            fprintf(fp, "%02x:", (uint8_t)keyStr.c_str()[i]);
        }
        if (i == FpLength - 1) {
            fprintf(fp, "%02x\t\t", (unsigned char)keyStr.c_str()[i]);
        }

        fprintf(fp, "%d\n", atoi(valueStr.c_str()));
    }
    fclose(fp);
    it->~Iterator();
    free(it);
}

/// \brief print cipher chunk info
///
/// \param plaintext - plaintext
/// \param plaintextLen - plaintext length
/// \param cipher - ciphertext
/// \param cipherLen - ciphertext length
/// \param chunkSize - the size of chunk
/// \param fpOut - thefile pointer of output file
void Simulator::PrintCipher(uint8_t* const plaintext, size_t plainLen, uint8_t* const cipher,
    size_t cipherLen, uint64_t const chunkSize, FILE* fpOut) {
    
    /**print the encrypted message */
    if (FULL_CIPHER_TEXT) {
        /**print full cipher text: hash + state */
        for (size_t i = 0; i < cipherLen - 1; i++) {
            fprintf(fpOut, "%02x:", cipher[i]);
        }
        fprintf(fpOut, "%02x", cipher[cipherLen - 1]);
    
    } else {
        for (size_t i = 0; i < cipherLen - plainLen - 1; i++) {
            fprintf(fpOut, "%02x:", cipher[plainLen + i]);
        }
        fprintf(fpOut, "%02x", cipher[cipherLen - 1]);
    }
        
    fprintf(fpOut, "\t\t%lu\t\t10\n", chunkSize);
}

/// \brief check whether a given chunk fingerprint is unique or not
///
/// \param chunkHash 
/// \param chunkHashLen
void Simulator::CheckUniqueTable(uint8_t* const chunkHash, size_t chunkHashLen) {
    
    std::string chunkKey = std::string((const char*)chunkHash, chunkHashLen);

    auto findResult = uniqueKeySet_.find(chunkKey);

    if (findResult != uniqueKeySet_.end()) {
        /**this chunk is not unique */
    } else {
        /**this chunk is unique*/
        currentUniqueChunk_++;
        uniqueKeySet_.insert(chunkKey);
    }
}

/// \brief check whether it is the end of a backup
///
/// \param chunkHash 
/// \param chunkHashLen 
/// \return true 
/// \return false 
bool Simulator::IsEndOfSingleBackup(uint8_t* const chunkHash, 
    size_t chunkHashLen) {
    //TODO: to check the end of a backup
    return true;
}
