/// \file sim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of simulator
/// \version 0.1
/// \date 2019-06-28
///
/// \copyright Copyright (c) 2019
///
#ifndef __SIM_H__
#define __SIM_H__

#include <algorithm>
#include <assert.h>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unordered_set>

#include "cryptoPrimitive.h"
#include "define.h"
#include "leveldb/db.h"

class Simulator {
protected:
    /// \brief count statistic information by leveldb
    ///
    /// \param name - the db file of leveldb
    /// \return leveldb::DB* - the instance of leveldb
    leveldb::DB* InitStat(const char* name);

    /**crypto operation */
    CryptoPrimitive* cryptoObj_;

    /* handler for leveldb */
    leveldb::DB* mdb_ = NULL;
    leveldb::DB* cdb_ = NULL;

    /**variables for the number of logical chunks*/
    uint64_t mLogicalChunks_ = 0UL;
    uint64_t cLogicalChunks_ = 0UL;

    /**variables for the number of unique chunks*/
    uint64_t mUniqueChunks_ = 0UL;
    uint64_t cUniqueChunks_ = 0UL;

    /**variables for the size of logical data*/
    uint64_t mLogicalSize_ = 0UL;
    uint64_t cLogicalSize_ = 0UL;

    /**variables for the size of unique data */
    uint64_t mUniqueSize_ = 0UL;
    uint64_t cUniqueSize_ = 0UL;

    /**tmp chunk size*/
    uint64_t chunkSize_ = 0UL;

    /// \brief pseudo encryption via hashing the (fingerprint + key)
    ///
    /// \param msg - input fingerprint
    /// \param msgLen - input message length
    /// \param key - encryption key
    /// \param keyLen - encryption key length
    /// \param output - the corresponding ciphertext
    void Encrypt(uint8_t* const msg, int const msgLen, uint8_t* const key,
        int const keyLen, uint8_t output[CIPHER_SIZE + 1]);

    /// \brief count frequency of chunks
    ///
    /// \param chunkHash - the hash buffer of this chunk
    /// \param chunkHashLen - the length of chunk hash
    /// \param chunkSize - the size of this chunk
    /// \param flag - 0:plaintext, 1:ciphertext
    void CountChunk(uint8_t* const chunkHash, size_t chunkHashLen,
        uint64_t const chunkSize, bool const flag);

    /// \brief print accumulate frequencies of chunks
    ///
    /// \param fileName - the output file name
    /// \param FpLength - the length of message
    /// \param flag - 0: original backup 1: encrypted backup
    void PrintChunkFreq(std::string const fileName, size_t FpLength,
        bool const flag);

    /// \brief print cipher chunk info
    ///
    /// \param plaintext - plaintext
    /// \param plaintextLen - plaintext length
    /// \param cipher - ciphertext
    /// \param cipherLen - ciphertext length
    /// \param chunkSize - the size of chunk
    /// \param fpOut - thefile pointer of output file
    void PrintCipher(uint8_t* const plaintext, size_t plainLen, uint8_t* const cipher,
        size_t cipherLen, uint64_t const chunkSize, FILE* fpOut);

    /**current unique chunk number */
    uint64_t currentUniqueChunk_;

    /**current logical chunk number */
    uint64_t currentLogicalChunk_;

    /**unique chunk table*/
    std::unordered_set<std::string> uniqueKeySet_;

    /// \brief check whether a given chunk fingerprint is unique or not
    ///
    /// \param chunkHash
    /// \param chunkHashLen
    void CheckUniqueTable(uint8_t* const chunkHash, size_t chunkHashLen);

    /// \brief check whether it is the end of a backup
    ///
    /// \param chunkHash
    /// \param chunkHashLen
    /// \return true
    /// \return false
    bool IsEndOfSingleBackup(uint8_t* const chunkHash, size_t chunkHashLen);

public:
    /// \brief Construct a new Simulator object
    ///
    Simulator();

    /// \brief Destroy the Simulator object
    ///
    virtual ~Simulator();

    /// \brief print the statistic information of this backup
    ///
    /// \param flag - 0:plaintext, 1:ciphertext
    void PrintBackupStat();

    virtual void ProcessHashFile(std::string const inputFileName,
        std::string const outputFileName)
        = 0;
};

#endif // !__
