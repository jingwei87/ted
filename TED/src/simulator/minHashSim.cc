/// \file minHashSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in MinHash simulator
/// \version 0.1
/// \date 2019-08-13
///
/// \copyright Copyright (c) 2019
///

#include "../../include/minHashSim.h"


ChunkInfo::ChunkInfo() {
    memset(fp, 0, FP_SIZE + 1);
    size = 0;
}

ChunkInfo::ChunkInfo(ChunkInfo const &a) {
    memcpy(this->fp, a.fp, FP_SIZE+1);
    this->size = a.size;
}

ChunkInfo::ChunkInfo(unsigned char const inFp[FP_SIZE+1], uint64_t const inSize) {
    memcpy(this->fp, inFp, FP_SIZE+1);
    this->size = inSize;
}

ChunkInfo::~ChunkInfo() {
    memset(fp, 0, FP_SIZE + 1);
    size = 0;
}

MinHashSim::MinHashSim() {
    /* initialize minChunk */
    fprintf(stderr, "Initialize a MinHash Simulator.\n");
    memset(minChunk_, 0xff, FP_SIZE+1);
    minChunk_[FP_SIZE] = 0;
}

MinHashSim::~MinHashSim() {
    fprintf(stderr, "Destory a MinHash Simulator.\n");
    memset(minChunk_, 0xff, FP_SIZE+1);
    minChunk_[FP_SIZE] = 0;
    while (chunkQueue_.empty() == false) {
        chunkQueue_.pop();
    }
}

/// \brief decide the end of border of the segment
///
/// \param chunkHash - input chunk hash
/// \param chunkSize - chunk size
/// \return true - the end
/// \return false - not the end 
bool MinHashSim::EndOfSegment(uint8_t* const chunkHash, uint64_t const chunkSize) {
    /* segment size < MIN_SEGMENT_SIZE or segment size > MAX_SEGMENT_SIZE */ 
    if (segmentSize_ < MIN_SEGMENT_SIZE) {
        return false;
    } else if (segmentSize_ > MAX_SEGMENT_SIZE) {
        return true;
    }

    /* number of bytes to be checked */
    uint64_t numOfBytes = ceil((double) DIVISOR / 8);

    /* need to check only one byte */
    if (numOfBytes == 1) {
        return chunkHash[0] == PATTERN ? true : false;
    } else {
        /* check more than one bytes: the first numOfBytes-1 bytes are zero and the numOfBytes-th byte is one */
        size_t i = 0; 
        for (i = 0; i < numOfBytes - 1 && chunkHash[i] == 0; i++) { }
        if (i == numOfBytes - 1 && chunkHash[i] == PATTERN) {
            return true;
        } else {
            return false;
        }
    }
}




/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void MinHashSim::ProcessHashFile(std::string const inputFileName, 
    std::string const outputFileName) {
    
    /**assume size of input file is large than 32 bytes */
    char readBuffer[256];
    char* readFlag;
    char* item;
    uint8_t chunkFp[FP_SIZE + 1];
    memset(chunkFp, 0 , FP_SIZE + 1);

    /**init the input file and output file */
    FILE* fpIn = NULL;
    FILE* fpOut = NULL;
    if ((fpIn = fopen(inputFileName.c_str(), "r")) != NULL) {
        fprintf(stderr, "Open data file success, %s:%d\n", FILE_NAME, CURRENT_LIEN);
    } else {
        fprintf(stderr, "Open data file fails, %s:%d\n", FILE_NAME, CURRENT_LIEN);
    }

    fpOut = fopen(outputFileName.c_str(), "w");
    
    /**encryption key */
    uint8_t key[sizeof(int)]; 

    /**simulate the data stream come from here */

    while ((readFlag = fgets(readBuffer, sizeof(readBuffer), fpIn)) != NULL) {

        /**read chunk information into chunk buffer */    
        item = strtok(readBuffer, ":\t\n ");
        size_t index = 0;
        for (index = 0; (item != NULL) && (index < FP_SIZE); index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n ");
        }
        chunkFp[FP_SIZE] = '\0';

        /**increment chunk size */
        uint64_t size = atol((const char*)item);

        /**count the chunk information in global leveldb */
        CountChunk(chunkFp, FP_SIZE + 1, size, 0);

        /**update the minHash */
        MinHashUpdateState(chunkFp, size);

        if (EndOfSegment(chunkFp, size) == true) {
            /**generate real key */
            uint8_t key[FP_SIZE + 1];
            MinHashKeyGen(NULL, key);
            int32_t realKey = 0;
            memcpy(&realKey, key, sizeof(int32_t));

            while (chunkQueue_.empty() == false) {
                /**de-queue */
                ChunkInfo info(chunkQueue_.front());
                chunkQueue_.pop();
                /**encryption */
                uint8_t cipher[FP_SIZE + sizeof(realKey) + 1];
                memcpy(cipher, info.fp, FP_SIZE);
                memcpy(cipher + FP_SIZE, &realKey, sizeof(realKey));
                cipher[FP_SIZE + sizeof(realKey)] = '\0'; 

                /**count the encrypted chunk */
                CountChunk(cipher, FP_SIZE + sizeof(realKey) + 1, info.size, 1);

                /**print the message ciphertext */
                PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE + sizeof(key), info.size, fpOut);
            }
        }
    }

    /* process rest chunks */
    if (chunkQueue_.empty() == false) {
        /* generate real key */ 
        uint8_t key[FP_SIZE + 1];
        MinHashKeyGen(NULL, key);
        int32_t realKey = 0;
        memcpy(&realKey, key, sizeof(int32_t));

        while (chunkQueue_.empty() == false) {
            /* de-queue */
            ChunkInfo info(chunkQueue_.front());
            chunkQueue_.pop();

            /* encryption */
            uint8_t cipher[FP_SIZE + sizeof(realKey) + 1];
            memcpy(cipher, info.fp, FP_SIZE);
            memcpy(cipher + FP_SIZE, &realKey, sizeof(realKey));
            cipher[FP_SIZE + sizeof(realKey)] = '\0'; 
            /**count the encrypted chunk */
            CountChunk(cipher, FP_SIZE + sizeof(realKey) + 1, info.size, 1);

            /**print the message ciphertext */
            PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE + sizeof(key), info.size, fpOut);
        }
    }
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE + sizeof(key), 1);
}

/// \brief add chunk into queue
///
/// \param chunkHash - hash of the chunk 
/// \param chunkSize - size of the chunk
void MinHashSim::MinHashUpdateState(unsigned char* const chunkHash, 
    uint64_t const chunkSize) {
    ChunkInfo item(chunkHash, chunkSize);
    segmentSize_ += chunkSize;
    chunkQueue_.push(item);

    /**update minChunk*/
    if (memcmp(minChunk_, chunkHash, FP_SIZE) > 0) {
        memcpy(minChunk_, chunkHash, FP_SIZE);
    }
}

/// \brief generate MLE key based on minimum chunk fingerprint
///
/// \param chunkHash - hash of the chunk
/// \param key - encryption key
void MinHashSim::MinHashKeyGen(uint8_t* const chunkHash, 
    uint8_t key[FP_SIZE + 1]) {
    /**generate key */
    memcpy(key, minChunk_, FP_SIZE);
    key[FP_SIZE] = 0;

    /**reset state */
    memset(minChunk_, 0xff, FP_SIZE + 1);
    minChunk_[FP_SIZE] = 0;
    segmentSize_ = 0UL;
}