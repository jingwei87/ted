/// \file tSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implementation of threshold-based encryption simulator
/// \version 0.1
/// \date 2019-08-10
///
/// \copyright Copyright (c) 2019
///

/// \brief threshold key generation process
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
/// \param key - generated encryption key <return>
#include "../../include/tSim.h"

void TSim::ThresholdKeyGen(uint8_t* const chunkHash, size_t chunkHashLen,
    uint64_t const chunkSize,uint8_t key[sizeof(int)]) {

    int state = 0; /**represent the resulut of (current frequency / Threshold) */

    uint64_t frequency = 0;

    std::string chunkKey = std::string((const char*)chunkHash, chunkHashLen);

    if (SKETCH_ENABLE) {
        frequency = cmSketch_->Estimate(chunkHash, chunkHashLen);
        if (frequency <= thresholdBase_) {
            /**low than threshold  */
            state = frequency;
        } else {
            /**high than threshold */
            state = thresholdBase_;
        }
    } else {
        auto findResult = keyFreqTable_.find(chunkKey);

        if (findResult != keyFreqTable_.end()) {
            /**this key exists */
            frequency = findResult->second;
            
            if (frequency <= thresholdBase_) {
                /**low than threshold  */
                state = frequency;
            } else {
                /**high than threshold */
                state = thresholdBase_;
            }
        } else {
            /**the key does not exists */
            fprintf(stderr, "Error: the key does not exists. %s:%d\n", 
                FILE_NAME, CURRENT_LIEN);
        }
    }
    memcpy(key, &state, sizeof(int));
}

/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void TSim::ProcessHashFile(std::string const inputFileName, 
    std::string const outputFileName) {
    
    /**assume size of input file is large than 32 bytes */
    char readBuffer[256];
    char* readFlag;
    char* item;
    uint8_t chunkFp[FP_SIZE + 1];
    memset(chunkFp, 0, FP_SIZE + 1);

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

        /**update the state in in-memory hash-table */
        TECUpdateState(chunkFp, FP_SIZE + 1, size);

        /**key generation */
        ThresholdKeyGen(chunkFp, FP_SIZE + 1, size, key);

        /**encryption (simulation) */
        uint8_t cipher[FP_SIZE + sizeof(int) + 1];

        SimTECEncrypt(chunkFp, FP_SIZE, key, sizeof(key), cipher);

        uint64_t chunkSize = atol((const char*)item);

        /**count the encrypted chunk */
        CountChunk(cipher, FP_SIZE + sizeof(key) + 1, chunkSize, 1);

        /**Print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE + sizeof(key), chunkSize, fpOut);
    }
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency distribution */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE + sizeof(key), 1);
}