/// \file tecSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interfaces defined in TECSim
/// \version 0.1
/// \date 2019-07-11
///
/// \copyright Copyright (c) 2019
///

#include "../../include/tecSim.h"

/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void TECSim::ProcessHashFile(std::string const inputFileName, 
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
    uint8_t key[32]; 

    /**simulate the data stream come from here */
    while ((readFlag = fgets(readBuffer, sizeof(readBuffer), fpIn)) != NULL) {
        /**read chunk information into chunk buffer */    
        item = strtok(readBuffer, ":\t\n ");
        size_t index = 0;
        for (index = 0; (item != NULL) && (index < FP_SIZE); index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            // fprintf(stderr, "%02x:", chunkFp[index]);
            item = strtok(NULL, ":\t\n ");
        }
        chunkFp[FP_SIZE] = '\0';

        /**increment chunk size */
        uint64_t size = atol((const char*)item);

        /**count the chunk information in global leveldb */
        CountChunk(chunkFp, FP_SIZE + 1, size, 0);

        /**update the state in in-memory hash-table*/
        TECUpdateState(chunkFp, FP_SIZE + 1, size);

        /**key generation */
        KeyGen(chunkFp, FP_SIZE + 1, size, key);

        /**encryption (simulation) */
        uint8_t cipher[FP_SIZE + 1];

        // SimTECEncrypt(chunkFp, FP_SIZE, key, sizeof(key), cipher);
        uint8_t alignedCipher[16] = {0};
        uint8_t alignedChunkFp[16] = {0};
        memcpy(alignedChunkFp, chunkFp, FP_SIZE);
        cryptoObj_->encryptWithKey(alignedChunkFp, 16, key, alignedCipher);
        memcpy(cipher, alignedCipher, FP_SIZE);
        cipher[FP_SIZE] = '\0';

        uint64_t chunkSize = atol((const char*)item);
        /**count the encrypted chunk */
        CountChunk(cipher, FP_SIZE + 1, chunkSize, 1);

        /**print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE, chunkSize, fpOut);

        // CheckUniqueTable(chunkFp, FP_SIZE + 1);

        if (SKETCH_ENABLE) {
            if (SEGMENT_ENABLE) {
                if (currentUniqueChunk_ >= ACCURACY * SKETCH_WIDTH) {
                    fprintf(stderr,"current unique chunk number: %lu\n", currentUniqueChunk_);
                    fprintf(stderr, "start to clean up the sketch,  after receiving %d * SKETCH_WIDTH\n",
                        ACCURACY);
                    cmSketch_->ClearUp();
                    uniqueKeySet_.clear();
                    currentUniqueChunk_ = 0;
                }
            }    
        }

    }
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE, 1);
}

/// \brief update the state according to the incoming chunk
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
void TECSim::TECUpdateState(uint8_t* const chunkHash, size_t chunkHashLen, uint64_t const chunkSize) {

    std::string key = std::string((const char*)chunkHash, chunkHashLen);

    if (SKETCH_ENABLE) {
        /** using sketch */
        cmSketch_->Update(chunkHash, chunkHashLen, 1);
        
    } else {
        /** using hashtale */
        auto findResult = keyFreqTable_.find(key);

        if (findResult != keyFreqTable_.end()) {
            /**this key exists */
            findResult->second++;
        } else {
            /**this key doesn't exist */
            keyFreqTable_.insert(std::make_pair(key, 1));
        }
    }
}


/// \brief key generation process
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
/// \param key - generated encryption key <return>
void TECSim::KeyGen(uint8_t* const chunkHash, size_t chunkHashLen, uint64_t const chunkSize, 
    uint8_t key[32]) {
    
    int state = 0; /**represent the result of (current frequency / Threshold) */

    uint64_t frequency = 0;

    std::string chunkKey = std::string((const char*)chunkHash, chunkHashLen);

    if (SKETCH_ENABLE) {
        
        frequency = cmSketch_->Estimate(chunkHash, chunkHashLen);

        state = frequency / (threshold_ + 0.00000000001);

        if (enablePro) {
            state = randomNumGen_->ProRandomNumber(distriType_, state);
        } 

    } else {
        auto findResult = keyFreqTable_.find(chunkKey);

        if (findResult != keyFreqTable_.end()) {
            /**this key exists */
            frequency = findResult->second;
            
            state = frequency / (threshold_ + 0.00000000001);
        } else {
            /**the key does not exist */
            fprintf(stderr, "Error: the key does not exist. %s:%d\n",
                FILE_NAME, CURRENT_LIEN);
            exit(1);
        }

        if (enablePro) {
            state = randomNumGen_->ProRandomNumber(distriType_, state);
        } 
    }
    
    // key seed: {fp || state}
    uint8_t keySeed[FP_SIZE + sizeof(int)];
    memcpy(keySeed, chunkHash, FP_SIZE);
    memcpy(keySeed + FP_SIZE, &state, sizeof(int));

    cryptoObj_->generateHash(keySeed, FP_SIZE + sizeof(int), key);
}

/// \brief simulate the encryption process: directly append the (frequency / T) to the 
/// end of hash
///
/// \param msg - the original input message
/// \param msgLen - the length of message
/// \param key - the encryption key 
/// \param keyLen - the length of the encrytion key
/// \param output 
void TECSim::SimTECEncrypt(uint8_t* const msg, size_t const msgLen, uint8_t* const key,
    size_t const keyLen, uint8_t output[FP_SIZE + sizeof(int) + 1]) {
    
    uint8_t in[msgLen + keyLen];
    memset(in, 0 , msgLen + keyLen);
    memcpy(in, msg, msgLen);

    /**contentation the (message hash + ) */
    memcpy(in + msgLen, key, keyLen);

    memcpy(output, in, (msgLen + keyLen));

    output[FP_SIZE + sizeof(int)] = '\0';
}


