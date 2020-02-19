/// \file localTecSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in local tec simulator
/// \version 0.1
/// \date 2019-07-12
///
/// \copyright Copyright (c) 2019
///

#include "../../include/localTecSim.h"

long inline calDiff(struct timeval &timestart, struct timeval &timeend) {
    long diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    return diff;
}


/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void LocalTECSim::ProcessHashFile(std::string const inputFileName, 
    std::string const outputFileName) {
    
    struct timeval stime, etime;

    /**assume size of input file is large than 32 bytes */
    char readBuffer[256];
    char* readFlag;
    char* item;
    uint8_t chunkFp[FP_SIZE + 1];

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

    /**simulate the data stream come from here 
     * the first pass using in-memory hash
    */
    
    /**set the initial threshold as 1*/
    uint32_t initThreshold = 1;
    thresholdArray_.push_back(initThreshold);
    size_t currentSegIndex = 0;

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

        /**record the information in global leveldb (for message)*/
        CountChunk(chunkFp, FP_SIZE + 1, size, 0);

        /**update the state in in-memory hash table*/
        GlobalUpdateState(chunkFp, FP_SIZE + 1, size);
        globalCounter_++;
        localCounter_++;
                
        LocalKeyGen(chunkFp, FP_SIZE + 1, size, key, thresholdArray_[currentSegIndex]);

        /**calculate the optimization problem */
        if (localCounter_ == batchSize_) {
            vector<pair<string, uint64_t> > inputDistri;

            /**Solve the optimization from here*/
            if (SKETCH_ENABLE) {
                uint32_t firstRow[SKETCH_WIDTH];
                uint32_t* sketchFirstRow = cmSketch_->GetFirstRow();
                size_t index = 0;
                for (index = 0; index < SKETCH_WIDTH; index++) {
                    firstRow[index] = sketchFirstRow[index];
                    if (firstRow[index] != 0) {
                        inputDistri.push_back(std::make_pair("1", 
                            static_cast<uint64_t>(firstRow[index])));
                    } 
                }
            } else {
                for (auto it = globalKeyFreqTable_.begin(); 
                    it != globalKeyFreqTable_.end(); it++) {
                    /**reconstruct a vector from the the global key table */
                    std::string fP = it->first;
                    uint64_t freq = it->second;
                    inputDistri.push_back(std::make_pair(fP, freq));
                }
            }

            /**initialize Optimization Solver */
            OpSolver* mySolver = new OpSolver(blowUpRate_, inputDistri); 

            /**record the time */
            gettimeofday(&stime, NULL);
            uint32_t threshold = mySolver->GetOptimal();
            gettimeofday(&etime, NULL);
            totalTime_ += calDiff(stime, etime);
            solveTimes_++;

            mySolver->PrintResult();
            delete mySolver;
            /**store the threshold in array */
            thresholdArray_.push_back(threshold);
             fprintf(stderr, "Current segment: %lu, chunk number: %lu, threshold: %u \n", 
                currentSegIndex, localCounter_, thresholdArray_[currentSegIndex]);
            currentSegIndex++;
            localCounter_ = 0;
            fprintf(stderr, "Process Logical Chunk: %lu\n", globalCounter_);
        }

        /**start to do the encryption*/
        // SimTECEncrypt(chunkFp, FP_SIZE, key, sizeof(key), cipher);
        uint8_t cipher[FP_SIZE + 1];
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
    }

    // fprintf(stderr, "Current segment: %lu, chunk number: %lu, threshold: %u\n",
    //     currentSegIndex, localCounter_, thresholdArray_[currentSegIndex]);
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
void LocalTECSim::GlobalUpdateState(uint8_t* const chunkHash, 
    size_t chunkHashLen, uint64_t const chunkSize) {

    std::string key = std::string((const char*)chunkHash, chunkHashLen);
    if (SKETCH_ENABLE) {
        cmSketch_->Update(chunkHash, chunkHashLen, 1);

    } else {
        auto findResult = globalKeyFreqTable_.find(key);

        if (findResult != globalKeyFreqTable_.end()) {
            /**this key exists */
            findResult->second++;
        } else {
            /**this key doesn't exist */
            globalKeyFreqTable_.insert(std::make_pair(key, 1));
        }
    }
}

/// \brief update the state according to the incoming chunk in local hash table
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
void LocalTECSim::LocalUpdateState(uint8_t* const chunkHash,
    size_t chunkHashLen, uint64_t const chunkSize) {

    std::string key = std::string((const char*)chunkHash, chunkHashLen);
    auto findResult = globalKeyFreqTable_.find(key);

    if (findResult != globalKeyFreqTable_.end()) {
        /**this key exists */
        uint64_t currentFreq = findResult->second;

        /**check the result in local frequency table*/

        auto findLocalResult = localKeyFreqTable_.find(key);
        if (findLocalResult != localKeyFreqTable_.end()) {
            /**this key exists in local table, update directly*/
            findLocalResult->second = currentFreq;
        } else {
            /**this key doesn't exist*/
            localKeyFreqTable_.insert(std::make_pair(key, currentFreq));
        }

    } else {
        /**this key doesn't exist*/
        fprintf(stderr, "ERROR: cannot find the key in global table, %s:%d\n", FILE_NAME, CURRENT_LIEN);
        exit(1);
    }
    /**TODO: add sketch here */
}

/// \brief process an input hash file of encryption incremental local
///
/// \param inputFileName - the input file name
/// \param ouputFileName - the output file name
void LocalTECSim::ProcessHashFileLocal(std::string const inputFileName,
    std::string const outputFileName) {
    
    /**assume size of input file is large than 32 bytes */
    char readBuffer[256];
    char* readFlag;
    char* item;
    uint8_t chunkFp[FP_SIZE + 1];
    memset(chunkFp, 0 , FP_SIZE + 1);

    /**init the input file and output */
    FILE* fpIn = NULL;
    FILE* fpOut = NULL;

    if ((fpIn = fopen(inputFileName.c_str(), "r")) != NULL) {
        fprintf(stderr, "Open data file success, %s:%d\n", FILE_NAME, CURRENT_LIEN);
    } else {
        fprintf(stderr, "Open data file fails, %s:%d\n", FILE_NAME, CURRENT_LIEN);
    }

    fpOut = fopen(outputFileName.c_str(), "w");

    /*encryption key */
    uint8_t key[sizeof(int)];

    /**simulate the data stream come from here
     * the first pass using in-memory hash
     */

    while ((readFlag = fgets(readBuffer, sizeof(readBuffer), fpIn)) != NULL) {
        
        /**read chunk information into chunk buffer */
        item = strtok(readBuffer, ":\t\n");
        size_t index = 0;
        for (index = 0; (item != NULL) && (index < FP_SIZE); index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunkFp[FP_SIZE] = '\0';

        /**increment chunk size */
        uint64_t size = atol((const char*)item);

        /**record the information in global leveldb (for message) */
        CountChunk(chunkFp, FP_SIZE + 1, size, 0);

        /**update the state in in-memory hash table */
        GlobalUpdateState(chunkFp, FP_SIZE + 1, size);
        LocalUpdateState(chunkFp, FP_SIZE + 1, size);
        globalCounter_++;
        localCounter_++;

        /**calculate the optimization problem */
        if (localCounter_ == batchSize_) {
            vector<pair<string, uint64_t> > inputDistri;
            /**solve the optimization from here */
            for (auto it = localKeyFreqTable_.begin();
                    it != localKeyFreqTable_.end(); it++) {
                /**reconstruct a vector from the local key table */
                std::string fP = it->first;
                uint64_t freq = it->second;
                inputDistri.push_back(std::make_pair(fP, freq));
            }

            /**initialize Optimization Solver */
            OpSolver* mySolver = new OpSolver(blowUpRate_, inputDistri);
            uint32_t threshold = mySolver->GetOptimal();
            mySolver->PrintResult();
            delete mySolver;
            
            /**clean up the local hash table */
            LocalHashTableCleanUp();
            localCounter_ = 0;
            /**store the threshold in array */
            thresholdArray_.push_back(threshold);
        }
    }

    /**calculate the final threshold */
    if (localCounter_ != 0) {
        vector<pair<string, uint64_t> > inputDistri;
        /**solve the optimization problem here */
        for (auto it = localKeyFreqTable_.begin();
                it != localKeyFreqTable_.end(); it++) {
            /**reconstruct a vector from the global key table */
            std::string fP = it->first;
            uint64_t freq = it->second;
            inputDistri.push_back(std::make_pair(fP, freq));
        } 

        /**initialize optimization solver */
        OpSolver* mySolver = new OpSolver(blowUpRate_, inputDistri);
        uint32_t threshold = mySolver->GetOptimal();
        mySolver->PrintResult();
        delete mySolver;
        localCounter_ = 0;
        /**store the threshold in array */
        thresholdArray_.push_back(threshold);
    }

    /********************************
     * Second pass of this workload**
     ********************************/

    /**reset the file pointer at the begin of the file */
    fseek(fpIn, 0, SEEK_SET);

    globalKeyFreqTable_.clear();
    fprintf(stderr, "Start the second pass, total chunk: %lu, hashtable size: %lu," \
        "Threshold Array Size: %lu, %s:%d\n",
        globalCounter_, globalKeyFreqTable_.size(), thresholdArray_.size(),
        FILE_NAME, CURRENT_LIEN);
    
    /**simulate the data stream come from here
     * the second pass using in-memory hash
     */
    globalCounter_ = 0;
    localCounter_ = 0;
    size_t currentSegIndex = 0;

    while ((readFlag = fgets(readBuffer, sizeof(readBuffer), fpIn)) != NULL) {
        /**read chunk information into chunk buffer */

        item = strtok(readBuffer, ":\t\n");
        size_t index = 0;
        for (index = 0; (item != NULL) && (index < FP_SIZE); index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunkFp[FP_SIZE] = '\0';

        /**increment chunk size */
        uint64_t size = atol((const char*)item);

        /**update the state in hash table */
        GlobalUpdateState(chunkFp, FP_SIZE + 1, size);
        /**key generation*/
        globalCounter_++;
        localCounter_++;
        LocalKeyGen(chunkFp, FP_SIZE + 1, size, key, thresholdArray_[currentSegIndex]);
        if (localCounter_ == batchSize_) {
            fprintf(stderr, "Current segment: %lu, chunk number: %lu, threshold: %u \n",
                currentSegIndex, localCounter_, thresholdArray_[currentSegIndex]);
            currentSegIndex++;
            localCounter_ = 0;
        }

        /**encryption (simulation) */
        uint8_t cipher[FP_SIZE + sizeof(key) + 1];

        SimTECEncrypt(chunkFp, FP_SIZE, key, sizeof(key), cipher);

        /**count the encrypted chunk */
        CountChunk(cipher, FP_SIZE + sizeof(key) + 1, size, 1);
        /**print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE + sizeof(key), size, fpOut);
        
    }
    fprintf(stderr, "Current segment: %lu, chunk number: %lu, threshold: %u\n",
        currentSegIndex, localCounter_, thresholdArray_[currentSegIndex]);
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE + sizeof(key), 1);
}


/// \brief key generation process according to different threshold in a region
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
/// \param key - generated encryption key <return>
/// \param threshold - the threshold during this region
void LocalTECSim::LocalKeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
    uint64_t const chunkSize, uint8_t key[32], uint32_t threshold) {
    
    int state = 0;

    uint64_t frequency = 0;

    std::string chunkKey = std::string((const char*)chunkHash, chunkHashLen);

    if (SKETCH_ENABLE) {
        
        frequency = cmSketch_->Estimate(chunkHash, chunkHashLen);
        
        state = frequency / (threshold + 0.00000000001);

        if (enablePro) {
            state = randomNumGen_->ProRandomNumber(distriType_, state);
        }

    } else {
        auto findResult = globalKeyFreqTable_.find(chunkKey);

        if (findResult != globalKeyFreqTable_.end()) {
            /**this key exists*/
            frequency = findResult->second;
            state = frequency / (threshold + 0.00000000001);
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

    uint8_t keySeed[FP_SIZE + sizeof(state)];
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
void LocalTECSim::SimTECEncrypt(uint8_t* const msg, size_t const msgLen, uint8_t* const key,
    size_t const keyLen, uint8_t output[FP_SIZE + sizeof(int) + 1]) {
    
    uint8_t in[msgLen + keyLen];
    memset(in, 0 , msgLen + keyLen);
    memcpy(in, msg, msgLen);

    /**contentation the (message hash + ) */
    memcpy(in + msgLen, key, keyLen);

    memcpy(output, in, (msgLen + keyLen));

    output[FP_SIZE + sizeof(int)] = '\0';
}
