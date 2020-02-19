/// \file globalTecSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in global tec simulator
/// \version 0.1
/// \date 2019-10-09
///
/// \copyright Copyright (c) 2019
///

#include "../../include/globalTecSim.h"

long inline calDiff(struct timeval &timestart, struct timeval &timeend) {
    long diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    return diff;
}

/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the out file name
void GlobalTECSim::ProcessHashFile(std::string const inputFileName,
    std::string const outputFileName){
    
    struct timeval stime, etime;

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


    /****************first pass *************
    * for calculation the optimization problem
    * **************************************
    */

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

        /**record the state in hashtable or sketch */
        GlobalUpdateState(chunkFp, FP_SIZE + 1, size);
    }

    /**start to solve the optimization problem */
    fprintf(stderr, "Start to solve the optimization problem.\n");
    vector<pair<string, uint64_t> > inputDistri;

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
    threshold_ = mySolver->GetOptimal();
    gettimeofday(&etime, NULL);
    totalTime_ += calDiff(stime, etime);
    mySolver->PrintResult();
    delete mySolver;

    /**start to clean the data structure */
    fprintf(stderr, "start to clean up the sketch.\n");
    if (SKETCH_ENABLE){
        cmSketch_->ClearUp();
    } else {
        globalKeyFreqTable_.clear();
    }
    
    /****************Second pass *************
    * for calculation the optimization problem
    * **************************************
    */

    fprintf(stderr, "start the second pass of the workload.\n");
    fseek(fpIn, 0, SEEK_SET);

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

        /**key generateion */
        KeyGen(chunkFp, FP_SIZE + 1, size, key);

        /**encryption (simulation) */
        uint8_t cipher[FP_SIZE + sizeof(key) + 1];

        SimTECEncrypt(chunkFp, FP_SIZE, key, sizeof(key), cipher);

        /**count the encrypted chunk */
        CountChunk(cipher, FP_SIZE + sizeof(key) + 1, size, 1);

        /**print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE + sizeof(key), size, fpOut);
    }
    
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE + sizeof(key), 1);
}

void GlobalTECSim::GlobalUpdateState(uint8_t* const chunkHash,
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

/// \brief key generation process
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
/// \param key - generated encryption key <return>
void GlobalTECSim::KeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
    uint64_t const chunkSize, uint8_t key[sizeof(int)]) {
    
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
        auto findResult = globalKeyFreqTable_.find(chunkKey);

        if (findResult != globalKeyFreqTable_.end()) {
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
    memcpy(key, &state, sizeof(int));
}


/// \brief simulate the encryption process: directly append the (frequency / T) to the 
/// end of hash
///
/// \param msg - the original input message
/// \param msgLen - the length of message
/// \param key - the encryption key 
/// \param keyLen - the length of the encrytion key
/// \param output 
void GlobalTECSim::SimTECEncrypt(uint8_t* const msg, size_t const msgLen, uint8_t* const key,
    size_t const keyLen, uint8_t output[FP_SIZE + sizeof(int) + 1]) {
    
    uint8_t in[msgLen + keyLen];
    memset(in, 0 , msgLen + keyLen);
    memcpy(in, msg, msgLen);

    /**contentation the (message hash + ) */
    memcpy(in + msgLen, key, keyLen);

    memcpy(output, in, (msgLen + keyLen));

    output[FP_SIZE + sizeof(int)] = '\0';
}