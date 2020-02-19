/// \file proTecSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface define in probabilistic TEC 
/// \version 0.1
/// \date 2019-07-30
///
/// \copyright Copyright (c) 2019
///

#include "../../include/proTecSim.h"


/// \brief key generation process
///
/// \param chunkHash - chunk hash
/// \param chunkHashLen - the length of chunk hash
/// \param chunkSize - chunk size
/// \param key - generate
void ProTECSim::ProKeyGen(uint8_t* const chunkHash, size_t chunkHashLen,
    uint64_t const chunkSize, uint8_t key[sizeof(int)]) {
    
    int state = 0; /**represent the result of (current frequency / Threshold) */

    int proState = 0; /**represent the result of probabilistic state */

    uint64_t frequency = 0;

    std::string chunkKey = std::string((const char*)chunkHash, chunkHashLen);

    if (SKETCH_ENABLE) {
        frequency = cmSketch_->Estimate(chunkHash, chunkHashLen);

        state = frequency / (threshold_ + 0.00000000001);

        /**generate the probabilistic state based on the random number generator */
        proState = randomNumGen_->ProRandomNumber(distriType_, state);
        
    } else {
        auto findResult = keyFreqTable_.find(chunkKey);

        if (findResult != keyFreqTable_.end()) {
            /**this key exits */
            frequency = findResult->second;

            state = frequency / (threshold_ + 0.00000000001);
            
            /**generate the probabilistic state based on the random number generator */
            proState = randomNumGen_->ProRandomNumber(distriType_, state);
        } else {
            fprintf(stderr, "Error: the key does not exist. %s:%d\n",
                FILE_NAME, CURRENT_LIEN);
        }
    }

    memcpy(key, &proState, sizeof(proState));
}


/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void ProTECSim::ProcessHashFile(std::string const inputFileName, 
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

        /**update the state in in-memory hashtable */
        TECUpdateState(chunkFp, FP_SIZE + 1, size);

        /**probabilistic key generation */
        ProKeyGen(chunkFp, FP_SIZE + 1, size, key);

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

    /**print out the state information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE + sizeof(key), 1);
}   