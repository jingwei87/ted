#include "../../include/intuiSim.h"



/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void IntuiSim::ProcessHashFile(std::string const inputFileName, 
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

        // CheckUniqueTable(chunkFp, FP_SIZE + 1);

        currentLogicalChunk_ ++;

        /**count the chunk information in global leveldb */
        CountChunk(chunkFp, FP_SIZE + 1, size, 0);

        /**update the state in in-memory hash-table or sketch*/
        TECUpdateState(chunkFp, FP_SIZE + 1, size);

        /**key generation */
        IntuiKeyGen(chunkFp, FP_SIZE + 1, size, key);

        /**encryption (simulation) */
        uint8_t cipher[FP_SIZE + sizeof(key) + 1];

        SimTECEncrypt(chunkFp, FP_SIZE, key, sizeof(key), cipher);

        /**count the encrypted chunk */
        CountChunk(cipher, FP_SIZE + sizeof(key) + 1, size, 1);

        /**print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE + sizeof(key), size, fpOut);

        

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
    PrintChunkFreq(outputFileName, FP_SIZE + sizeof(key), 1);
}


/// \brief Construct a new Intui Key Gen object
///
/// \param chunkHash 
/// \param chunkHashLen 
/// \param chunkSize 
/// \param key 
void IntuiSim::IntuiKeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
    uint64_t const chunkSize, uint8_t key[sizeof(int)]) {
    
    int state = 0;

    uint64_t frequency = 0;

    std::string chunkKey = std::string((const char*)chunkHash, chunkHashLen);

    currentAvg_ = static_cast<double>(currentLogicalChunk_ / currentUniqueChunk_);
    
    maxThreshold_ = currentAvg_ * boundRate_;

    if (SKETCH_ENABLE) {
    
        frequency = cmSketch_->Estimate(chunkHash, chunkHashLen);

        int pos = cmSketch_->ReturnFirstRowPos(chunkHash, chunkHashLen);

        uint32_t threshold = thresholdArray_[pos];

        if (frequency < currentAvg_) {
            state = frequency / (threshold + 0.00000000001);
        } else {

            if (threshold < maxThreshold_) {
                threshold++;
                thresholdArray_[pos] = threshold;
                state = frequency / (threshold + + 0.00000000001);
            } else {
                state = frequency / (maxThreshold_ + + 0.00000000001);
            }
        }

    } else {
        auto findResult = keyFreqTable_.find(chunkKey);

        if (findResult != keyFreqTable_.end()) {
            /**this key exists */
            frequency = findResult->second;
            
            int pos = cmSketch_->ReturnFirstRowPos(chunkHash, chunkHashLen);

            uint32_t threshold = thresholdArray_[pos];

            if (frequency < currentAvg_) {
                state = frequency / (threshold + 0.00000000001);
            } else {
                if (threshold < maxThreshold_) {
                    threshold++;
                    thresholdArray_[pos] = threshold;
                    state = frequency / (threshold + + 0.00000000001);
                } else {
                    state = frequency / (maxThreshold_ + + 0.00000000001);
                }
            }
        } else {
            /**the key does not exist */
            fprintf(stderr, "Error: the key does not exist. %s:%d\n",
                FILE_NAME, CURRENT_LIEN);
        }
    }
    memcpy(key, &state, sizeof(int));
}