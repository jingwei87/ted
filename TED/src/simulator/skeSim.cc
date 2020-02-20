/// \file skeSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in SKE simulator
/// \version 0.1
/// \date 2019-09-26
///
/// \copyright Copyright (c) 2019
///

#include "../../include/skeSim.h"


/// \brief Generate random encryption key (SKE)
///
void SKESim::SKEKeyGen() {
    keySeed_ = rand();
    cryptoObj_->generateHash((uint8_t*)&keySeed_, sizeof(keySeed_), encryptKey_);
}


/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name 
/// \param outputFileName - the output file name 
void SKESim::ProcessHashFile(std::string const inputFileName,
    std::string const outputFileName) {
    
    /**for random key generation */
    srand(time(NULL));
    
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

        /**encrypt the chunk with the unique key via AES-256*/
        SKEKeyGen();
        uint8_t cipher[FP_SIZE + sizeof(int)+ 1];
        memset(cipher, 0, FP_SIZE + sizeof(int) + 1); 

        /**padding with 0*/
        uint8_t alignedCipher[16] = {0};
        uint8_t alignedChunkFp[16] = {0};
        memcpy(alignedChunkFp, chunkFp, FP_SIZE + 1);

        cryptoObj_->encryptWithKey(alignedChunkFp, 16, encryptKey_, alignedCipher);

        memcpy(cipher, alignedCipher, FP_SIZE + 1);

        /**count the encrypted chunk */
        CountChunk(cipher, FP_SIZE + 1, size, 1);

        /**print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, cipher, FP_SIZE, size, fpOut);
    }
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE, 1);

}