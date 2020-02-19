/// \file convSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in convergent encryption simulator
/// \version 0.1
/// \date 2019-07-09
///
/// \copyright Copyright (c) 2019
///

#include "../../include/convSim.h"




/// \brief process an input hash file for encryption
///
/// \param inputFileName - the input file name
/// \param outputFileName - the output file name
void ConvSim::ProcessHashFile(std::string const inputFileName, 
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
        fprintf(stderr, "Open data file success\n");
    } else {
	    fprintf(stderr, "Open data file fails, %s:%d\n", FILE_NAME, CURRENT_LIEN);
    	exit(1);
    } 

    fpOut = fopen(outputFileName.c_str(), "w");

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

        /**count chunk frequency in original backup */
        CountChunk(chunkFp, FP_SIZE + 1, size, 0);

        /**key generation */
        uint8_t key[32];
        KeyGen(chunkFp, size, key);

        /**encryption */

        uint8_t ciphertext[FP_SIZE + 1];
        memset(ciphertext, 0, FP_SIZE + 1);
        uint8_t alignedCipher[16] = {0};
        uint8_t alignedChunkFp[16] = {0};
        memcpy(alignedChunkFp, chunkFp, FP_SIZE);
        cryptoObj_->encryptWithKey(alignedChunkFp, 16, key, alignedCipher);
        memcpy(ciphertext, alignedCipher, FP_SIZE);
        ciphertext[FP_SIZE] = '\0';

        uint64_t chunkSize = atol((const char*)item);
        /**count chunk frequency in encrypted backup */
        CountChunk(ciphertext, FP_SIZE + 1, chunkSize, 1);                

        /**print the message ciphertext */
        PrintCipher(chunkFp, FP_SIZE, ciphertext, FP_SIZE, chunkSize, fpOut);
    
    }
    fclose(fpIn);
    fclose(fpOut);

    /**print out the stat information */
    PrintBackupStat();

    /**print out the frequency information */
    PrintChunkFreq(outputFileName, FP_SIZE, 0);
    PrintChunkFreq(outputFileName, FP_SIZE, 1);
}
