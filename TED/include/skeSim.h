/// \file skeSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of SKE simulator
/// \version 0.1
/// \date 2019-09-26
///
/// \copyright Copyright (c) 2019
///

#ifndef __SKE_SIM_H__
#define __SKE_SIM_H__

#include "sim.h"
#include <random>
#include <cstdlib>
#include <stdio.h>
#include <ctime>

class SKESim : public Simulator {
    private:
        /**encryption key for AES*/
        uint8_t* encryptKey_;

        /**random key seed */
        int keySeed_;

    public:
        /// \brief Construct a new SKESim object
        ///
        /// \param encryptKey - the encryption key
        SKESim(){
            fprintf(stderr, "Initialize SKE Encryption Simulator.\n");
            encryptKey_ = (uint8_t*) malloc(32 * sizeof(uint8_t));
            memset(encryptKey_, 0, 32 * sizeof(uint8_t));
            keySeed_ = 0;
        }

        /// \brief Generate random encryption key (SKE)
        ///
        void SKEKeyGen();

        /// \brief Destroy the SKESim object
        ///
        ~SKESim() {
            fprintf(stderr, "Destory SKE Simulator.\n");
            free(encryptKey_);
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name 
        /// \param outputFileName - the output file name 
        void ProcessHashFile(std::string const inputFileName,
            std::string const outputFileName);
};


#endif // _SKE_SIM_H__