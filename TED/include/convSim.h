/// \file convSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the convergent encryption simulator
/// \version 0.1
/// \date 2019-07-09
///
/// \copyright Copyright (c) 2019
///
#ifndef __CONV_SIM_H__
#define __CONV_SIM_H__

#include "sim.h"

class ConvSim : public Simulator {
    protected:

        /// \brief generate the encrypt key
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkSize - chunk size
        /// \param key - encryption key
        void KeyGen(uint8_t* const chunkHash, uint64_t const chunkSize, 
           uint8_t key[32]) {
           cryptoObj_->generateHash(chunkHash, FP_SIZE + 1, key);
        }

    public:

        /// \brief Construct a new Conv Sim object
        ///
        ConvSim() { fprintf(stderr, "Initialize Convergent Encryption Simulator.\n");};

        /// \brief Destroy the Conv Sim object
        ///
        ~ConvSim() {fprintf(stderr, "Start to destory Convergent Encryption Simulator.\n");}

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
           std::string const outputFileName);



};
#endif // 

