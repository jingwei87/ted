/// \file tSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of threshold-based simulation 
/// \version 0.1
/// \date 2019-08-10
///
/// \copyright Copyright (c) 2019
///

#ifndef __T_SIM_H__
#define __T_SIM_H__

#include "tecSim.h"
#include "sparsepp/spp.h"

class TSim : public TECSim {
    private:

        /// \brief threshold key generation process
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        /// \param key - generated encryption key <return>
        void ThresholdKeyGen(uint8_t* const chunkHash, size_t chunkHashLen,
            uint64_t const chunkSize,uint8_t key[sizeof(int)]);

        /**define the threshold */
        uint32_t thresholdBase_;
        
    public:

        /// \brief Construct a new TSim object
        ///
        TSim() { fprintf(stderr, "Initialize Threshold-based Encryption Simulator.\n"); }

        /// \brief Destroy the TSim object
        ///
        ~TSim() { fprintf(stderr, "Destory Threshold-based Encryption Simulator.\n"); }

        /// \brief Set the Threshold object
        ///
        /// \param threshold - the input threshold
        inline void SetThresholdBase(uint32_t thresholdBase) {
            thresholdBase_ = thresholdBase;
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
            std::string const outputFileName);

};
#endif // !__T_SIM_H__