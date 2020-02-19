/// \file proTecSim.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of probabilistic tec
/// \version 0.1
/// \date 2019-07-30
///
/// \copyright Copyright (c) 2019
///
#ifndef __PRO_TEC_SIM_H__
#define __PRO_TEC_SIM_H__

#include "tecSim.h"
#include "randomGen.h"

class ProTECSim : public TECSim {
    protected:

        /// \brief key generation process
        ///
        /// \param chunkHash - chunk hash
        /// \param chunkHashLen - the length of chunk hash
        /// \param chunkSize - chunk size
        /// \param key - generate
        void ProKeyGen(uint8_t* const chunkHash, size_t chunkHashLen,
            uint64_t const chunkSize, uint8_t key[sizeof(int)]);

        /**a random number generator */
        RandomGen* randomNumGen_;

        /**the type of distribution of random number */
        int distriType_;

    public:

        /// \brief Construct a new Pro TECSim object
        ///
        ProTECSim() { fprintf(stderr, "Initialize Probabilistic Tunable Encryption Simulator.\n");}

        /// \brief Destroy the ProTECSim object
        ///
        ~ProTECSim() { 
            delete randomNumGen_;
            fprintf(stderr, "Destory Tunable Encryption Simulator. \n");
        }

        /// \brief Set the Probabilistic number generator 
        ///
        inline void SetDistri(int type) {
            distriType_ = type;
            randomNumGen_ = new RandomGen();
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
            std::string const outputFileName);

};


#endif // !__PRO_TEC_SIM_H__
