/// \file inituiSim.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of the Intuitive simulation
/// \version 0.1
/// \date 2019-08-19
///
/// \copyright Copyright (c) 2019
///

#ifndef __Intui_SIM_H__
#define __Intui_SIM_H__

#include "tecSim.h"

class IntuiSim : public TECSim {
    private:

        double boundRate_;

        /// \brief the maximum threshold
        ///
        uint32_t maxThreshold_;

        /// \brief current average 
        ///
        double currentAvg_;

        /// \brief Construct a new Intui Key Gen object
        ///
        /// \param chunkHash 
        /// \param chunkHashLen 
        /// \param chunkSize 
        /// \param key 
        void IntuiKeyGen(uint8_t* const chunkHash, size_t chunkHashLen, 
            uint64_t const chunkSize, uint8_t key[sizeof(int)]);

        uint32_t* thresholdArray_;

    public: 

        /// \brief Construct a new Intui Sim object
        ///
        IntuiSim() {
            fprintf(stderr, "Initialize Intuitive Simulator.\n");
            boundRate_ = 0;
            currentAvg_ = 0;
            thresholdArray_ = (uint32_t*)malloc(sizeof(int32_t) * SKETCH_WIDTH);
            memset(thresholdArray_, 0, sizeof(uint32_t) * SKETCH_WIDTH);
        }

        /// \brief Set the Bound Rate object
        ///
        /// \param boundRate - the bound rate 
        void SetBoundRate(double boundRate) {
            boundRate_ = boundRate;
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
          std::string const outputFileName); 

        ~IntuiSim() {
            fprintf(stderr, "Destory Intuitive Simulator.\n");
            free(thresholdArray_);
        }
};


#endif // !__Intui_SIM_H__
