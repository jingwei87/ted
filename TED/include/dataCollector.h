/// \file dataCollector.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the interface of data collector
/// \version 0.1
/// \date 2019-08-21
///
/// \copyright Copyright (c) 2019
///

#ifndef __DATA_COLLECTOR_H__
#define __DATA_COLLECTOR_H__

#include "sim.h"
#define MLE 1
#define MIN_HASH 2
#define TEC 3


class DataCollector : public Simulator {
    private:
        /**the length of fingerprint */
        size_t fpLen_ = 0;

    public:

        /// \brief Construct a new Data Collector object
        ///
        /// \param type - the type of encryption
        DataCollector(uint32_t type) {
            if (type == MLE) {
                fpLen_ = FP_SIZE;
            } else if (type == MIN_HASH) {
                fpLen_ = FP_SIZE + FP_SIZE + 1;
            } else if (type == TEC) {
                fpLen_ = FP_SIZE + sizeof(uint32_t);
            }
        }

        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessHashFile(std::string const inputFileName, 
            std::string const outputFileName); 
        
        /// \brief process an input hash file for encryption
        ///
        /// \param inputFileName - the input file name
        /// \param outputFileName - the output file name
        void ProcessCipherHashFile(std::string const inputFileName, 
            std::string const outputFileName); 

        ~DataCollector() {
            fprintf(stderr, "Destory the data collector\n");
        }
        
};

#endif // !__DATA_COLLECTOR_H__