/// \file statsRecord.h
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief define the object regarding to record the performance parameter
/// \version 0.1
/// \date 2019-06-19
///
/// \copyright Copyright (c) 2019
///

#ifndef __STATS_RECORD_H__
#define __STATS_RECORD_H__

#include <stdio.h>
#include <sys/time.h>
#include "define.h"

enum StatusType {
    RUN_TIME,
    HASH_TIME,
    ENCRYPT_TIME,
    SIMULATOR_TIME,
    /**for index */
    NUMLENGTH 
};


class StatsRecorder {
    
    public:
        /// \brief 
        ///
        /// \param startTime 
        /// \param resTime 
        /// \return ULL 
        static ULL TimeAddto(struct timeval &startTime, ULL &resTime);

        /// \brief Get the Instance object
        ///
        /// \return StatsRecorder* 
        static StatsRecorder* GetInstance();

        static void DestroyInstance();

        #define STAT_TIME_PROCESS(_FUNC_, _TYPE_) \
        do { \
            struct timeval startTime; \
            gettimeofday(&startTime, NULL); \
            _FUNC_; \
            StatsRecorder::GetInstance()->TimeProcess(_TYPE_, startTime); \
        } while(0);


        ULL TimeProcess(StatusType stat, struct timeval &startTime, size_t diff = 0,
            size_t count = 1, ULL valueSize = 0);


        void OpenStatistics(struct timeval &startTime);

        ULL inline GetTime(StatusType stat) {return time[stat];}

    private:

        StatsRecorder();
        ~StatsRecorder();

        static StatsRecorder *mInstance;
        
        bool statisticsOpen;

        ULL time[NUMLENGTH];
};


#endif // !__STATS_RECORD_H__

