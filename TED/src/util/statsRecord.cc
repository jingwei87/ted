/// \file statsRecord.cc
/// \author Zuoru YANG (zryang@cse.cuhk.edu.hk)
/// \brief implement the interface defined in StatsRecord
/// \version 0.1
/// \date 2019-06-19
///
/// \copyright Copyright (c) 2019
///

#include "../../include/statsRecord.h"
StatsRecorder *StatsRecorder::mInstance = NULL;


double inline subTime(struct timeval &stime, struct timeval &etime) {
    double usedTime = (double)((etime.tv_sec + etime.tv_usec / 1000000.0) - 
            (stime.tv_sec + stime.tv_usec / 1000000.0));
    return usedTime;
}



ULL inline timevalToMicros(struct timeval &res) {
    return res.tv_sec * S2US + res.tv_usec;
}

ULL StatsRecorder::TimeAddto(struct timeval &startTime, ULL &resTime) {
    struct timeval endTime, res;
    ULL diff;
    gettimeofday(&endTime, NULL);
    timersub(&endTime, &startTime, &res);
    diff = timevalToMicros(res);
    resTime += diff;
    return resTime;
}


StatsRecorder* StatsRecorder::GetInstance() {
    if (mInstance == NULL){
        mInstance = new StatsRecorder();
    }
    return mInstance;
}

StatsRecorder::StatsRecorder() {
    for (int i = 0; i < NUMLENGTH; i++) {
        time[i] = 0;
    }
    
    statisticsOpen = false;

}

ULL StatsRecorder::TimeProcess(StatusType stat, struct timeval &startTime, size_t diff,
        size_t count, ULL valueSize) {
    ULL ret = 0;
    if (!statisticsOpen) {
        return 0;
    }
    ret = TimeAddto(startTime, time[stat]);
    if (stat == StatusType::RUN_TIME) {
        //fprintf(stderr, "record the running time.\n");
    } 
    return ret;
}

void StatsRecorder::DestroyInstance(){
    if(mInstance != NULL){
        delete mInstance;
        mInstance = NULL;
    }
}


void StatsRecorder::OpenStatistics(struct timeval &startTime) {
    ULL diff = 0;
    statisticsOpen = true;
    TimeAddto(startTime, diff);
    fprintf(stderr, "Last Phase Duration: %llu us \n", diff);
}

StatsRecorder::~StatsRecorder() {
    fprintf(stdout, "-------------------Run Time--------------\n");
    fprintf(stdout, "Running time: %llu\n", time[RUN_TIME]);
}

