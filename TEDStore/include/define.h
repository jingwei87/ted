/**
 * @file define.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief include the necessary header 
 * @version 0.1
 * @date 2020-09-09
 * 
 * @copyright Copyright (c) 2020
 * 
 */
#ifndef CHUNKING_LIB_DEFINE
#define CHUNKING_LIB_DEFINE

#include <iostream>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <stdint.h>
#include <fstream>
#include <cstring>
#include <chrono>
#include <unistd.h>
#include <vector>
#include <math.h>
#include <algorithm>
#include <unistd.h>
#include <memory>

namespace tool {
    double GetTimeDiff(struct timeval startTime, struct timeval endTime);
    uint32_t CompareLimit(uint32_t input, uint32_t lower, uint32_t upper);
    uint32_t DivCeil(uint32_t a, uint32_t b);  
}
#endif 