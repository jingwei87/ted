#ifndef GENERALDEDUPSYSTEM_SIME_OP_SOLVER_HPP_
#define GENERALDEDUPSYSTEM_SIME_OP_SOLVER_HPP_
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

using namespace std;

class OpSolver {
public:
    OpSolver(int m, vector<pair<string, int>> inputDistribution);
    ~OpSolver();
    double GetOptimal();
    void PrintResult(FILE* fpOut);
    bool CheckConstrain(int startIndex);
    bool Compare(pair<string, int> a, pair<string, int> b);
    void PrintDistri(FILE* outputP, FILE* outputC);

private:
    int m_;
    int n_;
    unsigned int sum_;
    int currentIndex_;
    int remainSum_;
    double storageBlow_;
    double maxEntropy_;
    double originalEntropy_;

    vector<pair<string, int>> inputFeqDistr_;
    vector<double> outputFeqDistr_;
};

#endif // GENERALDEDUPSYSTEM_SIME_OP_SOLVER_HPP_
