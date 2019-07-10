#include "solver.h"

double Log2(double number) {
    return log(number) / log(2);
}

OpSolver::OpSolver(int m, vector<pair<string, int> > inputDistribution) {
    m_ = m;
    n_ = inputDistribution.size();

    storageBlow_ = m_ / n_;

    inputFeqDistr_ = inputDistribution;
    maxEntropy_ = 0;
    originalEntropy_ = 0;
    int i;
    for (auto iter = inputDistribution.begin(); iter != inputDistribution.end(); iter++) {
        sum_ += iter->second;
    }

    /**Initialization */
    double average = static_cast<double>(sum_) / m_;
    if (sum_ % m_ != 0) {
        printf("the output maybe double\n");
       
    }
    printf("the initialized average: %lf\n", average);

    for (int i = 0; i < m; i++) {
        outputFeqDistr_.push_back(average);
    }

    /**Calculate the basic entropy */
    remainSum_ = sum_;
    double freq = 1.00 / sum_;
    for (i = 0; i < sum_; i++) {
        maxEntropy_ -= freq * Log2(freq);
    }
    for (auto iter = inputFeqDistr_.begin(); iter != inputFeqDistr_.end(); iter++) {
        freq = static_cast<double> (iter->second) / sum_; 
        originalEntropy_ -= freq * Log2(freq); 
    }
    printf("The maximum entropy of this workload: %f\n", maxEntropy_);
    printf("The original entropy of this workload: %f\n", originalEntropy_);
}

void OpSolver::PrintResult(FILE* fpOut) {
    printf("Total Plaintext Logical Chunk Amount: %d\n", sum_);
    double csum = 0;
    for (auto iter = outputFeqDistr_.begin(); iter != outputFeqDistr_.end(); iter++) {
        csum += *iter;
    //    printf("%lf, ", *iter);
    }
    printf("\n");
    printf("Total Ciphertext Logical Chunk Amount: %lf\n", csum);
    double originlRatio = static_cast<double> (sum_ - n_) / sum_;
    double cipherRatio = static_cast<double> (sum_ - m_) / sum_;
    printf("Original Storage Saving Rate: %f\n", originlRatio);
    printf("Cipher Storage Saving Rate: %f\n", cipherRatio);
    printf("Storage Saving Loss Rate: %f\n", (originlRatio - cipherRatio) / originlRatio);

    double cipherEntropy = 0;
    double freq = 0;
    for (auto iter = outputFeqDistr_.begin(); iter != outputFeqDistr_.end(); iter++) {
        freq = static_cast<double> (*iter) / sum_;
        cipherEntropy -= freq * Log2(freq);
    }
    printf("Cipher Entropy: %f\n", cipherEntropy);
    printf("Entropy Gain: %f\n", ( cipherEntropy - originalEntropy_) / (maxEntropy_ - originalEntropy_));

    for (int i = 0; i < m_; i++) {
        if (i < n_){
            fprintf(fpOut, "%d\t\t%f\n", inputFeqDistr_[i].second, outputFeqDistr_[i]);
        } else {
            fprintf(fpOut, "\t\t%f\n", outputFeqDistr_[i]);
        }
    }

}


void OpSolver::PrintDistri(FILE* outputP, FILE* outputC) {
    for (int i = 0; i < n_; i++) {
        fprintf(outputP, "%d\n", inputFeqDistr_[i].second);
    }
    for (int i = 0; i < m_; i++) {
        fprintf(outputC, "%f\n", outputFeqDistr_[i]);
    }
}

void OpSolver::GetOptimal() {
    sort(inputFeqDistr_.begin(), inputFeqDistr_.end(), [=](pair<string, int> a, pair<string, int> b)
    { return a.second < b.second;});

    if (DEBUG) {
        for (auto iter = inputFeqDistr_.begin(); iter != inputFeqDistr_.end(); iter++) {
            printf("%d, ", iter->second);
        }
        printf("\n");
    }
    int finishItem = 0;
    double newAverage = 0;
    int startIndex = 0;
    while (1) {
        if (CheckConstrain(startIndex)) {
            printf("newAverage: %f\n", newAverage);
            printf("currentIndex:%d, Value: %d\n", currentIndex_, 
                inputFeqDistr_[currentIndex_].second);
            break;
        } else {
            outputFeqDistr_[currentIndex_] = inputFeqDistr_[currentIndex_].second;
            finishItem ++;
            remainSum_ -= outputFeqDistr_[currentIndex_];
            newAverage = (double)remainSum_ / (double)(m_ - finishItem);
            //for (int i = currentIndex_+1; i < m_; i++) {
            //}
            startIndex = currentIndex_ + 1;
            outputFeqDistr_[startIndex] = newAverage;
            //printf("startIndex: %d, newAverage: %f\n",startIndex, newAverage);
        }
        if (DEBUG) {
            for (auto iter = outputFeqDistr_.begin(); iter != outputFeqDistr_.end(); iter++) {
                printf("%f, ", *iter);
            }
            printf("\n");
            printf("Iteration: %d, remainSum_: %d, newAverage_: %lf\n", finishItem, remainSum_, newAverage);        
        }
        //printf("Iteration: %d, remainSum_: %d, newAverage_: %lf\n", finishItem, remainSum_, newAverage);
        //PrintResult();
    }
    for (int i = startIndex + 1; i < m_; i++) {
        outputFeqDistr_[i] = newAverage;
    }
}

bool OpSolver::CheckConstrain(int startIndex) {
    int flag = 1;
    int counter = startIndex;
    while (counter < n_) {
        if (inputFeqDistr_[counter].second < outputFeqDistr_[counter]){
            flag = 0;
            /**store the current counter*/
            currentIndex_ = counter;
            break;    
        }
        counter++;
    }

    if (flag) {
        return true;
    } else {
        return false;
    }
}



