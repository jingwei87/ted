#include "solver.h"
#include <sys/time.h>
#include "sparsepp/spp.h"

int main(int argc, char* argv[]) {
    int n = 0;
    int m = 0;
    int totalChunk = 0; 
    double storageBlow;
    storageBlow = atof(argv[1]);
    vector<pair<string, int> > input;

    struct timeval stime, etime;
    
    /**start to read the file */
    char readBuffer[256];
    char* readFlag;
    char* item;
    unsigned char chunkFp[FP_SIZE+1];

    /**prepare file operation */
    FILE* fpIn = NULL;
    FILE* fpOut = NULL;
    FILE* output_p = NULL;
    FILE* output_c = NULL; 
    fpIn = fopen(argv[2], "r");
    fpOut = fopen("output", "w");
    output_p = fopen("output_p", "w");
    output_c = fopen("output_c", "w");


    while ((readFlag = fgets(readBuffer, 256, fpIn)) != NULL) {
        item = strtok(readBuffer, ":\t\n ");
        for (int index = 0; item != NULL && index < FP_SIZE; index++) {
            chunkFp[index] = strtol(item, NULL, 16);
			item = strtok(NULL, ":\t\n");
        }
        chunkFp[FP_SIZE] = '\0';
        std::string key = std::string((const char *)chunkFp, FP_SIZE +1);
        /* increment size */
		int frequency = atoi((const char*)item);
        //printf("frequency: %d\n", frequency);
        input.push_back(make_pair(key, frequency));
    }

    for (auto iter = input.begin(); iter != input.end(); iter++){
        n++;
        totalChunk += iter->second;
    }
    printf("n:%d\ntotal logicl chunk:%d\n", n, totalChunk);

    /**calculate the expected ciphertext chunk according to storage blowup rate*/
    m = n * (1 + storageBlow);
    printf("m: %d\n", m);

    OpSolver* solver = new OpSolver(m, input);
    
    /**start to solve the optimization */
    gettimeofday(&stime, NULL);
    solver->GetOptimal();
    gettimeofday(&etime, NULL);
    double usedTime = (double)((etime.tv_sec + etime.tv_usec / 1000000.0)) - (stime.tv_sec + stime.tv_usec / 1000000.0);
    printf("Total Time: %lf\n", usedTime);

    /**print result */
    solver->PrintResult(fpOut);
    solver->PrintDistri(output_p, output_c);

    int upLimit = 1006591;
    int threshold = 20;
    int result = 0;
    int currentState = 0;
    spp::sparse_hash_map<int, int> counterMap;
    for (int i = 1; i <= upLimit; i++) {
        result = i / (threshold + 0.00000000001);
        //result = i / (threshold);
        auto findResult = counterMap.find(result);
        if (findResult != counterMap.end()) {
            findResult->second ++;
        } else {
            counterMap.insert(std::make_pair(result,1));
        }
    }

    for(auto it = counterMap.begin(); it != counterMap.end(); it++) {
        if (it->second == 21){
            printf("Error: %d\n", it->first);
            currentState ++;
        }
    }
    printf("Counter: %d\n", currentState);


    /**clear up*/
    fclose(fpIn);
    fclose(fpOut);
    fclose(output_p);
    fclose(output_c);


    return 0;
}
