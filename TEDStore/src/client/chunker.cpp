#include "chunker.hpp"
#include "sys/time.h"
extern Configure config;

struct timeval timestartChunker;
struct timeval timeendChunker;
struct timeval timestartChunker_VarSizeInsert;
struct timeval timeendChunker_VarSizeInsert;
struct timeval timestartChunker_VarSizeHash;
struct timeval timeendChunker_VarSizeHash;

uint32_t DivCeil(uint32_t a, uint32_t b) {
    uint32_t tmp = a / b;
    if (a % b == 0) {
        return tmp;
    } else {
        return (tmp + 1);
    }
}

uint32_t CompareLimit(uint32_t input, uint32_t lower, uint32_t upper) {
    if (input <= lower) {
        return lower; 
    } else if (input >= upper) {
        return upper;
    } else {
        return input;
    }
}


Chunker::Chunker(std::string path, keyClient* keyClientObjTemp)
{
    loadChunkFile(path);
    ChunkerInit(path);
    cryptoObj = new CryptoPrimitive();
    keyClientObj = keyClientObjTemp;
}

Chunker::~Chunker()
{
    if (powerLUT != NULL) {
        delete powerLUT;
    }
    if (removeLUT != NULL) {
        delete removeLUT;
    }
    if (waitingForChunkingBuffer != NULL) {
        delete waitingForChunkingBuffer;
    }
    if (chunkBuffer != NULL) {
        delete chunkBuffer;
    }
    if (cryptoObj != NULL) {
        delete cryptoObj;
    }
    if (chunkingFile.is_open()) {
        chunkingFile.close();
    }
}

std::ifstream& Chunker::getChunkingFile()
{
    if (!chunkingFile.is_open()) {
        cerr << "Chunker : chunking file open failed" << endl;
        exit(1);
    }
    return chunkingFile;
}

void Chunker::loadChunkFile(std::string path)
{
    if (chunkingFile.is_open()) {
        chunkingFile.close();
    }
    chunkingFile.open(path, std::ios::binary);
    if (!chunkingFile.is_open()) {
        cerr << "Chunker : open file: " << path << "error, client exit now" << endl;
        exit(1);
    }
}

void Chunker::ChunkerInit(string path)
{
    u_char filePathHash[FILE_NAME_HASH_SIZE];
    cryptoObj->generateHash((u_char*)&path[0], path.length(), filePathHash);
    memcpy(fileRecipe.recipe.fileRecipeHead.fileNameHash, filePathHash, FILE_NAME_HASH_SIZE);
    memcpy(fileRecipe.recipe.keyRecipeHead.fileNameHash, filePathHash, FILE_NAME_HASH_SIZE);

    ChunkerType = (int)config.getChunkingType();

    if (ChunkerType == CHUNKER_VAR_SIZE_TYPE) {
        int numOfMaskBits;
        avgChunkSize = (int)config.getAverageChunkSize();
        minChunkSize = (int)config.getMinChunkSize();
        maxChunkSize = (int)config.getMaxChunkSize();
        slidingWinSize = (int)config.getSlidingWinSize();
        ReadSize = config.getReadSize();
        ReadSize = ReadSize * 1024 * 1024;
        waitingForChunkingBuffer = new u_char[ReadSize];
        chunkBuffer = new u_char[maxChunkSize];

        if (waitingForChunkingBuffer == NULL || chunkBuffer == NULL) {
            cerr << "Chunker : Memory malloc error" << endl;
            exit(1);
        }
        if (minChunkSize >= avgChunkSize) {
            cerr << "Chunker : minChunkSize should be smaller than avgChunkSize!" << endl;
            exit(1);
        }
        if (maxChunkSize <= avgChunkSize) {
            cerr << "Chunker : maxChunkSize should be larger than avgChunkSize!" << endl;
            exit(1);
        }

        /*initialize the base and modulus for calculating the fingerprint of a window*/
        /*these two values were employed in open-vcdiff: "http://code.google.com/p/open-vcdiff/"*/
        polyBase = 257; /*a prime larger than 255, the max value of "unsigned char"*/
        polyMOD = (1 << 23) - 1; /*polyMOD - 1 = 0x7fffff: use the last 23 bits of a polynomial as its hash*/
        /*initialize the lookup table for accelerating the power calculation in rolling hash*/
        powerLUT = (uint32_t*)malloc(sizeof(uint32_t) * slidingWinSize);
        /*powerLUT[i] = power(polyBase, i) mod polyMOD*/
        powerLUT[0] = 1;
        for (int i = 1; i < slidingWinSize; i++) {
            /*powerLUT[i] = (powerLUT[i-1] * polyBase) mod polyMOD*/
            powerLUT[i] = (powerLUT[i - 1] * polyBase) & polyMOD;
        }
        /*initialize the lookup table for accelerating the byte remove in rolling hash*/
        removeLUT = (uint32_t*)malloc(sizeof(uint32_t) * 256); /*256 for unsigned char*/
        for (int i = 0; i < 256; i++) {
            /*removeLUT[i] = (- i * powerLUT[_slidingWinSize-1]) mod polyMOD*/
            removeLUT[i] = (i * powerLUT[slidingWinSize - 1]) & polyMOD;
            if (removeLUT[i] != 0) {

                removeLUT[i] = (polyMOD - removeLUT[i] + 1) & polyMOD;
            }
            /*note: % is a remainder (rather than modulus) operator*/
            /*      if a < 0,  -polyMOD < a % polyMOD <= 0       */
        }

        /*initialize the anchorMask for depolytermining an anchor*/
        /*note: power(2, numOfanchorMaskBits) = avgChunkSize*/
        numOfMaskBits = 1;
        while ((avgChunkSize >> numOfMaskBits) != 1) {

            numOfMaskBits++;
        }
        anchorMask = (1 << numOfMaskBits) - 1;
        /*initialize the value for depolytermining an anchor*/
        anchorValue = 0;
    } else if (ChunkerType == CHUNKER_FIX_SIZE_TYPE) {

        avgChunkSize = (int)config.getAverageChunkSize();
        minChunkSize = (int)config.getMinChunkSize();
        maxChunkSize = (int)config.getMaxChunkSize();
        ReadSize = config.getReadSize();
        ReadSize = ReadSize * 1024 * 1024;
        waitingForChunkingBuffer = new u_char[ReadSize];
        chunkBuffer = new u_char[avgChunkSize];

        if (waitingForChunkingBuffer == NULL || chunkBuffer == NULL) {
            cerr << "Chunker : Memory Error" << endl;
            exit(1);
        }
        if (minChunkSize != avgChunkSize || maxChunkSize != avgChunkSize) {
            cerr << "Chunker : Error: minChunkSize and maxChunkSize should be same in fixed size mode!" << endl;
            exit(1);
        }
        if (ReadSize % avgChunkSize != 0) {
            cerr << "Chunker : Setting fixed size chunking error : ReadSize not compat with average chunk size" << endl;
        }

    } else if (ChunkerType == CHUNKER_FAST_CDC) {

        avgChunkSize = (int)config.getAverageChunkSize();
        minChunkSize = (int)config.getMinChunkSize();
        maxChunkSize = (int)config.getMaxChunkSize();
        ReadSize = config.getReadSize();
        ReadSize = ReadSize * 1024 * 1024;
        waitingForChunkingBuffer = new u_char[ReadSize];
        chunkBuffer = new u_char[maxChunkSize];

        if (waitingForChunkingBuffer == NULL || chunkBuffer == NULL) {
            cerr << "Chunker : Memory malloc error" << endl;
            exit(1);
        }
        if (minChunkSize >= avgChunkSize) {
            cerr << "Chunker : minChunkSize should be smaller than avgChunkSize!" << endl;
            exit(1);
        }
        if (maxChunkSize <= avgChunkSize) {
            cerr << "Chunker : maxChunkSize should be larger than avgChunkSize!" << endl;
            exit(1);
        }

        normalSize_ = calNormalSize(minChunkSize, avgChunkSize, maxChunkSize);
        uint32_t bits = (uint32_t) round(log2(static_cast<double>(avgChunkSize))); 
        maskS_ = generateFastCDCMask(bits + 1);
        maskL_ = generateFastCDCMask(bits - 1);

    } else if (ChunkerType == CHUNKER_FIX_SIZE_TYPE) {

        avgChunkSize = (int)config.getAverageChunkSize();
        minChunkSize = (int)config.getMinChunkSize();
        maxChunkSize = (int)config.getMaxChunkSize();
        ReadSize = config.getReadSize();
        ReadSize = ReadSize * 1024 * 1024;
        waitingForChunkingBuffer = new u_char[ReadSize];
        chunkBuffer = new u_char[avgChunkSize];

        if (waitingForChunkingBuffer == NULL || chunkBuffer == NULL) {
            cerr << "Chunker : Memory Error" << endl;
            exit(1);
        }
        if (minChunkSize != avgChunkSize || maxChunkSize != avgChunkSize) {
            cerr << "Chunker : Error: minChunkSize and maxChunkSize should be same in fixed size mode!" << endl;
            exit(1);
        }
        if (ReadSize % avgChunkSize != 0) {
            cerr << "Chunker : Setting fixed size chunking error : ReadSize not compat with average chunk size" << endl;
        }
    } else if (ChunkerType == CHUNKER_TRACE_DRIVEN_TYPE_FSL) {
        maxChunkSize = (int)config.getMaxChunkSize();
        chunkBuffer = new u_char[maxChunkSize + 6];
    } else if (ChunkerType == CHUNKER_TRACE_DRIVEN_TYPE_UBC) {
        maxChunkSize = (int)config.getMaxChunkSize();
        chunkBuffer = new u_char[maxChunkSize + 5];
    } else {
        cerr << "Chunker : Error chunker type.\n";
        exit(1);
    }
}

bool Chunker::chunking()
{
    /*fixed-size Chunker*/
    if (ChunkerType == CHUNKER_FIX_SIZE_TYPE) {
        fixSizeChunking();
    }
    /*variable-size Chunker*/
    if (ChunkerType == CHUNKER_VAR_SIZE_TYPE) {
        varSizeChunking();
    }

    if (ChunkerType == CHUNKER_TRACE_DRIVEN_TYPE_FSL) {
        traceDrivenChunkingFSL();
    }

    if (ChunkerType == CHUNKER_TRACE_DRIVEN_TYPE_UBC) {
        traceDrivenChunkingUBC();
    }

    if (ChunkerType == CHUNKER_FAST_CDC) {
        fastCDC();
    }

    return true;
}

void Chunker::fixSizeChunking()
{
    double chunkTime = 0;
    double hashTime = 0;
    long diff;
    double second;
    std::ifstream& fin = getChunkingFile();
    uint64_t chunkIDCounter = 0;
    memset(chunkBuffer, 0, sizeof(char) * avgChunkSize);
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
    /*start chunking*/
    while (true) {
        memset((char*)waitingForChunkingBuffer, 0, sizeof(unsigned char) * ReadSize);
        fin.read((char*)waitingForChunkingBuffer, sizeof(char) * ReadSize);
        uint64_t totalReadSize = fin.gcount();
        fileSize += totalReadSize;
        uint64_t chunkedSize = 0;
        if (totalReadSize == ReadSize) {
            while (chunkedSize < totalReadSize) {
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunker, NULL);
#endif
                memset(chunkBuffer, 0, sizeof(char) * avgChunkSize);
                memcpy(chunkBuffer, waitingForChunkingBuffer + chunkedSize, avgChunkSize);
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunker, NULL);
                diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
                second = diff / 1000000.0;
                chunkTime += second;
#endif
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunker, NULL);
#endif
                if (!cryptoObj->generateHash(chunkBuffer, avgChunkSize, hash)) {
                    cerr << "Chunker : fixed size chunking: compute hash error" << endl;
                }
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunker, NULL);
                diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
                second = diff / 1000000.0;
                hashTime += second;
#endif
                Data_t tempChunk;
                tempChunk.chunk.ID = chunkIDCounter;
                tempChunk.chunk.logicDataSize = avgChunkSize;
                memcpy(tempChunk.chunk.logicData, chunkBuffer, avgChunkSize);
                memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                tempChunk.dataType = DATA_TYPE_CHUNK;

                insertMQToKeyClient(tempChunk);
                chunkIDCounter++;
                chunkedSize += avgChunkSize;
            }
        } else {
            uint64_t retSize = 0;
            while (chunkedSize < totalReadSize) {
                memset(chunkBuffer, 0, sizeof(char) * avgChunkSize);
                Data_t tempChunk;
                if (retSize > avgChunkSize) {
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartChunker, NULL);
#endif
                    memcpy(chunkBuffer, waitingForChunkingBuffer + chunkedSize, avgChunkSize);
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendChunker, NULL);
                    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
                    second = diff / 1000000.0;
                    chunkTime += second;
#endif
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartChunker, NULL);
#endif
                    if (!cryptoObj->generateHash(chunkBuffer, avgChunkSize, hash)) {
                        cerr << "Chunker : fixed size chunking: compute hash error" << endl;
                    }
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendChunker, NULL);
                    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
                    second = diff / 1000000.0;
                    hashTime += second;
#endif
                    tempChunk.chunk.ID = chunkIDCounter;
                    tempChunk.chunk.logicDataSize = avgChunkSize;
                    memcpy(tempChunk.chunk.logicData, chunkBuffer, avgChunkSize);
                    memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                } else {
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartChunker, NULL);
#endif
                    memcpy(chunkBuffer, waitingForChunkingBuffer + chunkedSize, retSize);
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendChunker, NULL);
                    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
                    second = diff / 1000000.0;
                    chunkTime += second;
#endif
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timestartChunker, NULL);
#endif
                    if (!cryptoObj->generateHash(chunkBuffer, retSize, hash)) {
                        cerr << "Chunker : fixed size chunking: compute hash error" << endl;
                    }
#if SYSTEM_BREAK_DOWN == 1
                    gettimeofday(&timeendChunker, NULL);
                    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
                    second = diff / 1000000.0;
                    hashTime += second;
#endif
                    tempChunk.chunk.ID = chunkIDCounter;
                    tempChunk.chunk.logicDataSize = retSize;
                    memcpy(tempChunk.chunk.logicData, chunkBuffer, retSize);
                    memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                }
                retSize = totalReadSize - chunkedSize;
                tempChunk.dataType = DATA_TYPE_CHUNK;
                insertMQToKeyClient(tempChunk);
                chunkIDCounter++;
                chunkedSize += avgChunkSize;
            }
        }
        if (fin.eof()) {
            break;
        }
    }
    fileRecipe.recipe.fileRecipeHead.totalChunkNumber = chunkIDCounter;
    fileRecipe.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCounter;
    fileRecipe.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe.recipe.keyRecipeHead.fileSize = fileRecipe.recipe.fileRecipeHead.fileSize;
    fileRecipe.dataType = DATA_TYPE_RECIPE;
    insertMQToKeyClient(fileRecipe);
    if (setJobDoneFlag() == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
    cout << "Chunker : Fixed chunking over:\nTotal file size = " << fileRecipe.recipe.fileRecipeHead.fileSize << "; Total chunk number = " << fileRecipe.recipe.fileRecipeHead.totalChunkNumber << endl;
#if SYSTEM_BREAK_DOWN == 1
    cout << "Chunker : total chunking time = " << chunkTime << " s" << endl;
    cout << "Chunker : total hashing time = " << hashTime << " s" << endl;
#endif
}

void Chunker::traceDrivenChunkingFSL()
{
    double chunkTime = 0;
    double hashTime = 0;
    long diff;
    double second;
    std::ifstream& fin = getChunkingFile();
    uint64_t chunkIDCounter = 0;
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
    char readLineBuffer[256];
    string readLineStr;
    /*start chunking*/
    getline(fin, readLineStr);
    while (true) {
        getline(fin, readLineStr);
        if (fin.eof()) {
            break;
        }
        memset(readLineBuffer, 0, 256);
        memcpy(readLineBuffer, (char*)readLineStr.c_str(), readLineStr.length());
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker, NULL);
#endif
        u_char chunkFp[7];
        memset(chunkFp, 0, 7);
        char* item;
        item = strtok(readLineBuffer, ":\t\n ");
        for (int index = 0; item != NULL && index < 6; index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunkFp[6] = '\0';
        auto size = atoi(item);
        int copySize = 0;
        memset(chunkBuffer, 0, sizeof(char) * maxChunkSize + 6);
        if (size > maxChunkSize) {
            continue;
        }
        while (copySize < size) {
            memcpy(chunkBuffer + copySize, chunkFp, 6);
            copySize += 6;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker, NULL);
        diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
        second = diff / 1000000.0;
        chunkTime += second;
#endif
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker, NULL);
#endif
        if (!cryptoObj->generateHash(chunkBuffer, size, hash)) {
            cerr << "Chunker : trace driven chunking: compute hash error" << endl;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker, NULL);
        diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
        second = diff / 1000000.0;
        hashTime += second;
#endif
        Data_t tempChunk;
        tempChunk.chunk.ID = chunkIDCounter;
        tempChunk.chunk.logicDataSize = size;
        memcpy(tempChunk.chunk.logicData, chunkBuffer, size);
        memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
        tempChunk.dataType = DATA_TYPE_CHUNK;

        insertMQToKeyClient(tempChunk);
        chunkIDCounter++;
        fileSize += size;
    }
    fileRecipe.recipe.fileRecipeHead.totalChunkNumber = chunkIDCounter;
    fileRecipe.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCounter;
    fileRecipe.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe.recipe.keyRecipeHead.fileSize = fileRecipe.recipe.fileRecipeHead.fileSize;
    fileRecipe.dataType = DATA_TYPE_RECIPE;
    insertMQToKeyClient(fileRecipe);
    if (setJobDoneFlag() == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
    cout << "Chunker : trace gen over:\nTotal file size = " << fileRecipe.recipe.fileRecipeHead.fileSize << "; Total chunk number = " << fileRecipe.recipe.fileRecipeHead.totalChunkNumber << endl;
#if SYSTEM_BREAK_DOWN == 1
    cout << "Chunker : total chunking time = " << chunkTime << " s" << endl;
    cout << "Chunker : total hashing time = " << hashTime << " s" << endl;
#endif
}

void Chunker::traceDrivenChunkingUBC()
{
    double chunkTime = 0;
    double hashTime = 0;
    long diff;
    double second;
    std::ifstream& fin = getChunkingFile();
    uint64_t chunkIDCounter = 0;
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
    char readLineBuffer[256];
    string readLineStr;
    /*start chunking*/
    getline(fin, readLineStr);
    while (true) {
        getline(fin, readLineStr);
        if (fin.eof()) {
            break;
        }
        memset(readLineBuffer, 0, 256);
        memcpy(readLineBuffer, (char*)readLineStr.c_str(), readLineStr.length());

#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker, NULL);
#endif
        u_char chunkFp[6];
        memset(chunkFp, 0, 6);
        char* item;
        item = strtok(readLineBuffer, ":\t\n ");
        for (int index = 0; item != NULL && index < 5; index++) {
            chunkFp[index] = strtol(item, NULL, 16);
            item = strtok(NULL, ":\t\n");
        }
        chunkFp[5] = '\0';
        auto size = atoi(item);
        int copySize = 0;
        memset(chunkBuffer, 0, sizeof(char) * maxChunkSize + 5);
        if (size > maxChunkSize) {
            continue;
        }
        while (copySize < size) {
            memcpy(chunkBuffer + copySize, chunkFp, 5);
            copySize += 5;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker, NULL);
        diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
        second = diff / 1000000.0;
        chunkTime += second;
#endif
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker, NULL);
#endif
        if (!cryptoObj->generateHash(chunkBuffer, size, hash)) {
            cerr << "Chunker : trace driven chunking: compute hash error" << endl;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker, NULL);
        diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
        second = diff / 1000000.0;
        hashTime += second;
#endif
        Data_t tempChunk;
        tempChunk.chunk.ID = chunkIDCounter;
        tempChunk.chunk.logicDataSize = size;
        memcpy(tempChunk.chunk.logicData, chunkBuffer, size);
        memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
        tempChunk.dataType = DATA_TYPE_CHUNK;

        insertMQToKeyClient(tempChunk);
        chunkIDCounter++;
        fileSize += size;
    }
    fileRecipe.recipe.fileRecipeHead.totalChunkNumber = chunkIDCounter;
    fileRecipe.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCounter;
    fileRecipe.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe.recipe.keyRecipeHead.fileSize = fileRecipe.recipe.fileRecipeHead.fileSize;
    fileRecipe.dataType = DATA_TYPE_RECIPE;
    insertMQToKeyClient(fileRecipe);
    if (setJobDoneFlag() == false) {
        cerr << "Chunker : set chunking done flag error" << endl;
    }
    cout << "Chunker : trace gen over:\nTotal file size = " << fileRecipe.recipe.fileRecipeHead.fileSize << "; Total chunk number = " << fileRecipe.recipe.fileRecipeHead.totalChunkNumber << endl;
#if SYSTEM_BREAK_DOWN == 1
    cout << "Chunker : total chunking time = " << chunkTime << " s" << endl;
    cout << "Chunker : total hashing time = " << hashTime << " s" << endl;
#endif
}

void Chunker::varSizeChunking()
{
    double insertTime = 0;
    double hashTime = 0;
    long diff;
    double second;
    uint16_t winFp;
    uint64_t chunkBufferCnt = 0, chunkIDCnt = 0;
    ifstream& fin = getChunkingFile();
    uint64_t fileSize = 0;
    u_char hash[CHUNK_HASH_SIZE];
/*start chunking*/
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartChunker, NULL);
#endif
    while (true) {
        memset((char*)waitingForChunkingBuffer, 0, sizeof(unsigned char) * ReadSize);
        fin.read((char*)waitingForChunkingBuffer, sizeof(unsigned char) * ReadSize);
        int len = fin.gcount();
        fileSize += len;
        for (int i = 0; i < len; i++) {

            chunkBuffer[chunkBufferCnt] = waitingForChunkingBuffer[i];

            /*full fill sliding window*/
            if (chunkBufferCnt < slidingWinSize) {
                winFp = winFp + (chunkBuffer[chunkBufferCnt] * powerLUT[slidingWinSize - chunkBufferCnt - 1]) & polyMOD; //Refer to doc/Chunking.md hash function:RabinChunker
                chunkBufferCnt++;
                continue;
            }
            winFp &= (polyMOD);

            /*slide window*/
            unsigned short int v = chunkBuffer[chunkBufferCnt - slidingWinSize]; //queue
            winFp = ((winFp + removeLUT[v]) * polyBase + chunkBuffer[chunkBufferCnt]) & polyMOD; //remove queue front and add queue tail
            chunkBufferCnt++;

            /*chunk's size less than minChunkSize*/
            if (chunkBufferCnt < minChunkSize)
                continue;

            /*find chunk pattern*/
            if ((winFp & anchorMask) == anchorValue) {
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunker_VarSizeHash, NULL);
#endif
                if (!cryptoObj->generateHash(chunkBuffer, chunkBufferCnt, hash)) {
                    cerr << "Chunker : average size chunking compute hash error" << endl;
                    return;
                }
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunker_VarSizeHash, NULL);
                diff = 1000000 * (timeendChunker_VarSizeHash.tv_sec - timestartChunker_VarSizeHash.tv_sec) + timeendChunker_VarSizeHash.tv_usec - timestartChunker_VarSizeHash.tv_usec;
                second = diff / 1000000.0;
                hashTime += second;
#endif
                Data_t tempChunk;
                tempChunk.chunk.ID = chunkIDCnt;
                tempChunk.chunk.logicDataSize = chunkBufferCnt;
                memcpy(tempChunk.chunk.logicData, chunkBuffer, chunkBufferCnt);
                memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunker_VarSizeInsert, NULL);
#endif
                if (!insertMQToKeyClient(tempChunk)) {
                    cerr << "Chunker : error insert chunk to keyClient message queue for chunk ID = " << tempChunk.chunk.ID << endl;
                    return;
                }
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunker_VarSizeInsert, NULL);
                diff = 1000000 * (timeendChunker_VarSizeInsert.tv_sec - timestartChunker_VarSizeInsert.tv_sec) + timeendChunker_VarSizeInsert.tv_usec - timestartChunker_VarSizeInsert.tv_usec;
                second = diff / 1000000.0;
                insertTime += second;
#endif
                chunkIDCnt++;
                chunkBufferCnt = winFp = 0;
            }

            /*chunk's size exceed maxChunkSize*/
            if (chunkBufferCnt >= maxChunkSize) {
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunker_VarSizeHash, NULL);
#endif
                if (!cryptoObj->generateHash(chunkBuffer, chunkBufferCnt, hash)) {
                    cerr << "Chunker : average size chunking compute hash error" << endl;
                    return;
                }
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunker_VarSizeHash, NULL);
                diff = 1000000 * (timeendChunker_VarSizeHash.tv_sec - timestartChunker_VarSizeHash.tv_sec) + timeendChunker_VarSizeHash.tv_usec - timestartChunker_VarSizeHash.tv_usec;
                second = diff / 1000000.0;
                hashTime += second;
#endif
                Data_t tempChunk;
                tempChunk.chunk.ID = chunkIDCnt;
                tempChunk.chunk.logicDataSize = chunkBufferCnt;
                memcpy(tempChunk.chunk.logicData, chunkBuffer, chunkBufferCnt);
                memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
                tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timestartChunker_VarSizeInsert, NULL);
#endif
                if (!insertMQToKeyClient(tempChunk)) {
                    cerr << "Chunker : error insert chunk to keyClient message queue for chunk ID = " << tempChunk.chunk.ID << endl;
                    return;
                }
#if SYSTEM_BREAK_DOWN == 1
                gettimeofday(&timeendChunker_VarSizeInsert, NULL);
                diff = 1000000 * (timeendChunker_VarSizeInsert.tv_sec - timestartChunker_VarSizeInsert.tv_sec) + timeendChunker_VarSizeInsert.tv_usec - timestartChunker_VarSizeInsert.tv_usec;
                second = diff / 1000000.0;
                insertTime += second;
#endif
                chunkIDCnt++;
                chunkBufferCnt = winFp = 0;
            }
        }
        if (fin.eof()) {
            break;
        }
    }

    /*add final chunk*/
    if (chunkBufferCnt != 0) {
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker_VarSizeHash, NULL);
#endif
        if (!cryptoObj->generateHash(chunkBuffer, chunkBufferCnt, hash)) {
            cerr << "Chunker : average size chunking compute hash error" << endl;
            return;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker_VarSizeHash, NULL);
        diff = 1000000 * (timeendChunker_VarSizeHash.tv_sec - timestartChunker_VarSizeHash.tv_sec) + timeendChunker_VarSizeHash.tv_usec - timestartChunker_VarSizeHash.tv_usec;
        second = diff / 1000000.0;
        hashTime += second;
#endif
        Data_t tempChunk;
        tempChunk.chunk.ID = chunkIDCnt;
        tempChunk.chunk.logicDataSize = chunkBufferCnt;
        memcpy(tempChunk.chunk.logicData, chunkBuffer, chunkBufferCnt);
        memcpy(tempChunk.chunk.chunkHash, hash, CHUNK_HASH_SIZE);
        tempChunk.dataType = DATA_TYPE_CHUNK;
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timestartChunker_VarSizeInsert, NULL);
#endif
        if (!insertMQToKeyClient(tempChunk)) {
            cerr << "Chunker : error insert chunk to keyClient message queue for chunk ID = " << tempChunk.chunk.ID << endl;
            return;
        }
#if SYSTEM_BREAK_DOWN == 1
        gettimeofday(&timeendChunker_VarSizeInsert, NULL);
        diff = 1000000 * (timeendChunker_VarSizeInsert.tv_sec - timestartChunker_VarSizeInsert.tv_sec) + timeendChunker_VarSizeInsert.tv_usec - timestartChunker_VarSizeInsert.tv_usec;
        second = diff / 1000000.0;
        insertTime += second;
#endif
        chunkIDCnt++;
        chunkBufferCnt = winFp = 0;
    }
    fileRecipe.recipe.fileRecipeHead.totalChunkNumber = chunkIDCnt;
    fileRecipe.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCnt;
    fileRecipe.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe.recipe.keyRecipeHead.fileSize = fileRecipe.recipe.fileRecipeHead.fileSize;
    fileRecipe.dataType = DATA_TYPE_RECIPE;
    if (!insertMQToKeyClient(fileRecipe)) {
        cerr << "Chunker : error insert recipe head to keyClient message queue" << endl;
        return;
    }
    if (setJobDoneFlag() == false) {
        cerr << "Chunker: set chunking done flag error" << endl;
        return;
    }
    cout << "Chunker : variable size chunking over:\nTotal file size = " << fileRecipe.recipe.fileRecipeHead.fileSize << "; Total chunk number = " << fileRecipe.recipe.fileRecipeHead.totalChunkNumber << endl;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendChunker, NULL);
    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
    second = diff / 1000000.0;
    cout << "Chunker : total chunking time = " << setbase(10) << second - (insertTime + hashTime) << " s" << endl;
    cout << "Chunker : total hashing time = " << hashTime << " s" << endl;
#endif
    return;
}

bool Chunker::insertMQToKeyClient(Data_t& newData)
{
    return keyClientObj->insertMQFromChunker(newData);
}

bool Chunker::setJobDoneFlag()
{
    return keyClientObj->editJobDoneFlag();
}

uint32_t Chunker::cutPoint(const uint8_t* src, const uint32_t len) {
    uint32_t n;
    uint32_t fp = 0;
    uint32_t i;
    i = std::min(len, static_cast<uint32_t>(minChunkSize)); 
    n = std::min(normalSize_, len);
    for (; i < n; i++) {
        fp = (fp >> 1) + GEAR[src[i]];
        if (!(fp & maskS_)) {
            return (i + 1);
        }
    }

    n = std::min(static_cast<uint32_t>(maxChunkSize), len);
    for (; i < n; i++) {
        fp = (fp >> 1) + GEAR[src[i]];
        if (!(fp & maskL_)) {
            return (i + 1);
        }
    } 
    return i;
}

void Chunker::fastCDC() {
    double insertTime = 0;
    double hashTime = 0;
    long diff;
    double second;
    size_t pos = 0;
    ifstream& fin = getChunkingFile();
    uint64_t fileSize = 0;
    uint64_t chunkIDCnt = 0;
    size_t totalOffset = 0;
    bool end = false;
/*start chunking*/
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timestartChunker, NULL);
#endif
    while (!end) {
        memset((char*)waitingForChunkingBuffer, 0, sizeof(uint8_t) * ReadSize);
        fin.read((char*)waitingForChunkingBuffer, sizeof(uint8_t) * ReadSize);
        end = fin.eof();
        size_t len = fin.gcount();
        fprintf(stderr, "Chunker: len: %lu\n", len);
        size_t localOffset = 0;
        while (((len - localOffset) >= maxChunkSize) || (end && (localOffset < len))) {
            uint32_t cp = cutPoint(waitingForChunkingBuffer + localOffset, len - localOffset);
            Data_t tempChunk;
            tempChunk.chunk.ID = chunkIDCnt;
            tempChunk.chunk.logicDataSize = cp;
            memcpy(tempChunk.chunk.logicData, waitingForChunkingBuffer + localOffset, cp);
            tempChunk.dataType = DATA_TYPE_CHUNK;

#if SYSTEM_BREAK_DOWN==1
            gettimeofday(&timestartChunker_VarSizeHash, NULL);
#endif
            if (!cryptoObj->generateHash(tempChunk.chunk.logicData, tempChunk.chunk.logicDataSize, tempChunk.chunk.chunkHash)) {
                    cerr << "Chunker : average size chunking compute hash error" << endl;
                    return;
            }

#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendChunker_VarSizeHash, NULL);
            diff = 1000000 * (timeendChunker_VarSizeHash.tv_sec - timestartChunker_VarSizeHash.tv_sec) + timeendChunker_VarSizeHash.tv_usec - timestartChunker_VarSizeHash.tv_usec;
            second = diff / 1000000.0;
            hashTime += second;
#endif


#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timestartChunker_VarSizeInsert, NULL);
#endif
            if (!insertMQToKeyClient(tempChunk)) {
                fprintf(stderr, "Chunker, error insert chunk to FPWorker MQ for chunkID: %u.\n",
                    tempChunk.chunk.ID);
            }
#if SYSTEM_BREAK_DOWN == 1
            gettimeofday(&timeendChunker_VarSizeInsert, NULL);
            diff = 1000000 * (timeendChunker_VarSizeInsert.tv_sec - timestartChunker_VarSizeInsert.tv_sec) + timeendChunker_VarSizeInsert.tv_usec - timestartChunker_VarSizeInsert.tv_usec;
            second = diff / 1000000.0;
            insertTime += second;
#endif
            localOffset += cp;
            fileSize += cp;
            chunkIDCnt++;
        }
        pos += localOffset;
        totalOffset += localOffset;
    
        fin.seekg(totalOffset, std::ios_base::beg);
    }
    fileRecipe.recipe.fileRecipeHead.totalChunkNumber = chunkIDCnt;
    fileRecipe.recipe.keyRecipeHead.totalChunkKeyNumber = chunkIDCnt;
    fileRecipe.recipe.fileRecipeHead.fileSize = fileSize;
    fileRecipe.recipe.keyRecipeHead.fileSize = fileSize;
    fileRecipe.dataType = DATA_TYPE_RECIPE;

    if (!insertMQToKeyClient(fileRecipe)) {
        cerr << "Chunker : error insert recipe head to keyClient message queue" << endl;
        return;
    }
    if (setJobDoneFlag() == false) {
        cerr << "Chunker: set chunking done flag error" << endl;
        return;
    }

    cout << "Chunker : variable size chunking over:\nTotal file size = " << fileRecipe.recipe.fileRecipeHead.fileSize << "; Total chunk number = " << fileRecipe.recipe.fileRecipeHead.totalChunkNumber << endl;
#if SYSTEM_BREAK_DOWN == 1
    gettimeofday(&timeendChunker, NULL);
    diff = 1000000 * (timeendChunker.tv_sec - timestartChunker.tv_sec) + timeendChunker.tv_usec - timestartChunker.tv_usec;
    second = diff / 1000000.0;
    cout << "Chunker : total chunking time = " << setbase(10) << second - (insertTime + hashTime) << " s" << endl;
    cout << "Chunker : total hashing time = " << hashTime << " s" << endl;
#endif

    return ;
}


uint32_t Chunker::calNormalSize(const uint32_t min, const uint32_t av, const uint32_t max) {
    uint32_t off = min + DivCeil(min, 2);
    if (off > av) {
        off = av;
    } 
    uint32_t diff = av - off;
    if (diff > max) {
        return max;
    }
    return diff;
}


uint32_t Chunker::generateFastCDCMask(uint32_t bits) {
    uint32_t tmp;
    tmp = (1 << CompareLimit(bits, 1, 31)) - 1;
    return tmp;
}