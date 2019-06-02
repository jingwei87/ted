/*
 * main test program
 */
#include "CDCodec.hh"
#include "CryptoPrimitive.hh"
#include "chunker.hh"
#include "conf.hh"
#include "decoder.hh"
#include "downloader.hh"
#include "encoder.hh"
#include "solver.h"
#include "uploader.hh"
#include <bits/stdc++.h>
#include <google/dense_hash_map>
#include <iostream>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#define MAIN_CHUNK

using namespace std;

struct timeval timestart;
struct timeval timeend;

Chunker* chunkerObj;
Decoder* decoderObj;
Encoder* encoderObj;
Uploader* uploaderObj;
CryptoPrimitive* cryptoObj;
CDCodec* cdCodecObj;
Downloader* downloaderObj;
Configuration* confObj;

void usage(char* s)
{
    printf("usage: ./CLIENT [filename] [userID] [action] [secutiyType]\n- [filename]: full path of the file;\n- [userID]: use ID of current client;\n- [action]: [-u] upload; [-d] download;\n- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1\n- [storageBlowUp]:\n");
    exit(1);
}

int main(int argc, char* argv[])
{

    gettimeofday(&timestart, NULL);
    /* argument test */
    if (argc != 6)
        usage(NULL);

    /* get options */
    int userID = atoi(argv[2]);
    char* opt = argv[3];
    char* securesetting = argv[4];
    double storageBlow;
    storageBlow = atof(argv[5]);
    /* read file */

    unsigned char* buffer;
    int* chunkEndIndexList;
    vector<int> chunkNumberVec;

    int numOfChunks;
    int n, m, k, r, *kShareIDList;

    int i;

    /* initialize openssl locks */
    if (!CryptoPrimitive::opensslLockSetup()) {
        printf("fail to set up OpenSSL locks\n");

        return 0;
    }

    confObj = new Configuration();
    /* fix parameters here */
    /* TO DO: load from config file */
    n = confObj->getN();
    m = confObj->getM();
    k = confObj->getK();
    r = confObj->getR();

    /* initialize buffers */
    int bufferSize = confObj->getBufferSize();
    int chunkEndIndexListSize = confObj->getListSize();
    int secretBufferSize = confObj->getSecretBufferSize();
    int shareBufferSize = confObj->getShareBufferSize();

    unsigned char *secretBuffer, *shareBuffer;

    buffer = (unsigned char*)malloc(sizeof(unsigned char) * bufferSize);
    chunkEndIndexList = (int*)malloc(sizeof(int) * chunkEndIndexListSize);
    secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
    shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);

    /* initialize share ID list */
    kShareIDList = (int*)malloc(sizeof(int) * k);
    for (i = 0; i < k; i++)
        kShareIDList[i] = i;

    /* full file name process */
    int namesize = 0;
    while (argv[1][namesize] != '\0') {
        namesize++;
    }
    namesize++;

    /* parse secure parameters */
    int securetype = LOW_SEC_PAIR_TYPE;
    if (strncmp(securesetting, "HIGH", 4) == 0)
        securetype = HIGH_SEC_PAIR_TYPE;

    if (strncmp(opt, "-u", 2) == 0 || strncmp(opt, "-a", 2) == 0) {

        FILE* fin = fopen(argv[1], "r");

        /* get file size */
        fseek(fin, 0, SEEK_END);
        long size = ftell(fin);
        fseek(fin, 0, SEEK_SET);
        uploaderObj = new Uploader(n, n, userID);

        chunkerObj = new Chunker(VAR_SIZE_TYPE);
        cryptoObj = new CryptoPrimitive(securetype);

        Encoder::Secret_Item_t header;
        header.type = 1;
        memcpy(header.file_header.data, argv[1], namesize);
        header.file_header.fullNameSize = namesize;
        header.file_header.fileSize = size;

        // do encode

        //uploaderObj->generateMDHead(0,size,(unsigned char*) argv[1],namesize,n,0,0,0,0);

        long total = 0;
        int totalChunks = 0;

        unordered_map<string, int> chunkFreqTable;
        int index = 0;
        int maxReadTimes = size / confObj->getBufferSize() + 1;
        int maxChunkNumberPerRead = confObj->getBufferSize() / 2048;
        cout << maxChunkNumberPerRead * maxReadTimes << endl;
        unsigned char* hashTable;
        hashTable = (unsigned char*)malloc(sizeof(unsigned char) * 300 * 1024 * 1024);
        int tempIndex[maxReadTimes][maxChunkNumberPerRead];
        while (total < size) {
            int ret = fread(buffer, 1, bufferSize, fin);
            chunkerObj->chunking(buffer, ret, chunkEndIndexList, &numOfChunks);
            for (int i = 0; i < numOfChunks; i++) {
                tempIndex[index][i] = chunkEndIndexList[i];
            }
            chunkNumberVec.push_back(numOfChunks);
            int count = 0;
            int preEnd = -1;
            // cout << index << "th:" << numOfChunks << endl;
            // for (auto i = 0; i < numOfChunks; i++) {
            //     cout << chunkEndIndexList[i] << "  ";
            // }
            // cout << endl;
            while (count < numOfChunks) {

                unsigned char data[SECRET_SIZE];
                unsigned char hash[32];
                memcpy(data, buffer + preEnd + 1, chunkEndIndexList[count] - preEnd);
                SHA256(data, chunkEndIndexList[count] - preEnd, hash);
                memcpy(hashTable + (totalChunks * 32), hash, 32);
                // char buf[65] = { 0 };
                // char tmp[3] = { 0 };
                // for (int i = 0; i < 32; i++) {
                //     sprintf(tmp, "%02x", hash[i]);
                //     strcat(buf, tmp);
                // }
                // cout << buf << endl;
                // cout << chunkEndIndexList[count + 1] - chunkEndIndexList[count] << endl;
                string newChunkHash((char*)hash, 32);
                auto current = chunkFreqTable.find(newChunkHash);
                if (current == chunkFreqTable.end()) {
                    // cout << "new unique" << endl;
                    chunkFreqTable.insert(make_pair(newChunkHash, 1));
                } else {
                    // cout << "new dup" << current->first.length() << endl;
                    // char output[65] = { 0 };
                    // char temp[3] = { 0 };
                    // for (int i = 0; i < 32; i++) {
                    //     sprintf(temp, "%02x", current->first[i]);
                    //     strcat(output, temp);
                    // }
                    // cout << output << endl
                    //      << endl;
                    current->second++;
                }
                preEnd = chunkEndIndexList[count];
                count++;
                totalChunks++;
            }
            total += ret;
            index++;
        }
        vector<pair<string, int>> opInput;
        opInput.reserve(chunkFreqTable.size());
        cout << "total chunk number = " << totalChunks << endl;
        cout << "unique chunk number = " << chunkFreqTable.size() << endl;
        for (auto it = chunkFreqTable.begin(); it != chunkFreqTable.end(); it++) {
            // char buf[65] = { 0 };
            // char tmp[3] = { 0 };
            // for (int i = 0; i < 32; i++) {
            //     sprintf(tmp, "%02x", it->first.c_str()[i]);
            //     strcat(buf, tmp);
            // }
            // cout << it->first.length() << buf << endl;
            opInput.push_back(make_pair(it->first, it->second));
        }

        int opm = chunkFreqTable.size() * (1 + storageBlow);
        OpSolver* solver = new OpSolver(opm, opInput);
        encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj, solver->GetOptimal());
        // encoderObj->set_T();
        encoderObj->add(&header);
        total = 0;
        totalChunks = 0;
        fseek(fin, 0, SEEK_SET);

        // for (auto i = 0; i < chunkNumberVec.size(); i++) {
        //     cout << i << "th:" << chunkNumberVec[i] << endl;
        //     for (auto j = 0; j < chunkNumberVec[i]; j++) {
        //         cout << tempIndex[i][j] << "  ";
        //     }
        //     cout << endl;
        // }
        int i = 0;
        while (total < size) {

            int ret = fread(buffer, 1, bufferSize, fin);
            //chunkerObj->chunking(buffer, ret, chunkEndIndexList, &numOfChunks);
            //printf("line - %d\n", __LINE__);
            int count = 0;
            int preEnd = -1;
            while (count < numOfChunks) {

                Encoder::Secret_Item_t input;
                input.type = 0;
                input.secret.secretID = totalChunks;
                //input.secret.secretSize = chunkEndIndexList[count] - preEnd;
                input.secret.secretSize = tempIndex[i][count] - preEnd;
                input.secret.end = 0;
                memcpy(input.secret.data, buffer + preEnd + 1, input.secret.secretSize);
                //SHA256(input.secret.data, input.secret.secretSize, input.secret.hash);
                memcpy(input.secret.hash, hashTable + (totalChunks * 32), 32);
                // char buf[65] = { 0 };
                // char tmp[3] = { 0 };
                // for (int i = 0; i < 32; i++) {
                //     sprintf(tmp, "%02x", input.secret.hash[i]);
                //     strcat(buf, tmp);
                // }
                // cout << buf << endl;
                string newChunkHash((char*)input.secret.hash, 32);
                auto temp = chunkFreqTable.find(newChunkHash);
                if (temp == chunkFreqTable.end()) {
                    cout << "error in re find chunk" << endl;
                } else {
                    // cout << "success in re find chunk" << endl;
                    // for (int i = 0; i < 32; i++) {
                    //     sprintf(tmp, "%02x", temp->first[i]);
                    //     strcat(buf, tmp);
                    // }
                    // cout << buf << endl;
                    // cout << temp->second << endl;
                    input.secret.currentFreq = temp->second;
                    temp->second = temp->second - 1;
                }
                if (total + ret == size && count + 1 == chunkNumberVec[i] /*numOfChunks*/)
                    input.secret.end = 1;
                encoderObj->add(&input);

                totalChunks++;
                //preEnd = chunkEndIndexList[count];
                preEnd = tempIndex[i][count];
                count++;
            }
            total += ret;
            i++;
        }
        long long tt = 0, unique = 0;
        uploaderObj->indicateEnd(&tt, &unique);

        delete uploaderObj;
        delete chunkerObj;
        delete encoderObj;

        fclose(fin);
    }

    if (strncmp(opt, "-d", 2) == 0 || strncmp(opt, "-a", 2) == 0) {
        //cdCodecObj = new CDCodec(CAONT_RS_TYPE, n, m, r, cryptoObj);
        decoderObj = new Decoder(CAONT_RS_TYPE, n, m, r, securetype);
        downloaderObj = new Downloader(k, k, userID, decoderObj);
        char nameBuffer[256];
        sprintf(nameBuffer, "%s.d", argv[1]);
        FILE* fw = fopen(nameBuffer, "wb");

        decoderObj->setFilePointer(fw);
        decoderObj->setShareIDList(kShareIDList);

        downloaderObj->downloadFile(argv[1], namesize, k);
        decoderObj->indicateEnd();

        fclose(fw);
        delete downloaderObj;
        delete decoderObj;
    }

    free(buffer);
    free(chunkEndIndexList);
    free(secretBuffer);
    free(shareBuffer);
    free(kShareIDList);
    CryptoPrimitive::opensslLockCleanup();

    gettimeofday(&timeend, NULL);
    long diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    double second = diff / 1000000.0;
    printf("the total work time is %ld us = %lf s\n", diff, second);

    return 0;
}
