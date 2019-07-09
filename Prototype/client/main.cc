/*
 * main test program
 */
#include <bits/stdc++.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "CDCodec.hh"
#include "CryptoPrimitive.hh"
#include "chunker.hh"
#include "conf.hh"
#include "decoder.hh"
#include "downloader.hh"
#include "encoder.hh"
#include "exchange.hh"
#include "uploader.hh"
//#include "metadataChunkMaker.hh"

#define MAIN_CHUNK

using namespace std;

Chunker* chunkerObj;
Decoder* decoderObj;
Encoder* encoderObj;
Uploader* uploaderObj;
CryptoPrimitive* cryptoObj;
CDCodec* cdCodecObj;
Downloader* downloaderObj;
Configuration* confObj;
KeyEx* keyObj;

struct timeval timestart;
struct timeval timeend;

void usage(char* s)
{

    printf("usage: ./CLIENT [filename] [userID] [action] [secutiyType]\n");
    printf("\t- [filename]: full path of the file;\n");
    printf("\t- [userID]: use ID of current client;\n");
    printf("\t- [action]: [-u] upload; [-d] download;\n");
    printf("\t- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1\n");
    exit(1);
}

int main(int argc, char* argv[])
{

    gettimeofday(&timestart, NULL);
    /* argument test */
    if (argc != 5)
        usage(NULL);
    /* get options */
    char* policy = "1";
    int userID = atoi(argv[2]);
    char* opt = argv[3];
    char* securesetting = argv[4];
    /* read file */
    unsigned char* buffer;
    int* chunkEndIndexList;
    int numOfChunks;
    int n, m, k, r, *kShareIDList;
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
    for (int i = 0; i < k; i++)
        kShareIDList[i] = i;

    /* full file name size process */
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

        uploaderObj = new Uploader(n, n, userID, argv[1], namesize);
        encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
        chunkerObj = new Chunker(VAR_SIZE_TYPE);
        keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getkmPort(), confObj->getServerConf(0), CHARA_MIN_HASH, VAR_SEG);
        keyObj->readKeyFile("./keys/public.pem");

        //chunking
        Encoder::Secret_Item_t header;
        header.type = 1;
        memcpy(header.file_header.data, argv[1], namesize);
        header.file_header.fullNameSize = namesize;
        header.file_header.fileSize = size;

        // do encode
        encoderObj->add(&header);
        //uploaderObj->generateMDHead(0,size,(unsigned char*) argv[1],namesize,n,0,0,0,0);

        long total = 0;
        int totalChunks = 0;
        unsigned char tmp[secretBufferSize];
        memset(tmp, 0, secretBufferSize);
        while (total < size) {

            int ret = fread(buffer, 1, bufferSize, fin);
            chunkerObj->chunking(buffer, ret, chunkEndIndexList, &numOfChunks);
            //printf("line - %d\n", __LINE__);
            int count = 0;
            int preEnd = -1;
            while (count < numOfChunks) {

                // Encoder::Secret_Item_t input;
                // input.type = 0;
                // input.secret.secretID = totalChunks;
                // input.secret.secretSize = chunkEndIndexList[count] - preEnd;
                // memcpy(input.secret.data, buffer + preEnd + 1, input.secret.secretSize);
                // input.secret.end = 0;

                // if (total + ret == size && count + 1 == numOfChunks)
                //     input.secret.end = 1;
                // encoderObj->add(&input);

                // totalChunks++;
                // preEnd = chunkEndIndexList[count];
                // count++;
                KeyEx::Chunk_t input;
                input.chunkID = totalChunks;
                input.chunkSize = chunkEndIndexList[count] - preEnd;
                memcpy(input.data, buffer + preEnd + 1, input.chunkSize);
                /* zero counting */
                if (memcmp(buffer + preEnd + 1, tmp, input.chunkSize) == 0) {
                    total += input.chunkSize;
                }
                /* set end indicator */
                input.end = 0;
                if (ret + total == size && count + 1 == numOfChunks) {
                    input.end = 1;
                }
                /* add chunk to key client */
                keyObj->add(&input);
                /* increase counter */
                totalChunks++;
                preEnd = chunkEndIndexList[count];
                count++;
            }
            total += ret;
        }
        long long tt = 0, unique = 0;
        //printf("line - %d\n", __LINE__);
        //printf("flag-out of loop before indicate\n");
        uploaderObj->indicateEnd(&tt, &unique);

        delete uploaderObj;
        delete chunkerObj;
        delete encoderObj;
        fclose(fin);
    }

    if (strncmp(opt, "-d", 2) == 0 || strncmp(opt, "-a", 2) == 0) {

        //cdCodecObj = new CDCodec(CAONT_RS_TYPE, n, m, r, cryptoObj);
        decoderObj = new Decoder(CAONT_RS_TYPE, n, m, r, securetype);
        //printf("flag-before\n");
        downloaderObj = new Downloader(k, k, userID, decoderObj, argv[1], namesize);
        keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getkmPort(), confObj->getServerConf(0), CHARA_MIN_HASH, VAR_SEG);
        char nameBuffer[256];
        sprintf(nameBuffer, "%s.d", argv[1]);
        //printf("flag-0\n");
        downloaderObj->downloadKeyFile(argv[1]);
        //printf("flag-1\n");
        FILE* fw = fopen(nameBuffer, "wb");

        decoderObj->setFilePointer(fw);
        //printf("flag-2\n");
        decoderObj->setShareIDList(kShareIDList);
        //printf("flag-3\n");
        int preFlag = downloaderObj->preDownloadFile(argv[1], namesize, k);
        //printf("flag-4\n");
        if (preFlag == -1) {
            //printf("flag-5\n");
            downloaderObj->downloadFile(argv[1], namesize, k);
        }
        //printf("flag-6\n");
        decoderObj->indicateEnd();
        //printf("flag-7\n");
        downloaderObj->indicateEnd();
        //printf("flag-8\n");
        fclose(fw);
        delete downloaderObj;
        delete decoderObj;
    }

    delete confObj;
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

    //printf("\n\nRunning Time：%dms\n", timeendtime-begintime);

    return 0;
}
