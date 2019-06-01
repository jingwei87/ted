/*
 * main test program
 */
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
#include "solver.h"
#include "uploader.hh"
#include <google/sparse_hash_map>
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

void usage(char* s)
{
    printf("usage: ./CLIENT [filename] [userID] [action] [secutiyType]\n- [filename]: full path of the file;\n- [userID]: use ID of current client;\n- [action]: [-u] upload; [-d] download;\n- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1\n");
    exit(1);
}

int main(int argc, char* argv[])
{
    /* argument test */
    if (argc != 5)
        usage(NULL);

    /* get options */
    int userID = atoi(argv[2]);
    char* opt = argv[3];
    char* securesetting = argv[4];

    /* read file */

    unsigned char* buffer;
    int* chunkEndIndexList;
    vector<int*> chunkEndIndexListVec;

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
        encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
        chunkerObj = new Chunker(VAR_SIZE_TYPE);
        cryptoObj = new CryptoPrimitive();

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

        struct eqstr {
            bool operator()(unsigned char* s1, unsigned char* s2) const
            {
                return (s1 == s2) || (s1 && s2 && strcmp((const char*)s1, (const char*)s2) == 0);
            }
        };

        google::sparse_hash_map<unsigned char*, int, hash<unsigned char*>, eqstr> chunkFreqTable;
        chunkFreqTable.set_deleted_key(NULL);

        while (total < size) {
            int ret = fread(buffer, 1, bufferSize, fin);
            chunkerObj->chunking(buffer, ret, chunkEndIndexList, &numOfChunks);

            int count = 0;
            int preEnd = -1;
            while (count < numOfChunks) {
                unsigned char data[SECRET_SIZE];
                unsigned char* hash;
                memcpy(data, buffer + preEnd + 1, chunkEndIndexList[count] - preEnd);
                cryptoObj->generateHash(data, chunkEndIndexList[count] - preEnd, hash);
                chunkFreqTable[hash] = ;
                preEnd = chunkEndIndexList[count];
                count++;
            }
            total += ret;
        }

        total = 0;
        fseek(fin, 0, SEEK_SET);
        while (total < size) {
            int ret = fread(buffer, 1, bufferSize, fin);

            int count = 0;
            int preEnd = -1;
            while (count < numOfChunks) {
                Encoder::Secret_Item_t input;
                input.type = 0;
                input.secret.secretID = totalChunks;
                input.secret.secretSize = chunkEndIndexList[count] - preEnd;
                memcpy(input.secret.data, buffer + preEnd + 1, input.secret.secretSize);

                input.secret.end = 0;
                if (total + ret == size && count + 1 == numOfChunks)
                    input.secret.end = 1;
                encoderObj->add(&input);
                totalChunks++;
                preEnd = chunkEndIndexList[count];
                count++;
            }
            total += ret;
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
    return 0;
}
