#include "chunker.hpp"
#include "configure.hpp"
#include "encoder.hpp"
#include "keyClient.hpp"
#include "recvDecode.hpp"
#include "retriever.hpp"
#include "sender.hpp"
#include "sys/time.h"
#include <bits/stdc++.h>
#include <boost/thread/thread.hpp>

using namespace std;

Configure config("config.json");
Chunker* chunkerObj;
keyClient* keyClientObj;
Sender* senderObj;
Encoder* encoderObj;
RecvDecode* recvDecodeObj;
Retriever* retrieverObj;

struct timeval timestart;
struct timeval timeend;

void CTRLC(int s)
{
    cerr << "Client close" << endl;
    delete chunkerObj;
    delete keyClientObj;
    delete senderObj;
    delete recvDecodeObj;
    delete retrieverObj;
    delete encoderObj;
    exit(0);
}

void usage()
{
    cerr << "[client -r filename] for receive file" << endl;
    cerr << "[client -s filename] for send file" << endl;
}

int main(int argv, char* argc[])
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = CTRLC;
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    gettimeofday(&timestart, NULL);
    vector<boost::thread*> thList;
    boost::thread* th;
    if (argv != 3 && argv != 4) {
        usage();
        return 0;
    }
    boost::thread::attributes attrs;
    attrs.set_stack_size(200 * 1024 * 1024);
    int systemWorkType = -1;
    if (strcmp("-r", argc[1]) == 0) {
        systemWorkType = SYSTEM_WORK_TYPE_DOWNLOAD_FILE;

        string fileName(argc[2]);

        recvDecodeObj = new RecvDecode(fileName);
        retrieverObj = new Retriever(fileName, recvDecodeObj);
        th = new boost::thread(attrs, boost::bind(&RecvDecode::run, recvDecodeObj));
        thList.push_back(th);
        th = new boost::thread(attrs, boost::bind(&Retriever::recvThread, retrieverObj));
        thList.push_back(th);

    } else if (strcmp("-s", argc[1]) == 0) {
        systemWorkType = SYSTEM_WORK_TYPE_UPLOAD_FILE;

        senderObj = new Sender();
        encoderObj = new Encoder(senderObj);
        keyClientObj = new keyClient(encoderObj);
        string inputFile(argc[2]);
        chunkerObj = new Chunker(inputFile, keyClientObj);

        th = new boost::thread(attrs, boost::bind(&Chunker::chunking, chunkerObj));
        thList.push_back(th);
        th = new boost::thread(attrs, boost::bind(&keyClient::run, keyClientObj));
        thList.push_back(th);
        th = new boost::thread(attrs, boost::bind(&Encoder::run, encoderObj));
        thList.push_back(th);
        th = new boost::thread(attrs, boost::bind(&Sender::run, senderObj));
        thList.push_back(th);

    } else if (strcmp("-k", argc[1]) == 0) {
        systemWorkType = SYSTEM_WORK_TYPE_KEY_GENERATE_SIMULATE;

        int threadNumber = atoi(argc[2]);
        if (threadNumber == 0) {
            threadNumber = 1;
        }
        int keyGenNumber = atoi(argc[3]);

        cout << "Key Generate Test : target thread number = " << threadNumber << ", target key number per thread = " << keyGenNumber << endl;
        keyClientObj = new keyClient(keyGenNumber);
        for (int i = 0; i < threadNumber; i++) {
            th = new boost::thread(attrs, boost::bind(&keyClient::runKeyGenSimulator, keyClientObj));
            thList.push_back(th);
        }
    } else {
        usage();
        return 0;
    }
    gettimeofday(&timeend, NULL);
    long diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    double second = diff / 1000000.0;
    cerr << "System : init work time is " << diff << " us = " << second << " s" << endl;
    gettimeofday(&timestart, NULL);

    for (auto it : thList) {
        it->join();
    }
    gettimeofday(&timeend, NULL);
    diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    second = diff / 1000000.0;
    cerr << "System : total work time is " << diff << " us = " << second << " s" << endl;
#if SYSTEM_BREAK_DOWN == 1
    cerr << "System : start work time is " << timestart.tv_sec << " s, " << timestart.tv_usec << " us" << endl;
    cerr << "System : finish work time is " << timeend.tv_sec << " s, " << timeend.tv_usec << " us" << endl;
#endif
    if (systemWorkType == SYSTEM_WORK_TYPE_KEY_GENERATE_SIMULATE) {
        delete keyClientObj;
    } else if (systemWorkType == SYSTEM_WORK_TYPE_UPLOAD_FILE) {
        delete chunkerObj;
        delete keyClientObj;
        delete senderObj;
        delete encoderObj;
    } else if (systemWorkType == SYSTEM_WORK_TYPE_DOWNLOAD_FILE) {
        delete recvDecodeObj;
        delete retrieverObj;
    }
    return 0;
}
