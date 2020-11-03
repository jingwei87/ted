#include "chunker.hpp"
#include "configure.hpp"
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
RecvDecode* recvDecodeObj;
Retriever* retrieverObj;

struct timeval timestart;
struct timeval timeend;

void usage()
{
    cerr << "[client -r filename] for receive file" << endl;
    cerr << "[client -s filename] for send file" << endl;
}

int main(int argv, char* argc[])
{
    vector<boost::thread*> thList;
    boost::thread* th;
    if (argv != 3 && argv != 4) {
        usage();
        return 0;
    }
    boost::thread::attributes attrs;
    attrs.set_stack_size(200 * 1024 * 1024);

    if (strcmp("-r", argc[1]) == 0) {
        string fileName(argc[2]);

        recvDecodeObj = new RecvDecode(fileName);
        retrieverObj = new Retriever(fileName, recvDecodeObj);
        th = new boost::thread(attrs, boost::bind(&RecvDecode::run, recvDecodeObj));
        thList.push_back(th);
        th = new boost::thread(attrs, boost::bind(&Retriever::run, retrieverObj));
        thList.push_back(th);

    } else if (strcmp("-s", argc[1]) == 0) {

        senderObj = new Sender();
        keyClientObj = new keyClient(senderObj);
        string inputFile(argc[2]);
        chunkerObj = new Chunker(inputFile, keyClientObj);

        th = new boost::thread(attrs, boost::bind(&Chunker::chunking, chunkerObj));
        thList.push_back(th);
        if (OLD_VERSION) {
            th = new boost::thread(attrs, boost::bind(&keyClient::run, keyClientObj));
        } else {
            if (ENABLE_SECRET_SHARE) {
                th = new boost::thread(attrs, boost::bind(&keyClient::runSS, keyClientObj));
            } else {
                th = new boost::thread(attrs, boost::bind(&keyClient::runSimple, keyClientObj));
            }
        }

        thList.push_back(th);
        th = new boost::thread(attrs, boost::bind(&Sender::run, senderObj));
        thList.push_back(th);

    } else if (strcmp("-k", argc[1]) == 0) {
        int threadNumber = atoi(argc[2]);
        if (threadNumber == 0) {
            threadNumber = 1;
        }
        int keyGenNumber = atoi(argc[3]);

        gettimeofday(&timestart, NULL);
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

    gettimeofday(&timestart, NULL);

    for (auto it : thList) {
        it->join();
    }
    gettimeofday(&timeend, NULL);
    long diff = 1000000 * (timeend.tv_sec - timestart.tv_sec) + timeend.tv_usec - timestart.tv_usec;
    double second = diff / 1000000.0;
    cout << "System : total work time is " << diff << " us = " << second << " s" << endl;
#if SYSTEM_BREAK_DOWN == 1
    cout << "System : start work time is " << timestart.tv_sec << " s, " << timestart.tv_usec << " us" << endl;
    cout << "System : end work time is " << timeend.tv_sec << " s, " << timeend.tv_usec << " us" << endl;
#endif
    if (strcmp("-r", argc[1]) == 0) {
        delete recvDecodeObj;
        delete retrieverObj;
    } else if (strcmp("-s", argc[1]) == 0) {
        delete senderObj;
        delete keyClientObj;
        delete chunkerObj;
    } else {
        cerr << "Error: operation type" << endl;
    }
    return 0;
}
