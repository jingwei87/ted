/*
 * conf.hh
 */

#ifndef __CONF_HH__
#define __CONF_HH__

#include <bits/stdc++.h>

#define NEW 1
#define UPDATE 2
#define STUB 3
#define GETSTUB 4
#define META (-1)
#define DATA (-2)
#define STAT (-3)
#define DOWNLOAD (-7)

using namespace std;

struct serverConf {
    string serverIP;
    int dataStorePort;
    int keyStorePort;
};

/*
 * configuration class
 */

class Configuration {

private:
    /* total number for cloud */
    int numOfStore_;

    /* only single key manager is allowed for current version */
    string keymanagerIP_;

    int keymanagerPort_;

    vector<serverConf> server;

public:
    Configuration()
    {

        fstream configFile;
        configFile.open("config", ios::in | ios::binary);
        if (!configFile.is_open()) {

            cerr << "loading config file failed" << endl;
            exit(-1);
        }

        /* SET HERE! key manager IP & Port */
        configFile >> keymanagerIP_ >> keymanagerPort_;

        /* SET HERE! data store IPs and Ports */
        for (int i = 0; i < numOfStore_; i++) {

            serverConf temp;
            configFile >> temp.serverIP >> temp.dataStorePort >> temp.keyStorePort;
            server.push_back(temp);
        }
    }

    inline int getN()
    {

        return numOfStore_;
    }

    inline string getkmIP()
    {

        return keymanagerIP_;
    }

    inline int getkmPort()
    {

        return keymanagerPort_;
    }

    inline serverConf getServerConf(int index)
    {

        if (index > numOfStore_ + 1) {

            serverConf temp;
            temp.serverIP = "0";
            temp.dataStorePort = 0;
            temp.keyStorePort = 0;
            cerr << "index overflow numOfStore" << endl;
            return temp;
        } else {

            return server[index];
        }
    }
};

#endif
