# Balancing Storage Efficiency and Data Confidentiality with Tunable Encrypted Deduplication

## Introduction

Conventional encrypted deduplication approaches retain the deduplication capability on duplicate chunks after encryption by always deriving the key for encryption/decryption from the chunk content, but such a deterministic nature causes information leakage due to frequency analysis.  We present TED, a tunable encrypted deduplication primitive that provides a tunable mechanism for balancing the trade-off between storage efficiency and data confidentiality with a small performance overhead. It allows users to configure a storage blowup factor, under which the information leakage quantified by an information-theoretic measure is minimized for any input workload.  

## Publication

* Jingwei Li, Zuoru Yang, Yanjing Ren, Patrick P. C. Lee, and Xiaosong Zhang. Balancing Storage Efficiency and Data Confidentiality with Tunable Encrypted Deduplication. Proceedings of the European Conference on Computer Systems (Eurosys 2020), Heraklion, Crete, Greece, Apr 2020

## Prerequisites

TED and TEDStore supports CMake out of the box. The requirements for the compilation system are as follows:

* CMake version higher than 3.10 (Default CMake 3.17)
* C/C++ compilation tools need to support C 11 and C++ 11 standards (Default GNU GCC 7.4.0)

The TED and TEDStore require the following libraries:

* OpenSSL: [openssl-1.1.1d](https://www.openssl.org/source/openssl-1.1.1d.tar.gz)
* Boost C++ library: [libboost-1.72.0](https://dl.bintray.com/boostorg/release/1.72.0/source/boost_1_72_0.tar.gz)
* Snappy: [libsnappy-1.1.8](https://github.com/google/snappy/archive/1.1.8.tar.gz)
* Leveldb: [leveldb-1.22](https://github.com/google/leveldb/archive/1.22.tar.gz)

Among them, Leveldb 1.22 and OpenSSL 1.1.1d package are required to avoid compilation problems caused by different versions of the leveldb library paths and inconsistent default OpenSSL versions on different systems. You can download the compressed files of the two packages via the above link. Then you can configure and compile them with the following commands, and copy the two folders after compilation to `./TEDStore/lib/` and `./TED/ThirdPartyLib/` for compiling the prototype and the simulator.

For Leveldb

```shell
tar -xpf leveldb-1.22.tar.gz
cd ./leveldb-1.22/
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .

# for TEDStore
mkdir -p ${PATH_TO_TEDStore}/lib/
cp -r ./leveldb-1.22 ${PATH_TO_TEDStore}/lib/leveldb

# for TED
mkdir -p ${PATH_TO_TED}/lib/
cp -r ./leveldb-1.22 ${PATH_TO_TED}/lib/leveldb
```

For Openssl

```shell
tar -xpf openssl-1.1.1d.tar.gz
cd ./openssl-1.1.1d/
./config && make

# for TEDStore
mkdir -p ${PATH_TO_TEDStore}/lib/
cp -r ./openssl-1.1.1d ${PATH_TO_TEDStore}/lib/openssl

# for TED
mkdir -p ${PATH_TO_TED}/lib/
cp -r ./openssl-1.1.1d ${PATH_TO_TED}/lib/openssl
```

And the other dependent packages can be easily installed through the package management tool. For example, in Ubuntu 18.04 LTS, you can execute the following command to complete the installation.

```shell
sudo apt install libboost-all-dev libsnappy-dev
```

## TED Simulator

When using the simulator, first enter the `./TED/` folder directory.

### Build TED Simulator

We provide a simple script to build the simulator, please run:

```shell
bash ./script/setup.sh
```

The executable files are in *./bin*.

### Configure TED simulator

In TED simulator, you can configure the parameters of the sketch in *./include/define.h*

```C++
/**sketch configuration*/
#define SKETCH_ENABLE 1  // 1: using sketch 0: using hash table
#define SKETCH_DEPTH 4 // the depth of sketch
#define SKETCH_WIDTH (2<<20) // the width of sketch
```

And you need to configure the size of the fingerprint of the input trace. For FSL trace, it is 6 bytes. For MS trace, it is 5 bytes.

```c++
#define FP_SIZE (6) // for FSL trace
// if use MS trace, FP_SIZE = 5
```

### Usage

TED simulator implements 5 kinds of secure deduplication encryption schemes, including bted (Basic TED), fted (Full TED), minhash (MinHash Encryption), mle (Message-locked Encryption), ske (Symmetric Key Encryption). Here, we show the command format of each scheme.

```shell
1. bted (Basic TED): ./TEDSim [inputfile] [outputfile] [threshold] [distribution-type]
2, fted (Full TED):./TEDSim [inputfile] [outputfile] [batch-size] [storage blowup >=1] [distribution type]
3, minhash: ./TEDSim [inputfile] [outputfile]
4, mle: ./TEDSim [inputfile] [outputfile]
5, ske: ./TEDSim [inputfile] [outputfile]
[distribution-type: (0) Disable (1)uniform-distribution(2)poisson-distribution (3)normal-distribution (4)geo-distribution]
```

The input file should be a fingerprint list following the format in our example in *./example* folder.

Note: for the case of probabilistic key generation, this simulator can support 4 types of probabilistic distributions, but we only consider the uniform distribution in our original paper (i.e., [distribution type]=1).

After each run, it would generate two files:

```shell
[outputfile].pfreq: the frequency of each chunk in the original workload
[outputfile].cfreq: the frequency of each encrypted chunk in encrypted workload
```

Then you can run the script to compare the original workload and encrypted workload in different dimensions

```shell
python3 ./script/analyze.py [outputfile].pfreq [outputfile].cfreq
```

### Demo

Here, we provide a demo to show how to use this simulator, the FSL demo trace file cloud download via [FSL Traces and Snapshots Public Archive](http://tracer.filesystems.org/traces/fslhomes/) and the fingerprint list could be generated by the following commands with the help of [fs-hasher](http://tracer.filesystems.org/fs-hasher-0.9.5.tar.gz)

```shell
tar -jxvf ${compressed_hash_file_name}.tar.bz2
./hf-stat -f ${Uncompressed_hash_file_name}
```

Then, you will need to remove the first line in the generated fingerprint list. We use the snapshot of user004 in 2013-01-22 as the demo example.

Here we use Full-TED with probabilistic key generation and the batch size is 3000. Suppose the output file name is *test*, and we set the storage blowup factor as 1.05. Then the whole command is

```shell
cd bin;
./TEDSim ../example/fslhomes-user004-2013-01-22 test fted 3000 1.05 1
```

After this, it would print out some statistic information and generates two files (i.e., test.pfreq, test.cfreq):

```shell
============== Original Backup =============
Logical original chunks number: 1069738
Logical original chunks size: 9.416790GB
Unique original chunks number: 740314
Unique original chunks size: 6.449752GB
============== Encrypted Backup ============
Logical encrypted chunks size: 10111200989
Logical encrypted chunks number: 1069738
Logical encrypted chunks size: 9.416790GB
Unique encrypted chunks size: 7240790193
Unique encrypted chunks number: 769990
Unique encrypted chunks size: 6.743511GB
============== Storage Saving Ratio ========
Original Storage Saving (Size): 0.315080
Original Storage Saving (Chunk): 0.307948
Encrypted Storage Saving (Size): 0.283884
Encrypted Storage Saving (Chunk): 0.280207
```

Then, it can use the following command to further see other statistic information of plaintext chunk frequency distribution and ciphertext chunk frequency distribution, including maximum chunk frequencies, amount of unique chunks, amount of logical chunks, storage saving rate, KLD, and storage blowup rate. 

```shell
python3 ../script/analyze.py test.pfreq test.cfreq
```  

After this, it shows

```shell
----------------Finish Reading Data------------
The maximum count of plaintext chunks: 43592
The amount of unique plaintext chunks: 740314
Total Logical Plaintext Chunks: 1069738
The maximum count of ciphertext chunks: 32
The amount of unique ciphertext chunks: 769990
Total Logical Ciphertext Chunks: 1069738
First KLDivergence: 0.844787
Second KLDivergence: 0.227477
First Storage Saving: 0.307948
Second Storage Saving: 0.280207
----------------Storage Efficiency--------------
The amount of unique plaintext chunks: 740314
The amount of unique ciphertext chunks: 769990
Storage blowup rate: 1.040086
The maximum count of plaintext chunks: 43592
The amount of unique plaintext chunks: 740314
Total Logical Plaintext Chunks: 1069738
The maximum count of ciphertext chunks: 32
The amount of unique ciphertext chunks: 769990
Total Logical Ciphertext Chunks: 1069738
```

We can see under this setting, Full-TED reduces the KLD from 0.844787 to 0.227477, while the storage blowup is around 1.04 which is close to the setting storage blowup factor of 1.05.

### Limitations

* In this simulator, we treat the fingerprint of each chunk as the corresponding chunk content. The reason is we can only get the chunk fingerprint in both FSL trace and MS trace. There may be some deviation compared with using the real chunk content.

## TED System Prototype

When using the prototype, first enter the `./TEDStore/` folder directory.

### Build TEDStore System Prototype

You cloud compile the TEDStore prototype as shown below:

```shell
mkdir -p bin
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make
```

After compiling, copy the `lib/*.a`, `config.json`, and `key/` folders to the `bin/` folder.

To simplify the process, a quick build can be done through the script we provide. At the same time, the script will clear the compilation result of the original prototype at runtime (TED will be recompiled every time the script is used)

```shell
chmod +x ./ShellScripts/systemBuild.sh
./ShellScripts/systemBuild.sh
```

### Configure TEDStore System Prototype

When using this prototype after compilation is complete, we provide concise setting options based on JSON. Various parameters of the system can be set in `bin/config.json` according to the attribute name. For the attributes, we make the following comments:

```
{
    "ChunkerConfig": {
        "_chunkingType": 1, // 0: fixed size chunking; 1: variable size chunking
        "_minChunkSize": 4096, // The smallest chunk size in variable size chunking, Uint: Byte (Maximum size 16KB)
        "_avgChunkSize": 8192, // The average chunk size in variable size chunking and chunk size in fixed size chunking, Uint: Byte (Maximum size 16KB)
        "_maxChunkSize": 16384, // The biggest chunk size in variable size chunking, Uint: Byte (Maximum size 16KB)
        "_slidingWinSize": 256, // The sliding window size in variable size chunking, Uint: MB
        "_ReadSize": 128 // System read input file size every I/O operation, Uint: MB
    },
    "KeyServerConfig": {
        "_keyBatchSize": 3000, // Maximum number of keys obtained per communication
        "_keyServerIP": "127.0.0.1", // Key server host IP
        "_keyServerPort": 6666, // Key server host port
        "_sketchTableWidth": 1048576, // Number of columns in the sketch table
        "_optimalSolverComputeItemNumberThreshold": 48000, // After every set number of keys are generated, the optimization parameter t is solved
        "_storageBlowPercent": 0.005 // Preset storage blowup factor b, Uint: 1
    },
    "SPConfig": {
        "_storageServerIP": "127.0.0.1", // Storage server host IP
        "_storageServerPort": 6668, // Storage server host port
        "_maxContainerSize": 8388608, // Maximum space for one-time persistent chunk storage, Uint: Byte (Maximum size 8MB)
        "_RecipeRootPath": "Recipes/", // Path to the file recipe storage directory
        "_containerRootPath": "Containers/", // Path to the unique chunk storage directory
        "_fp2ChunkDBName": "db1", // Path to the chunk database directory
        "_fp2MetaDBame": "db2" // Path to the file recipe database directory
    },
    "client": {
        "_clientID": 1, // Current client ID 
        "_sendChunkBatchSize": 1000, // Maximum number of chunks sent per communication
        "_sendRecipeBatchSize": 100000, // Maximum number of file recipe entry sent per communication
        "_sendShortHashMaskBitNumber": 12 // Bit length modified during key generation (To prevent this information from being obtained by Key server)
    }
}
```

### Usage

After compilation and configuration are completed, TED is available, and instructions for use are given next.

#### Start Servers

In the `bin/` folder, directly execute the `keymanager` and `server` executable files to start the service according to the settings of `config.json`

#### Start Client

TEDStore provides a simple file store and restores operation:

```
[client -s filename] for store file
[client -r filename] for restore file
```

We show two usage examples:  

```shell
// store a file `test` to storage server
$ ./client -s test

// restore a file `test` from storage server
$ ./client -r test
```

### Limitations

* TEDStore focuses on only the deduplication of data chunks, but not metadata.
* TEDStore does not address the fault tolerance of the key manager and the provider.
* TEDStore focuses on confidentiality and does not support fine-grained access control.
* TEDStore has no optimization for file restore. As the number of stored files increases and fragmentation increases, the performance of restore decreases significantly.

### Maintainers

* Yanjing Ren, University of Electronic Science and Technology of China (UESTC), tinoryj@gmail.com
* Zuoru Yang, The Chinese University of Hong Kong (CUHK), zryang@cse.cuhk.edu.hk
