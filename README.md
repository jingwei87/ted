# Balancing Storage Efficiency and Data Confidentiality with Tunable Encrypted Deduplication

## Introduction

Conventional encrypted deduplication approaches retain the deduplication capability on duplicate chunks after encryption by always deriving the key for encryption/decryption from the chunk content, but such a deterministic nature causes information leakage due to frequency analysis.  We present TED, a tunable encrypted deduplication primitive that provides a tunable mechanism for balancing the trade-off between storage efficiency and data confidentiality with a small performance overhead. It allows users to configure a storage blowup factor, under which the information leakage quantified by an information-theoretic measure is minimized for any input workload.  

## Publication

* Jingwei Li, Zuoru Yang, Yanjing Ren, Patrick P. C. Lee, and Xiaosong Zhang. Balancing Storage Efficiency and Data Confidentiality with Tunable Encrypted Deduplication. Proceedings of the European Conference on Computer Systems (Eurosys 2020), Heraklion, Crete, Greece, Apr 2020

## Build TED System Prototype

### Prerequisites

TED supports CMake out of the box. The requirements of TED for the compilation system are as follows:

* CMake version higher than 3.10 (Default CMake 3.17)
* C/C++ compilation tools need to support C 11 and C++ 11 standards (Default GNU GCC 7.4.0)

This prototype requires the following libraries:

* OpenSSL: [openssl-1.1.1d](https://www.openssl.org/source/openssl-1.1.1d.tar.gz)
* Boost C++ library: [libboost-1.72.0](https://dl.bintray.com/boostorg/release/1.72.0/source/boost_1_72_0.tar.gz)
* Snappy: [libsnappy-1.1.8](https://github.com/google/snappy/archive/1.1.8.tar.gz)
* Leveldb: [leveldb-1.22](https://github.com/google/leveldb/archive/1.22.tar.gz)

Among them, Leveldb 1.22 and OpenSSL 1.1.1d has been packaged in  `lib/` to avoid compilation problems caused by different versions of the leveldb library paths and inconsistent default OpenSSL versions on different systems. And the other dependent packages can be easily installed through the package management tool. For example, in Ubuntu 18.04 LTS, you can execute the following command to complete the installation.

```shell
sudo apt install libboost-all-dev libsnappy-dev
```

### Building

First, you need to complete the compilation of Leveldb and OpenSSL which packaged in `lib/`. You can quickly complete it by the following command:

```shell
cd lib/leveldb/
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
```

```shell
cd lib/openssl/
./config && make
```

Then compile the TED prototype as shown below:

```shell
mkdir -p bin
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make
```

After compiling, copy the `lib/*.a`, `config.json`, and `key/` folders to the `bin/` folder.

To simplify the process, a quick build can be done through the script we provide. At the same time, the script will clear the compilation result of the original prototype at runtime (TED will be recompiled every time the script is used, and both leveldb and OpenSSL libraries are compiled only on first compilation)

```shell
chmod +x ./ShellScripts/systemBuild.sh
./ShellScripts/systemBuild.sh
```

## Configure TED System Prototype

When using this prototype after compilation is complete, we provide concise setting options based on json. Various parameters of the system can be set in `bin/config.json` according to the attribute name. For the attributes, we make the following comments:

```json
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
        "_storageBlowPercent": 0.005 // Preset storage expansion coefficient b, Uint: 1
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

## Usage

After compilation and configuration are completed, TED is available, and instructions for use are given next.

### Start Servers

In the `bin/` folder, directly execute the `keymanager` and `server` executable files to start the service according to the settings of `config.json`

### Start Client

TED provides a simple file store and restores operation:

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

## Limitations

* TED focuses on only the deduplication of data chunks, but not metadata.
* TED does not address the fault tolerance of the key manager and the provider.
* TED focuses on confidentiality and does not support fine-grained access control.
* TED has no optimization for file restore. As the number of stored files increases and fragmentation increases, the performance of restore decreases significantly.

## Maintainers

* Yanjing Ren, University of Electronic Science and Technology of China (UESTC), tinoryj@gmail.com
