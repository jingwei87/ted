# Balancing Storage Efficiency and Data Confidentiality with Tunable Encrypted Deduplication

## Introduction

Conventional encrypted deduplication approaches retain the deduplication capability on duplicate
chunks after encryption by always deriving the key for encryption/decryption from the chunk
content, but such a deterministic nature causes information leakage due to frequency analysis. We
present TED, a tunable encrypted deduplication primitive that provides a tunable mechanism for
balancing the trade-off between storage efficiency and data confidentiality. The core idea of
TED is that its key derivation is based on not only the chunk content but also the number of duplicate chunk
copies, such that duplicate chunks are encrypted by distinct keys in a controlled manner. In
particular, TED allows users to configure a storage blowup factor, under which the information
leakage quantified by an information-theoretic measure is minimized for any input workload. We implement an
encrypted deduplication prototype TEDStore to realize TED in networked environments. Evaluation on
real-world file system snapshots shows that TED effectively balances the trade-off between storage
efficiency and data confidentiality, with small performance overhead.

## Publication

* Jingwei Li, Zuoru Yang, Yanjing Ren, Patrick P. C. Lee, and Xiaosong Zhang. Balancing Storage Efficiency and Data Confidentiality with Tunable Encrypted Deduplication. Proceedings of the European Conference on Computer Systems (Eurosys 2020), Heraklion, Crete, Greece, Apr 2020.

## Prerequisites

We test TED and TEDStore under Ubuntu 18.04 and 16.04 (note that to run TEDStore, your machine needs to have at least 4GB memory). They require OpenSSL ([version 1.1.1d](https://www.openssl.org/source/openssl-1.1.1d.tar.gz)), Leveldb ([version 1.22](https://github.com/google/leveldb/archive/1.22.tar.gz)), Boost C++ library, and Snappy. Our test compiles TED and TEDStore using CMake 3.17 and GNU GCC 7.4.0.     

```shell
sudo apt-get install libboost-all-dev libsnappy-dev 

# openssl
wget -O - https://www.openssl.org/source/openssl-1.1.1d.tar.gz | tar -xz
cd ./openssl-1.1.1d/
./config && make
cd ..

# leveldb
wget -O - https://github.com/google/leveldb/archive/1.22.tar.gz | tar -xz 
mkdir -p ./leveldb-1.22/build && cd "$_" 
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build . 
cd ../../

mkdir -p ${PATH_TO_TED}/lib/
mkdir -p ${PATH_TO_TEDStore}/lib/
cp -r openssl-1.1.1d/ ${PATH_TO_TED}/lib/openssl
cp -r leveldb-1.22/ ${PATH_TO_TED}/lib/leveldb
cp -r openssl-1.1.1d/ ${PATH_TO_TEDStore}/lib/openssl
cp -r leveldb-1.22/ ${PATH_TO_TEDStore}/lib/leveldb
```

## TED 

TED implements a simulator to analyze the trade-off of different encrypted deduplication approaches, including symmetric-key encryption, message-locked encryption (MLE), MinHash encryption and TED itself.

To use TED, switch your current working directory to `TED/`.

### Configuration 

TED builds on CM-Sketch to count the frequency of each plaintext chunk. You can configure the parameters of CM-Sketch in `./include/define.h`, in order to decide: (i) whether using CM-Sketch for count; (ii) if yes, the width and depth of CM-Sketch.

```C++
/**sketch configuration*/
#define SKETCH_ENABLE 1  // 1: using sketch 0: using hash table
#define SKETCH_DEPTH 4 // the depth of sketch
#define SKETCH_WIDTH (2<<20) // the width of sketch
```

In addition, since TED is a simulator working on the fingerprints of chunks, you need to specify the number of bytes taken by each fingerprint in `./include/define.h`. For example, for FSL trace, it is 6 bytes; for MS trace, it is 5 bytes.    

```c++
#define FP_SIZE (6) // for FSL trace
// if use MS trace, FP_SIZE = 5
```


### Build 

We provide a script to build TED. You can run it as follows:

```shell
bash ./script/setup.sh
```
This produces executable files in `./bin`.
 

### Usage

TED simulates the results of five encrypted deduplication approaches.

- *Basic TED (bTED)*, which follows TED but using a fixed balance parameter t. 
- *Full TED (fTED)*, which implements the full version of TED and automatically configures t for a given storage blowup factor b.
- *MinHash encryption*, which encrypts each chunk with a key derived from the minimum fingerprint over a set of its adjacent chunks. 
- *MLE*, which encrypts each chunk with a key derived from the chunk itself. 
- *SKE*, which uses random symmetric key for encryption. 

You can run the executable file (in `./bin/`) of each approach as follows.


```shell
# usages for MinHash encryption, MLE and SKE
./TEDSim [inFile] [outFile] [method]

# usage for bTED
./TEDSim [inFile] [outFile] bted [t] [keygenDistribution]

# usage for fTED
./TEDSim [inFile] [outFile] fted [batchSize] [b] [keygenDistribution]
```
- `inFile` is a list of chunk fingerprints; an example of `inFile` can be found in `./example/`. 
- `outFile` specifies the output file name of the command; specifically, you will obtain two output files, namely `outFile.pfreq` and `outFile.cfreq`, which contain the frequency distributions of plaintext and ciphertext chunks, respectively. 
- `method` specifies the approach that you want to test, and it can be `minhash`, `mle`, `ske`, `bted` and `fted`.
- `t` defines the balance parameter of bTED.
- `b` defines the storage blowup factor of fTED.
- `batchSize` defines the number of plaintext chunks processed by the automated parameter configuration in a batch. 
- `keygenDistribution` defines the probabilistic distribution, based on which TED chooses the key seed; specifically, if `keygenDistribution` = 0, TED deterministically derives the key seed; otherwise if `keygenDistribution` = 1, 2, 3 and 4, TED chooses the key seed based on the uniform, poisson, normal and geometric distributions, respectively.  

Then you can run a python script `./script/analyze.py` to show the frequency distributions of plaintext and ciphertext chunks in different dimensions. Generally, it presents:

- The maximum frequencies among all plaintext/ciphertext chunks.
- The amount of unique plaintext/ciphertext chunks.
- The total number of plaintext/ciphertext chunks before deduplication.
- The storage saving rate, which is defined as (number of ciphertext chunks before deduplication - number of ciphertext chunk after deduplication)/(number of ciphertext chunks before deduplication).
- The KLD (relative entropy); refer our paper for its definition.
- The storage blowup rate, which is defined as (number of ciphertext chunks after deduplication - number of unique plaintext chunks)/(number of unique plaintext chunks).  

```shell
python3 ./script/analyze.py [outFile].pfreq [outFile].cfreq
```

### Usage Example

---

We now present an example to demonstrate the usage of TED. You first download the FSL trace from [FSL Traces and Snapshots Public Archive](http://tracer.filesystems.org/traces/fslhomes/) and generate the chunk fingerprint list using `hf-stat` (that is a component of the [fs-hasher](http://tracer.filesystems.org/fs-hasher-0.9.5.tar.gz) toolkit, see fs-hasher documentation for how to use it). For example, if we focus on the snapshot (that has an average chunk size of 8KB) from user004 in 2013-01-22, you can run:  

```shell
# note that you need to remove the title line of hf-stat output, in order to be compatiable with TED    
./hf-stat -h fslhomes-user004-2013-01-22.8kb.hash.anon |  sed --expression='1d' > fslhomes-user004-2013-01-22 

# fTED is used with a batch size of 3000, a storage blowup factor of 1.05 and uniform distribution for key generation 
./bin/TEDSim fslhomes-user004-2013-01-22 out fted 3000 1.05 1
```

In addition to `out.pfreq` and `out.cfreq`, it prints the following basic statistical information. 

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

You can further analyze advanced statistical information using the python script, and get the following outputs.

```shell
python3 ../script/analyze.py out.pfreq out.cfreq

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

This implies that, in the example, fTED 
 reduces the KLD from 0.844787 to 0.227477, while the actual storage blowup rate is around 1.04 which is close to the pre-configured storage blowup factor of 1.05.


## TEDStore

TEDStore implements an encrypted deduplication prototype based TED. 


To use TEDStore, switch your current working directory to `TEDStore/`.

### Build

Compile TEDStore as follows. 

```shell
mkdir -p bin && mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make

cd ..
cp lib/*.a bin/
cp config.json bin/
cp -r key/ bin/
mkdir -p bin/Containers && mkdir -p bin/Recipes
```

Alternatively, we provide a script for quick build, and you can use it. 
```shell
chmod +x ./ShellScripts/systemBuild.sh
chmod +x ./ShellScripts/systemCleanup.sh
./ShellScripts/systemBuild.sh
```

### Configuration

TEDStore is configured based on json. You can change its configuration without rebuilding. We show the default
configuration (`./bin/config.json`) of TEDStore as follows.
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

You can test TEDStore in a single machine, and connect the key manager, server (e.g., the provider in the paper) and client instances via the local loopback interface. To this end, switch your current working directory to `bin/`, and start each instance in an independent terminal:   

```shell
./keymanager
```
```shell
./server
```

TEDStore provides store and restore interfaces to client. 
```shell
# store file
./client -s file

# restore file
./client -r file
```

## Limitations

* TED works on the fingerprints of chunks (rather than exact chunk data). This may raise a few deviations on TED results, compared with working on actual data.   
* TEDStore does not apply any optimizations to file restore. Its restore performance may be affected by the number of stored files.

## Maintainers

* Yanjing Ren, University of Electronic Science and Technology of China (UESTC), tinoryj@gmail.com
* Zuoru Yang, The Chinese University of Hong Kong (CUHK), zryang@cse.cuhk.edu.hk
