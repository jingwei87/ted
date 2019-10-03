#!/bin/bash
cd ./lib/openssl/
make clean
cd ../leveldb/
make clean
cd ../../
rm -rf ./build/*
rm -rf ./bin/*
rm -rf ./bin/.StorageConfig
rm -rf ./lib/*.a
