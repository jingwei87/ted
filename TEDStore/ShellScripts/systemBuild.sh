#!/bin/bash
./ShellScripts/systemCleanup.sh

# cd lib/leveldb/
# if [ ! -d "build" ]; then
#     mkdir -p build && cd build
#     cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
#     cd ../../../
# else
#     cd ../../
# fi

# cd lib/openssl/
# if [ ! -f "Makefile" ]; then
#     ./config && make
#     cd ../../
# else
#     cd ../../
# fi

if [ ! -d "bin" ]; then
    mkdir bin
fi
if [ ! -d "build" ]; then
    mkdir build
fi
cd ./build
rm -rf ./*
cmake ..
make -j$(shell grep -c ^processor /proc/cpuinfo 2>/dev/null)
cd ..
cd ./bin
mkdir Containers Recipes
cd ..
cp config.json ./bin
cp -r ./key ./bin/