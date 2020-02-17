#!/bin/bash
./ShellScripts/systemCleanup.sh
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