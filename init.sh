./clean.sh
cd ./lib/openssl
./config
JOBS := $(shell grep -c ^processor /proc/cpuinfo 2>/dev/null)
make -j$(JOBS)
cd ../leveldb
make -j$(JOBS)
cd ../../
if [ ! -d "bin" ]; then
 mkdir bin
fi
if [ ! -d "build" ]; then
 mkdir build
fi
cd ./build
rm -rf ./*
cmake ..
make -j$(JOBS)
cd ..
cd ./bin
mkdir Containers Recipes
cd ..
cp config.json ./bin
cp -r ./key ./bin/
