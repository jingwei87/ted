if [ ! -d "bin" ]; then
 mkdir bin
fi
if [ ! -d "build" ]; then
 mkdir build
fi
./clean.sh
cd ./build
rm -rf ./*
cmake ..
JOBS := $(shell grep -c ^processor /proc/cpuinfo 2>/dev/null)
make -j$(JOBS)
cd ..
cd ./bin
mkdir Containers Recipes
cd ..
cp config.json ./bin
cp -r ./key ./bin/
