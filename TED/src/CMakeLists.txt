set(LEVELDB_INCLUDE_PATH ${TEDSim_SOURCE_DIR}/ThirdPartyLib/leveldb-1.22/include)
set(LEVELDB_LIBRARY_PATH ${TEDSim_SOURCE_DIR}/ThirdPartyLib/leveldb-1.22/build/libleveldb.a)


set(OPENSSL_INLCUDE_PATH ${TEDSim_SOURCE_DIR}/ThirdPartyLib/openssl-1.1.1d/include)
set(OPENSSL_LIBRARY_PATH_CRY ${TEDSim_SOURCE_DIR}/ThirdPartyLib/openssl-1.1.1d/libcrypto.a)
set(OPENSSL_LIBRARY_PATH_SSL ${TEDSim_SOURCE_DIR}/ThirdPartyLib/openssl-1.1.1d/libssl.a)

include_directories(${LEVELDB_INCLUDE_PATH} ${OPENSSL_INLCUDE_PATH} ../include)
link_directories(${LEVELDB_LIBRARY_PATH} ${OPENSSL_LIBRARY_PATH_CRY} ${OPENSSL_LIBRARY_PATH_SSL} ../lib)

set(SYSTEM_LIBRARY_OBJ pthread rt dl snappy)
set(OPENSSL_LIBRARY_OBJ ${OPENSSL_LIBRARY_PATH_SSL} ${OPENSSL_LIBRARY_PATH_CRY})
set(THIRD_OBJ ${OPENSSL_LIBRARY_OBJ} ${LEVELDB_LIBRARY_PATH} ${SYSTEM_LIBRARY_OBJ})


set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS_DEBUG "-Wall -std=c1x -g -ggdb -g2") 
set(CMAKE_CXX_FLAGS_DEBUG "-Wall -std=c++17 -g -ggdb -g2 -fsanitize=leak -fno-omit-frame-pointer")
#set(CMAKE_CXX_FLAGS_DEBUG "-Wall -std=c++17 -g -ggdb -g2 -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "-O3 -std=c1x") 
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -std=c++11")
set(CMAKE_MODULE_PATH /usr/share/cmake-3.10/Modules/)

# SET (CMAKE_C_COMPILER "/usr/bin/clang")
# SET (CMAKE_CXX_COMPILER "/usr/bin/clang++")
# SET (CMAKE_AR "/usr/bin/llvm-ar")
# SET (CMAKE_LINKER "/usr/bin/llvm-ld")
# SET (CMAKE_NM "/usr/bin/llvm-nm")
# SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
# SET (CMAKE_RANLIB "/usr/bin/llvm-ranlib")


add_subdirectory(app)
add_subdirectory(crypto)
add_subdirectory(util)
add_subdirectory(simulator)
