#/

find_package(Boost 1.36.0 REQUIRED COMPONENTS thread system serialization)
if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  link_directories(${BOOST_LIBRARY_DIR})
endif()

set(OPENSSL_INCLUDE_PATH ../lib/openssl/include)
set(OPENSSL_LIBRARY_PATH ../lib/openssl/)

# set(LEVELDB_INCLUDE_PATH ../lib/leveldb/include)
# set(LEVELDB_LIBRARY_PATH ../lib/leveldb/build)

set(LEVELDB_INCLUDE_PATH ~/Library/leveldb-1.22/include)
set(LEVELDB_LIBRARY_PATH ~/Library/leveldb-1.22/build)

include_directories(${BOOST_INCLUDE_DIR} ${LEVELDB_INCLUDE_PATH} ${OPENSSL_INCLUDE_PATH} ../include)
link_directories(${BOOST_LIBRARY_DIR} ${LEVELDB_LIBRARY_PATH} ${OPENSSL_LIBRARY_PATH} util)

set(BOOST_LIBRARY_OBJ boost_thread boost_system boost_serialization)
set(SYSTEM_LIBRARY_OBJ pthread rt dl)
set(OPENSSL_LIBRARY_OBJ ssl crypto)
set(LEVELDB_LIBRARY_OBJ pthread leveldb snappy)
set(UTIL_OBJ configure cryptoPrimitive Sock database murmurHash3 optimalSolver SSL_TLS)

set(LINK_OBJ ${UTIL_OBJ} ${OPENSSL_LIBRARY_OBJ} ${LEVELDB_LIBRARY_OBJ}
        ${BOOST_LIBRARY_OBJ} ${UTIL_OBJ} ${SYSTEM_LIBRARY_OBJ})

set(CLIENT_OBJ chunker keyClient sender  recvDecode  retriever)
set(SERVER_OBJ dataSR  dedupCore storage) 
set(KEYSERVER_OBJ keyServer)

# set(CMAKE_BUILD_TYPE "Release")
# set(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_C_FLAGS_DEBUG "-Wall -std=c1x -g -ggdb -g2") 
set(CMAKE_CXX_FLAGS_DEBUG "-Wall -std=c++17 -g -ggdb -g2 -fsanitize=leak -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "-O3 -std=c1x") 
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -std=c++11")
set(CMAKE_MODULE_PATH /usr/share/cmake-3.10/Modules/)

# SET (CMAKE_C_COMPILER             "/usr/bin/clang")
# SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
# SET (CMAKE_AR      "/usr/bin/llvm-ar")
# SET (CMAKE_LINKER  "/usr/bin/llvm-ld")
# SET (CMAKE_NM      "/usr/bin/llvm-nm")
# SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
# SET (CMAKE_RANLIB  "/usr/bin/llvm-ranlib")


add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(keymanage)
add_subdirectory(util)
