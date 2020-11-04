#src/util

add_library(configure STATIC configure.cpp)
add_library(cryptoPrimitive STATIC cryptoPrimitive.cpp)
add_library(Sock STATIC socket.cpp)
add_library(database STATIC database.cpp)
add_library(murmurHash3 STATIC murmurHash3.cpp)
add_library(optimalSolver STATIC optimalSolver.cpp)
add_library(SSL_TLS STATIC ssl.cpp)
add_library(hhash STATIC hHash.cpp)
add_library(cache STATIC cache.cpp)
add_executable(secretShare ssMain.cpp)

target_link_libraries(secretShare ${LINK_OBJ})