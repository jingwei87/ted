#src/client

add_library(chunker STATIC chunker.cpp)
add_library(keyClient STATIC keyClient.cpp)
add_library(encoder STATIC encoder.cpp)
add_library(sender STATIC sender.cpp)
add_library(recvDecode STATIC recvDecode.cpp)
add_library(retriever STATIC retriever.cpp)

add_executable(client clientMain.cpp)

target_link_libraries(client ${CLIENT_OBJ} ${LINK_OBJ})