#src/keymanage
add_library(keyServer STATIC keyServer.cpp)
add_executable(keymanager keyServerMain.cpp)
target_link_libraries(keymanager ${KEYSERVER_OBJ} ${LINK_OBJ})