cmake_minimum_required(VERSION 3.1)
project(TED)

set(CMAKE_CXX_STANDARD 17)

set(EXECUTABLE_OUTPUT_PATH ${TED_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${TED_SOURCE_DIR}/lib)

add_subdirectory(src)
