aux_source_directory(. SIMULATOR_SRC)

add_library(libSimulator ${SIMULATOR_SRC})


target_link_libraries(libSimulator libUtil libCrypto ${THIRD_OBJ})
