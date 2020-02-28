aux_source_directory(. UTIL_SRC)
aux_source_directory(./sketch SKETCH_SRC)

add_library(libUtil ${UTIL_SRC} ${SKETCH_SRC})