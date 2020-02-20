aux_source_directory(. CRYPTO_SRC)

add_library(libCrypto ${CRYPTO_SRC})

target_link_libraries(libCrypto ${OPENSSL_LIBRARY_OBJ} ${THIRD_OBJ})