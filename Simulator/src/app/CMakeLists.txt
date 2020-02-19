add_executable(TEDSim tedSim.cc)

target_link_libraries(TEDSim libCrypto libSimulator libUtil)