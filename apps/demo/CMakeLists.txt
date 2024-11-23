add_executable(demo demo.cpp)
target_compile_features(demo PRIVATE cxx_std_17)

target_link_libraries(demo PRIVATE cryptofw)