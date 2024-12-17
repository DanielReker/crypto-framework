add_executable(backend-demo backend-demo.cpp)
target_compile_features(backend-demo PRIVATE cxx_std_17)

target_link_libraries(backend-demo PRIVATE cryptofw-backend)