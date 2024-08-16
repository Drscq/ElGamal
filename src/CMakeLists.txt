cmake_minimum_required(VERSION 3.10)

project(CRTGamal)

set(CMAKE_CXX_STANDARD 17)

# Set the optimization level
#add_compile_options(-O3)
# Add any additional flags that might be beneficial
#add_compile_options(-march=native)  # Optimize for the local machine

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})
add_executable(crtgamal
    main.cpp
    ElGamal_standard.cpp
    ElGamal_vector.cpp
    ElGamal_parallel.cpp
    ECElGamal_parallel.cpp
)

target_link_libraries(crtgamal
    OpenSSL::Crypto
    stdc++fs
    pthread
)
