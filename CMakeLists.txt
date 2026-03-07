cmake_minimum_required(VERSION 3.10)

project(secure_stream)
find_package(OpenSSL REQUIRED)

add_executable(test test_packet.cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


target_link_libraries(test OpenSSL::SSL OpenSSL::Crypto)
