cmake_minimum_required(VERSION 3.10)

project(secure_stream)
find_package(OpenSSL REQUIRED)

add_executable(test test_packet.cpp)

#this is for tcp
add_executable(sender sender.cpp)
target_link_libraries(sender PRIVATE pthread)   # sometimes needed for std::thread

add_executable(receiver receiver.cpp)
target_link_libraries(receiver PRIVATE pthread)

#this is for udp
add_executable(udp_sender udp_sender.cpp)
add_executable(udp_receiver udp_receiver.cpp)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)


target_link_libraries(test OpenSSL::SSL OpenSSL::Crypto)
