cmake_minimum_required(VERSION 3.17)
project(DES CXX)

set(CMAKE_CXX_STANDARD 14)

add_executable(DES main.cpp helpers.h fun.cpp fun.h)
link_libraries(DES helpers.h fun.h)