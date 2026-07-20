# CMake for libdexdumper.so
cmake_minimum_required(VERSION 3.18)

project(dexdumper LANGUAGES CXX)

add_library(dexdumper SHARED
    native_dump.cpp)

find_library(log-lib log)

target_link_libraries(dexdumper
    ${log-lib})
