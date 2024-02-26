cmake_minimum_required(VERSION 3.27)
project(CTFLoader)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
include_directories("C:/Users/lemur/source/repos/hexane-server/src/include")

set(HEXANE_SRC "C:/Users/lemur/source/repos/hexane-server/src/core")
set(LDR_SRC "C:/Users/lemur/source/repos/CTFLoader")
add_executable(CTFLoader
        loader.cpp
        meterpreter.bin
        resource.hpp
        "${HEXANE_SRC}/multitool.cpp")

target_link_libraries(CTFLoader "${LDR_SRC}/resource.o")
