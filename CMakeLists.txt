cmake_minimum_required(VERSION 3.19)
project(MasterModule)

set(CMAKE_CXX_STANDARD 11)

add_library(test STATIC
        network/RequestManager.cpp
        network/WebsocketClient.cpp
        network/AbstractObject.cpp
        network/ProtoSchema.cpp
        network/ByteArray.cpp)

add_library(proto STATIC
        network/proto/MessageContainer.pb.cc
        network/proto/ActionMap.pb.cc
        network/proto/Security.pb.cc
        network/proto/Error.pb.cc)

add_library(logger STATIC
        include/logger/Logger.cpp
        include/logger/Logger.h)

set(CMAKE_CXX_FLAGS "-std=c++11 -g -o0 -fPIC -Wall")
set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -Wl,-rpath=${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -Wl,-rpath=./lib")

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib")
set(EXECUTABLE_OUTPUT_PATH "${CMAKE_BINARY_DIR}/bin")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/network)

#add_definitions(-DTLS)

add_executable(MasterModule main.cpp Define.h)
add_subdirectory(network)
target_link_libraries(test LINK_PUBLIC -lssl -lcrypto) #ssl

target_link_libraries(MasterModule test logger)
target_link_libraries(MasterModule proto -lprotobuf -lpthread)
