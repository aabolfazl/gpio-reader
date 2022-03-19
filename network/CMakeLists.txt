cmake_minimum_required(VERSION 2.8)

project(network)

file(GLOB worker_file
        "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

list(REMOVE_ITEM worker_file "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")

add_library(websocket_client ${worker_file})
target_link_libraries(websocket_client LINK_PUBLIC
        dl pthread boost_system ssl crypto)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} websocket_client)
#target_link_libraries(websocket_client LINK_PUBLIC -lssl -lcrypto)
