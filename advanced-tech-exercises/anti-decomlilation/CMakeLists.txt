project(test)
cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "-Wall -Wextra -Wshadow -std=gnu11")

add_executable(${PROJECT_NAME} ${PROJECT_NAME}.c)