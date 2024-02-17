cmake_minimum_required(VERSION 3.27)
project(byond_tracy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "-Ofast -DNDEBUG")

add_library(byond_tracy SHARED prof.c)

target_compile_definitions(byond_tracy PRIVATE -D_FILE_OFFSET_BITS=64)
set_target_properties(byond_tracy PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(byond_tracy PROPERTIES PREFIX "")
set_target_properties(byond_tracy PROPERTIES OUTPUT_NAME "libprof")