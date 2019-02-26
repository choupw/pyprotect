cmake_minimum_required(VERSION 2.8.12)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/objs")

set(PYBIND11_CPP_STANDARD -std=c++11)
project(pyprotect)

add_subdirectory(deps/pybind11)
<<<<<<< HEAD
pybind11_add_module(libdaiwentest pyprotect.cpp config.h aes.h aes.cpp)
=======
pybind11_add_module(libdaiwen pyprotect.cpp config.h aes.h aes.cpp)
>>>>>>> 3ac21e9e72fa59854110fca61c00dcce4c21bfa1
