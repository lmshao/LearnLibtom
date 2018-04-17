cmake_minimum_required(VERSION 3.9)
project(Libtom_Demo)

set(CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(include)

LINK_DIRECTORIES(libs/mac) # or libs/linux

LINK_LIBRARIES(tomcrypt)

SET(SRC_LIST main.cpp HMAC.cpp HMAC.h Utils.cpp Utils.h HASH.cpp HASH.h AES.cpp AES.h Test.cpp Test.h)

ADD_EXECUTABLE(LibtomDemo ${SRC_LIST})
