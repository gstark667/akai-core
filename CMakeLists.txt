cmake_minimum_required(VERSION 3.9)

find_package(Qt5Core REQUIRED)
find_package(Qt5Network REQUIRED)
find_package(Gpgmepp REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(include)

set(SOURCES
    src/address.cpp
    src/crypto.cpp
    src/peer.cpp
    src/request.cpp
)

add_library(akai SHARED ${SOURCES})
qt5_use_modules(akai Core Network)
