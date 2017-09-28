cmake_minimum_required(VERSION 3.9)

project(akai)

find_package(Qt5Core REQUIRED)
find_package(Qt5Network REQUIRED)
find_package(Gpgmepp REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

include_directories(include/)

set(HEADERS
    include/address.h
    include/crypto.h
    include/peer.h
    include/request.h
)

set(SOURCES
    src/address.cpp
    src/crypto.cpp
    src/peer.cpp
    src/request.cpp
)

add_library(akai SHARED ${SOURCES} ${HEADERS})
qt5_use_modules(akai Core Network)
target_include_directories(akai PUBLIC include/)
