cmake_minimum_required(VERSION 4.1.2)
project("tun2socks")

# Include prebuilt headers
include_directories(${CMAKE_SOURCE_DIR}/prebuilt/include)

# Import the prebuilt static library
add_library(tun2socks_prebuilt STATIC IMPORTED)
set_target_properties(tun2socks_prebuilt PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/prebuilt/lib/${ANDROID_ABI}/libtun2socks.a)

# Build the JNI wrapper
add_library(tun2socks SHARED tun2socks.cpp)

target_link_options(tun2socks PRIVATE "-Wl,-z,max-page-size=16384")

target_link_libraries(tun2socks
        tun2socks_prebuilt
        android
        log)
