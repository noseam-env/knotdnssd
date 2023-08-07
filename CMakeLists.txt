# This file is part of libknotdnssd.
#
# For license and copyright information please follow this link:
# https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL

cmake_minimum_required(VERSION 3.0)

project(knotdnssd LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

set(KNOTDNSSD_SOURCES ${KNOTDNSSD_SOURCES} src/util.cpp src/util.h)

if (CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
    include(cmake/FindDBus.cmake)
    include(cmake/FindAvahi.cmake)
    #set(KNOTDNSSD_INCLUDE ${KNOTDNSSD_INCLUDE} ${AVAHI_INCLUDE_DIRS})
    list(APPEND KNOTDNSSD_LIBS Avahi::common Avahi::client)
    set(KNOTDNSSD_SOURCES ${KNOTDNSSD_SOURCES} src/avahi.cpp)
    add_definitions(-DUSE_AVAHI)
else ()
    set(KNOTDNSSD_SOURCES ${KNOTDNSSD_SOURCES} src/bonjour.cpp)
    add_definitions(-DUSE_BONJOUR)
    if (WIN32)
        set(BONJOUR_SDK_HOME "$ENV{BONJOUR_SDK_HOME}")
        if (NOT BONJOUR_SDK_HOME)
            message(FATAL_ERROR "BONJOUR_SDK_HOME is not defined")
        endif ()
        set(DNSSD_INCLUDE_DIR "${BONJOUR_SDK_HOME}/Include")
        # TODO: ARM support
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(DNSSD_LIBRARY "${BONJOUR_SDK_HOME}/Lib/x64/dnssd.lib")
        else ()
            set(DNSSD_LIBRARY "${BONJOUR_SDK_HOME}/Lib/Win32/dnssd.lib")
        endif ()
        set(KNOTDNSSD_INCLUDE ${KNOTDNSSD_INCLUDE} ${DNSSD_INCLUDE_DIR})
        list(APPEND KNOTDNSSD_LIBS ws2_32 ${DNSSD_LIBRARY})
    endif ()
endif ()

add_library(knotdnssd_static STATIC ${KNOTDNSSD_SOURCES})

target_include_directories(knotdnssd_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(knotdnssd_static PRIVATE ${KNOTDNSSD_INCLUDE})

target_link_libraries(knotdnssd_static PRIVATE ${KNOTDNSSD_LIBS})
