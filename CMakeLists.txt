# This file is part of libknotdnssd.
#
# For license and copyright information please follow this link:
# https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL

cmake_minimum_required(VERSION 3.0)

project(knotdnssd)

option(FORCE_USE_BONJOUR "FORCE TO USE APPLE BONJOUR" ON)

set(CMAKE_CXX_STANDARD 17)

if (APPLE OR FORCE_USE_BONJOUR)
    set(SOURCES ${SOURCES} src/bonjour.cpp)
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
        list(APPEND LINK_LIBS ws2_32)
    elseif (APPLE)
        find_library(DNSSD_LIBRARY dnssd)
        set(DNSSD_INCLUDE_DIR "/usr/include")
    else ()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(AVAHI_COMPAT_LIBDNSSD REQUIRED IMPORTED_TARGET avahi-compat-libdns_sd)
        set(DNSSD_INCLUDE_DIR ${AVAHI_COMPAT_LIBDNSSD_INCLUDE_DIRS})
        set(DNSSD_LIBRARY PkgConfig::AVAHI_COMPAT_LIBDNSSD)
    endif ()
    set(TARGET_INCLUDE ${TARGET_INCLUDE} ${DNSSD_INCLUDE_DIR})
    list(APPEND LINK_LIBS ${DNSSD_LIBRARY})
    add_definitions(-DUSE_BONJOUR)
endif ()

add_library(knotdnssd_static STATIC ${SOURCES})

target_include_directories(knotdnssd_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(knotdnssd_static PRIVATE ${TARGET_INCLUDE})

target_link_libraries(knotdnssd_static PRIVATE ${LINK_LIBS})
