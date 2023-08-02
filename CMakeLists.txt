# This file is part of libknotdnssd.
#
# For license and copyright information please follow this link:
# https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL

cmake_minimum_required(VERSION 3.0)

project(knotdnssd LANGUAGES CXX)

option(FORCE_USE_BONJOUR "FORCE TO USE APPLE BONJOUR" ON)

set(CMAKE_CXX_STANDARD 17)

set(KNOTDNSSD_SOURCES ${KNOTDNSSD_SOURCES} src/util.cpp src/util.h)

if (APPLE OR FORCE_USE_BONJOUR)
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
        list(APPEND KNOTDNSSD_LIBS ws2_32 ${DNSSD_LIBRARY})
        set(KNOTDNSSD_INCLUDE ${KNOTDNSSD_INCLUDE} ${DNSSD_INCLUDE_DIR})
    elseif (NOT APPLE AND NOT ANDROID) # for linux, we dont need any libraries on mac
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(AVAHI_COMPAT_LIBDNSSD REQUIRED IMPORTED_TARGET avahi-compat-libdns_sd)
        list(APPEND KNOTDNSSD_LIBS PkgConfig::AVAHI_COMPAT_LIBDNSSD)
        set(KNOTDNSSD_INCLUDE ${KNOTDNSSD_INCLUDE} ${AVAHI_COMPAT_LIBDNSSD_INCLUDE_DIRS})
        add_definitions(-DAVAHI_BONJOUR)
    endif ()
endif ()

add_library(knotdnssd_static STATIC ${KNOTDNSSD_SOURCES})

target_include_directories(knotdnssd_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(knotdnssd_static PRIVATE ${KNOTDNSSD_INCLUDE})

target_link_libraries(knotdnssd_static PRIVATE ${KNOTDNSSD_LIBS})
