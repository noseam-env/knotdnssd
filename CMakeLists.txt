# This file is part of libknotdnssd.
#
# For license and copyright information please follow this link:
# https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL

cmake_minimum_required(VERSION 3.5)

project(knotdnssd LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(knotdnssd include/knot/dnssd.h src/util.c src/util.h)

target_compile_definitions(knotdnssd PRIVATE KNOTDNSSD_IMPLEMENTATION)

if (ANDROID)
    # TODO: noop.cpp
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
    # Not recommended to enable this option
    # You should install: libavahi-compat-libdnssd-dev or avahi-compat-libdns_sd-devel
    option(KNOTDNSSD_USE_AVAHI_COMPAT "Use avahi-compat-libdns_sd" OFF)

    #list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
    include(cmake/FindDBus.cmake)
    include(cmake/FindAvahi.cmake)
    list(APPEND KNOTDNSSD_LIBS Avahi::common Avahi::client)
    if (KNOTDNSSD_USE_AVAHI_COMPAT)
        target_sources(knotdnssd PRIVATE src/bonjour.cpp)
        target_compile_definitions(knotdnssd PRIVATE USE_BONJOUR)
        target_compile_definitions(knotdnssd PRIVATE AVAHI_BONJOUR_COMPAT)
        list(APPEND KNOTDNSSD_LIBS Avahi::common Avahi::compat-libdns_sd)
    else ()
        target_sources(knotdnssd PRIVATE src/avahi.cpp)
        target_compile_definitions(knotdnssd PRIVATE USE_AVAHI)
    endif ()
else ()
    target_sources(knotdnssd PRIVATE src/bonjour.cpp)
    target_compile_definitions(knotdnssd PRIVATE USE_BONJOUR)
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

target_include_directories(knotdnssd PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(knotdnssd PRIVATE ${KNOTDNSSD_INCLUDE})

target_link_libraries(knotdnssd PRIVATE ${KNOTDNSSD_LIBS})

if (PROJECT_IS_TOP_LEVEL)
    add_subdirectory(example)
endif()
