/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL
 */

#include "util.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <stdexcept>
#else
#include <arpa/inet.h>
#include <cstring>
#endif

std::string parseInetAddress(uint16_t rdlen, const void *rdata) {
    bool isV6 = rdlen == 16;
    char buffer[INET6_ADDRSTRLEN];
    const char* result;
#if defined(_WIN32)
    WSADATA wsaData;
    int r = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (r != 0) {
        throw std::runtime_error("Unable to init WinSock2");
    }
#endif
    if (isV6) {
        struct sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        std::memcpy(&sa.sin6_addr, rdata, 16);
        result = inet_ntop(AF_INET6, &(sa.sin6_addr), buffer, INET6_ADDRSTRLEN);
    } else {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        std::memcpy(&sa.sin_addr, rdata, 4);
        result = inet_ntop(AF_INET, &(sa.sin_addr), buffer, INET_ADDRSTRLEN);
    }
#if defined(_WIN32)
    WSACleanup();
#endif
    if (result == nullptr) {
        return "";
    }
    return {result};
}
