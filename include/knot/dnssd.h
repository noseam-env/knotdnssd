/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL
 */

#ifndef KNOTDNSSD_H
#define KNOTDNSSD_H

#include <string>
#include <atomic>
#include <functional>

#if defined(__clang__)
#include <unordered_map>
#endif

void registerService(const char *serviceName, const char *regType, const char *domain, int port, const std::unordered_map<std::string, std::string>& txt, std::atomic<bool> &stopFlag);

struct FindReply {
    const char* serviceName;
    const char* regType;
    const char* replyDomain;
};

void findService(const char *regType, const char *domain, std::function<void(const FindReply&)> callback, std::atomic<bool> &stopFlag);

struct ResolveReply {
    const char* host;
    uint16_t port;
    std::unordered_map<std::string, std::string> txt;
};

void resolveService(const char *serviceName, const char *regType, const char *domain, std::function<void(const ResolveReply&)> callback);

#endif //KNOTDNSSD_H
