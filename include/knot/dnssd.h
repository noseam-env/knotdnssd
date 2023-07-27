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

void registerService(const char *serviceName, const char *regType, const char *domain, int port, const std::unordered_map<std::string, std::string>& txt, const std::function<bool()> &isStopped);

struct FindReply {
    const char* serviceName;
    const char* regType;
    const char* replyDomain;
};

using findCallback = std::function<void(const FindReply &)>;

void findService(const char *regType, const char *domain, const findCallback &callback, const std::function<bool()> &isStopped);

struct ResolveReply {
    const char* host;
    unsigned short port;
    std::unordered_map<std::string, std::string> txt;
};

using resolveCallback = std::function<void(const ResolveReply &)>;

void resolveService(const char *serviceName, const char *regType, const char *domain, const resolveCallback &callback);

#endif //KNOTDNSSD_H
