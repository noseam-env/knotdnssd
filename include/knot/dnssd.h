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
#include <optional>

#if defined(__clang__)
#include <unordered_map>
#endif

void registerService(const char *serviceName, const char *regType, const char *domain, unsigned short port, const std::unordered_map<std::string, std::string>& txt, const std::function<bool()> &isStopped);

struct FindReply {
    const char* serviceName;
    const char* regType;
    const char* replyDomain;
};

using findCallback = std::function<void(const FindReply &)>;

void findService(const char *regType, const char *domain, const findCallback &callback, const std::function<bool()> &isStopped);

enum IPType {
    IPv6,
    IPv4
};

struct IPAddress {
    IPType type;
    std::string value;
};

struct ResolveReply {
    std::optional<std::string> hostName;
    std::optional<IPAddress> ip;
    unsigned short port;
    std::unordered_map<std::string, std::string> txt;
};

using resolveCallback = std::function<void(const std::optional<ResolveReply> &)>;

void resolveService(const char *serviceName, const char *regType, const char *domain, const resolveCallback &callback);

using queryCallback = std::function<void(const std::optional<IPAddress> &)>;

void queryIPv6Address(const char *hostName, const queryCallback &callback);

void queryIPv4Address(const char *hostName, const queryCallback &callback);

#endif //KNOTDNSSD_H
