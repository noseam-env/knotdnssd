/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/README.md
 */

#ifndef KNOTDNSSD_H
#define KNOTDNSSD_H

#include <string>
#include <atomic>
#include <functional>
#include <optional>
#include <unordered_map>

template <typename Signature>
using Fn = std::function<Signature>;

void registerService(const char* serviceName, const char* regType, const char* domain, unsigned short port, const std::unordered_map<std::string, std::string>& txt, const Fn<bool()> &isStopped);

struct BrowseReply {
    const char* serviceName;
    const char* regType;
    const char* replyDomain;
};

using browseCallback = Fn<void(const BrowseReply &)>;

void browseServices(const char* regType, const char* domain, const browseCallback& callback, const Fn<bool()>& isStopped);

using FindReply = BrowseReply;
using findCallback = Fn<void(const FindReply &)>;
static void findService(const char* regType, const char* domain, const findCallback& callback, const Fn<bool()>& isStopped) {
    browseServices(regType, domain, callback, isStopped);
}

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

using resolveCallback = Fn<void(const std::optional<ResolveReply> &)>;

void resolveService(const char* serviceName, const char* regType, const char* domain, const resolveCallback& callback);

using queryCallback = Fn<void(const std::optional<IPAddress>&)>;

void queryIPv6Address(const char* hostName, const queryCallback& callback);

void queryIPv4Address(const char* hostName, const queryCallback& callback);

#endif //KNOTDNSSD_H
