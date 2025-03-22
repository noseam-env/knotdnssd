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

#if defined(_WIN32)
#  define KNOTDNSSD_DLL_EXPORT __declspec(dllexport)
#  define KNOTDNSSD_DLL_IMPORT __declspec(dllimport)
#else
#  define KNOTDNSSD_DLL_EXPORT __attribute__((visibility("default")))
#  define KNOTDNSSD_DLL_IMPORT __attribute__((visibility("default")))
#endif

#if defined(KNOTDNSSD_IMPLEMENTATION)
#  define KNOTDNSSD_EXPORT KNOTDNSSD_DLL_EXPORT
#else
#  define KNOTDNSSD_EXPORT KNOTDNSSD_DLL_IMPORT
#endif

namespace knot {

enum IPFamily : uint8_t {
    IPv4 = 0,
    IPv6 = 1,
};

struct IPAddress {
    IPFamily family = IPv4;
    std::string value;
};

struct BrowseReply {
    const char* serviceName;
    const char* regType;
    const char* replyDomain;
};

struct ResolveReply {
    std::optional<std::string> hostName;
    std::optional<IPAddress> ip;
    uint16_t port = 0;
    std::unordered_map<std::string, std::string> txt;
};

template<typename Signature>
using Fn = std::function<Signature>;
using BrowseCallback = Fn<void(const BrowseReply&)>;
using ResolveCallback = Fn<void(const std::optional<ResolveReply>&)>;
using QueryCallback = Fn<void(const std::optional<IPAddress>&)>;

/// blocking operation
KNOTDNSSD_EXPORT
void registerService(const char* serviceName, const char* regType, const char* domain, uint16_t port, const std::unordered_map<std::string, std::string>& txt, const Fn<bool()>& isStopped);

/// blocking operation
KNOTDNSSD_EXPORT
void browseServices(const char* regType, const char* domain, const BrowseCallback& callback, const Fn<bool()>& isStopped);

/// blocking operation
KNOTDNSSD_EXPORT
void resolveService(const char* serviceName, const char* regType, const char* domain, const ResolveCallback& callback);

KNOTDNSSD_EXPORT
void queryIPv6Address(const char* hostName, const QueryCallback& callback);

KNOTDNSSD_EXPORT
void queryIPv4Address(const char* hostName, const QueryCallback& callback);

}

#endif //KNOTDNSSD_H
