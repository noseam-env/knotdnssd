/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL
 */

#if defined(USE_BONJOUR)

#include "knot/dnssd.h"
#include "dns_sd.h"
#include <functional> // function
#include <iostream> // print
#include <string> // string
#include "util.h"

#if !defined(_WIN32)
#include <sys/select.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

std::string DNSServiceErrorToString(DNSServiceErrorType error) {
    switch (error) {
        default: return "Unrecognized error code";
        case kDNSServiceErr_NoError: return "NoError";
        case kDNSServiceErr_Unknown: return "Unknown";
        case kDNSServiceErr_NoSuchName: return "NoSuchName";
        case kDNSServiceErr_NoMemory: return "NoMemory";
        case kDNSServiceErr_BadParam: return "BadParam";
        case kDNSServiceErr_BadReference: return "BadReference";
        case kDNSServiceErr_BadState: return "BadState";
        case kDNSServiceErr_BadFlags: return "BadFlags";
        case kDNSServiceErr_Unsupported: return "Unsupported";
        case kDNSServiceErr_NotInitialized: return "NotInitialized";
        case kDNSServiceErr_AlreadyRegistered: return "AlreadyRegistered";
        case kDNSServiceErr_NameConflict: return "NameConflict";
        case kDNSServiceErr_Invalid: return "Invalid";
        case kDNSServiceErr_Firewall: return "Firewall";
        case kDNSServiceErr_Incompatible: return "Incompatible";
        case kDNSServiceErr_BadInterfaceIndex: return "BadInterfaceIndex";
        case kDNSServiceErr_Refused: return "Refused";
        case kDNSServiceErr_NoSuchRecord: return "NoSuchRecord";
        case kDNSServiceErr_NoAuth: return "NoAuth";
        case kDNSServiceErr_NoSuchKey: return "NoSuchKey";
        case kDNSServiceErr_NATTraversal: return "NATTraversal";
        case kDNSServiceErr_DoubleNAT: return "DoubleNAT";
        case kDNSServiceErr_BadTime: return "BadTime";
#if !defined(AVAHI_BONJOUR)
        case kDNSServiceErr_BadSig: return "BadSig";
        case kDNSServiceErr_BadKey: return "BadKey";
        case kDNSServiceErr_Transient: return "Transient";
        case kDNSServiceErr_ServiceNotRunning: return "ServiceNotRunning";
        case kDNSServiceErr_NATPortMappingUnsupported: return "NATPortMappingUnsupported";
        case kDNSServiceErr_NATPortMappingDisabled: return "NATPortMappingDisabled";
        case kDNSServiceErr_NoRouter: return "NoRouter";
        case kDNSServiceErr_PollingMode: return "PollingMode";
        case kDNSServiceErr_Timeout: return "Timeout";
#endif
    }
}

void loop(DNSServiceRef sdRef, const std::function<bool()>& isStopped) {
    int fd = DNSServiceRefSockFD(sdRef);
    if (fd == -1) {
        std::cerr << "Couldn't ref sock fd" << std::endl;
        return;
    }
#if defined(AVAHI_BONJOUR)
    while (!isStopped()) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(fd, &readFds);

        struct timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int nfds = select(fd + 1, &readFds, nullptr, nullptr, &timeout);
        if (nfds > 0) {
            if (FD_ISSET(fd, &readFds)) {
                DNSServiceErrorType err = DNSServiceProcessResult(sdRef);
                if (err != kDNSServiceErr_NoError) {
                    std::cerr << "DNSServiceProcessResult failed with error: " << DNSServiceErrorToString(err) << std::endl;
                    break;
                }
            }
        } else if (nfds < 0) {
            std::cerr << "Error occurred in select" << std::endl;
            break;
        }

        sleep(1);
    }
#else
    while (!isStopped()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        int nfds = select(fd + 1, &fds, nullptr, nullptr, nullptr);
        if (nfds > 0) {
            DNSServiceErrorType err = DNSServiceProcessResult(sdRef);
            if (err != kDNSServiceErr_NoError) {
                std::cerr << "DNSServiceProcessResult failed with error: " << DNSServiceErrorToString(err) << std::endl;
                break;
            }
        } else {
            break;
        }
    }
#endif
}

void serializeToTXTRecord(TXTRecordRef &txtRecord, const std::unordered_map<std::string, std::string> &txt) {
    for (const auto &pair: txt) {
        std::string key = pair.first;
        std::string value = pair.second;
        TXTRecordSetValue(&txtRecord, key.c_str(), static_cast<uint8_t>(value.length()), value.c_str());
    }
}

void registerService(const char *serviceName, const char *regType, const char *domain, unsigned short port,
                     const std::unordered_map<std::string, std::string> &txt, const std::function<bool()> &isStopped) {
    DNSServiceRef sdRef;
    TXTRecordRef txtRecord;
    TXTRecordCreate(&txtRecord, 0, nullptr);
    serializeToTXTRecord(txtRecord, txt);
    DNSServiceErrorType err = DNSServiceRegister(&sdRef, 0, kDNSServiceInterfaceIndexAny,
                                                 serviceName, regType, domain,
                                                 nullptr,
                                                 htons(port),
                                                 TXTRecordGetLength(&txtRecord),TXTRecordGetBytesPtr(&txtRecord),
                                                 nullptr, nullptr);
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "DNSServiceRegister failed with error: " << DNSServiceErrorToString(err) << std::endl;
    } else {
        loop(sdRef, isStopped);
    }
    DNSServiceRefDeallocate(sdRef);
    TXTRecordDeallocate(&txtRecord);
}

void DNSSD_API dnssdBrowseReply(
        DNSServiceRef,
        DNSServiceFlags,
        uint32_t,
        DNSServiceErrorType errorCode,
        const char *serviceName,
        const char *regType,
        const char *replyDomain,
        void *context
) {
    if (errorCode != kDNSServiceErr_NoError) {
        std::cerr << "dnssdBrowseReply failed with error: " << DNSServiceErrorToString(errorCode) << std::endl;
        return;
    }
    const findCallback &callback = *static_cast<findCallback *>(context);
    callback({serviceName, regType, replyDomain});
}

void findService(const char *regType, const char *domain, const findCallback &callback,
                 const std::function<bool()> &isStopped) {
    void *callbackPtr = static_cast<void *>(const_cast<findCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceBrowse(&sdRef, 0, kDNSServiceInterfaceIndexAny,
                                               regType, domain,
                                               dnssdBrowseReply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "DNSServiceBrowse failed with error: " << DNSServiceErrorToString(err) << std::endl;
    } else {
        loop(sdRef, isStopped);
    }
    DNSServiceRefDeallocate(sdRef);
}

std::unordered_map<std::string, std::string> parseTXTRecord(const std::string &txtRecord) {
    std::unordered_map<std::string, std::string> txt;

    size_t startPos = 0;
    size_t endPos = txtRecord.find('\x05');

    while (endPos != std::string::npos) {
        std::string pair = txtRecord.substr(startPos, endPos - startPos);
        size_t equalPos = pair.find('=');
        if (equalPos != std::string::npos) {
            std::string key = pair.substr(0, equalPos);
            std::string value = pair.substr(equalPos + 1);
            txt.emplace(key, value);
        }
        startPos = endPos + 1;
        endPos = txtRecord.find('\x05', startPos);
    }

    std::string pair = txtRecord.substr(startPos);
    size_t equalPos = pair.find('=');
    if (equalPos != std::string::npos) {
        std::string key = pair.substr(0, equalPos);
        std::string value = pair.substr(equalPos + 1);
        txt.emplace(key, value);
    }

    return txt;
}

void DNSSD_API dnssdResolveReply(
        DNSServiceRef,
        DNSServiceFlags,
        uint32_t,
        DNSServiceErrorType errorCode,
        const char *,
        const char *hostTarget,
        uint16_t port,
        uint16_t txtLen,
        const unsigned char *txtRecord,
        void *context
) {
    const resolveCallback &callback = *static_cast<resolveCallback *>(context);
    if (errorCode != kDNSServiceErr_NoError) {
        std::cerr << "dnssdResolveReply failed with error: " << DNSServiceErrorToString(errorCode) << std::endl;
        callback(std::nullopt);
        return;
    }
    std::string txtString(reinterpret_cast<const char *>(txtRecord), txtLen);
    if (!txtString.empty()) {
        txtString = txtString.substr(1);
    }
    auto txt = parseTXTRecord(txtString);
    callback({{hostTarget, std::nullopt, htons(port), txt}});
}

void resolveService(const char *serviceName, const char *regType, const char *domain,
                    const resolveCallback &callback) {
    void *callbackPtr = static_cast<void *>(const_cast<resolveCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceResolve(&sdRef, 0, kDNSServiceInterfaceIndexAny,
                                                serviceName, regType, domain,
                                                dnssdResolveReply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "DNSServiceResolve failed with error: " << DNSServiceErrorToString(err) << std::endl;
    } else {
        DNSServiceProcessResult(sdRef);
    }
    DNSServiceRefDeallocate(sdRef);
}

void DNSSD_API dnssdQueryReply(
        DNSServiceRef                       sdRef,
        DNSServiceFlags                     flags,
        uint32_t                            interfaceIndex,
        DNSServiceErrorType                 errorCode,
        const char                          *fullname,
        uint16_t                            rrtype,
        uint16_t                            rrclass,
        uint16_t                            rdlen,
        const void                          *rdata,
        uint32_t                            ttl,
        void                                *context
) {
    const queryCallback &callback = *static_cast<queryCallback *>(context);
    if (errorCode != kDNSServiceErr_NoError) {
        std::cerr << "dnssdQueryReply failed with error: " << DNSServiceErrorToString(errorCode) << std::endl;
        callback(std::nullopt);
        return;
    }
    if (rdlen != 4 && rdlen != 16) {
        std::cerr << "dnssdQueryReply received invalid address" << std::endl;
        callback(std::nullopt);
    }
    std::string stringAddress = parseInetAddress(rdlen, rdata);
    if (stringAddress.empty()) {
        callback(std::nullopt);
    }
    callback({{rdlen == 16 ? IPv6 : IPv4, stringAddress}});
}

void queryIPv6Address(const char *hostName, const queryCallback &callback) {
    void *callbackPtr = static_cast<void *>(const_cast<queryCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceQueryRecord(&sdRef, 0, kDNSServiceInterfaceIndexAny, hostName,
                          kDNSServiceType_AAAA, kDNSServiceClass_IN, dnssdQueryReply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "DNSServiceQueryRecord failed with error: " << DNSServiceErrorToString(err) << std::endl;
    } else {
        DNSServiceProcessResult(sdRef);
    }
    DNSServiceRefDeallocate(sdRef);
}

void queryIPv4Address(const char *hostName, const queryCallback &callback) {
    void *callbackPtr = static_cast<void *>(const_cast<queryCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceQueryRecord(&sdRef, 0, kDNSServiceInterfaceIndexAny, hostName,
                                                    kDNSServiceType_A, kDNSServiceClass_IN, dnssdQueryReply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        std::cerr << "DNSServiceQueryRecord failed with error: " << DNSServiceErrorToString(err) << std::endl;
    } else {
        DNSServiceProcessResult(sdRef);
    }
    DNSServiceRefDeallocate(sdRef);
}

#endif  // USE_BONJOUR
