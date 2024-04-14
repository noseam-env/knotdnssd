/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/README.md
 */

#if defined(USE_BONJOUR)

#include "knot/dnssd.h"
#include "dns_sd.h"
#include <functional> // function
#include <string> // string
#include "util.h"

#if !defined(_WIN32)
#include <sys/select.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

const char* knotdnssd_bonjour_error_to_str(DNSServiceErrorType error) {
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

void knotdnssd_bonjour_loop(DNSServiceRef sdRef, const std::function<bool()>& isStopped) {
    int fd = DNSServiceRefSockFD(sdRef);
    if (fd == -1) {
        fprintf(stderr, "Couldn't ref sock fd\n");
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
                    fprintf(stderr, "DNSServiceProcessResult failed with error: %s\n", DNSServiceErrorToString(err));
                    break;
                }
            }
        } else if (nfds < 0) {
            fprintf(stderr, "Error occurred in select\n");
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
                fprintf(stderr, "DNSServiceProcessResult failed with error: %s\n", knotdnssd_bonjour_error_to_str(err));
                break;
            }
        } else {
            break;
        }
    }
#endif
}

void knotdnssd_bonjour_serialize_txt_rec(TXTRecordRef &txtRecord, const std::unordered_map<std::string, std::string> &txt) {
    for (const auto &pair : txt) {
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
    knotdnssd_bonjour_serialize_txt_rec(txtRecord, txt);
    DNSServiceErrorType err = DNSServiceRegister(&sdRef, 0, kDNSServiceInterfaceIndexAny,
                                                 serviceName, regType, domain,
                                                 nullptr,
                                                 htons(port),
                                                 TXTRecordGetLength(&txtRecord),TXTRecordGetBytesPtr(&txtRecord),
                                                 nullptr, nullptr);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceRegister failed with error: %s\n", knotdnssd_bonjour_error_to_str(err));
    } else {
        knotdnssd_bonjour_loop(sdRef, isStopped);
    }
    DNSServiceRefDeallocate(sdRef);
    TXTRecordDeallocate(&txtRecord);
}

void DNSSD_API knotdnssd_bonjour_browse_reply(
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
        fprintf(stderr, "knotdnssd_bonjour_browse_reply failed with error: %s\n", knotdnssd_bonjour_error_to_str(errorCode));
        return;
    }
    const browseCallback& callback = *static_cast<browseCallback*>(context);
    callback({serviceName, regType, replyDomain});
}

void browseServices(const char* regType, const char* domain, const browseCallback& callback,
                 const std::function<bool()>& isStopped) {
    void *callbackPtr = static_cast<void *>(const_cast<browseCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceBrowse(&sdRef, 0, kDNSServiceInterfaceIndexAny,
                                               regType, domain,
                                               knotdnssd_bonjour_browse_reply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceBrowse failed with error: %s\n", knotdnssd_bonjour_error_to_str(err));
    } else {
        knotdnssd_bonjour_loop(sdRef, isStopped);
    }
    DNSServiceRefDeallocate(sdRef);
}

std::unordered_map<std::string, std::string> knotdnssd_bonjour_parse_txt_rec(const std::string &txtRecord) {
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

void DNSSD_API knotdnssd_bonjour_resolve_reply(
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
        fprintf(stderr, "knotdnssd_bonjour_resolve_reply failed with error: %s\n", knotdnssd_bonjour_error_to_str(errorCode));
        callback(std::nullopt);
        return;
    }
    std::string txtString(reinterpret_cast<const char *>(txtRecord), txtLen);
    if (!txtString.empty()) {
        txtString = txtString.substr(1);
    }
    auto txt = knotdnssd_bonjour_parse_txt_rec(txtString);
    callback({{hostTarget, std::nullopt, htons(port), txt}});
}

void resolveService(const char *serviceName, const char *regType, const char *domain,
                    const resolveCallback &callback) {
    void *callbackPtr = static_cast<void *>(const_cast<resolveCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceResolve(&sdRef, 0, kDNSServiceInterfaceIndexAny,
                                                serviceName, regType, domain,
                                                knotdnssd_bonjour_resolve_reply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceResolve failed with error: %s\n", knotdnssd_bonjour_error_to_str(err));
    } else {
        DNSServiceProcessResult(sdRef);
    }
    DNSServiceRefDeallocate(sdRef);
}

void DNSSD_API knotdnssd_bonjour_query_reply(
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
        fprintf(stderr, "knotdnssd_bonjour_query_reply failed with error: %s\n", knotdnssd_bonjour_error_to_str(errorCode));
        callback(std::nullopt);
        return;
    }
    if (rdlen != 4 && rdlen != 16) {
        fprintf(stderr, "knotdnssd_bonjour_query_reply received invalid address\n");
        callback(std::nullopt);
    }
    const char* stringAddress = knotdnssd_parse_inet_addr(rdlen, rdata);
    if (stringAddress == nullptr) {
        callback(std::nullopt);
    }
    callback({{rdlen == 16 ? IPv6 : IPv4, std::string(stringAddress)}});
}

void queryIPv6Address(const char *hostName, const queryCallback &callback) {
    void *callbackPtr = static_cast<void *>(const_cast<queryCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceQueryRecord(&sdRef, 0, kDNSServiceInterfaceIndexAny, hostName,
                                                    kDNSServiceType_AAAA, kDNSServiceClass_IN,
                                                    knotdnssd_bonjour_query_reply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceQueryRecord failed with error: %s\n", knotdnssd_bonjour_error_to_str(err));
    } else {
        DNSServiceProcessResult(sdRef);
    }
    DNSServiceRefDeallocate(sdRef);
}

void queryIPv4Address(const char *hostName, const queryCallback &callback) {
    void *callbackPtr = static_cast<void *>(const_cast<queryCallback *>(&callback));
    DNSServiceRef sdRef;
    DNSServiceErrorType err = DNSServiceQueryRecord(&sdRef, 0, kDNSServiceInterfaceIndexAny, hostName,
                                                    kDNSServiceType_A, kDNSServiceClass_IN,
                                                    knotdnssd_bonjour_query_reply, callbackPtr);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceQueryRecord failed with error: %s\n", knotdnssd_bonjour_error_to_str(err));
    } else {
        DNSServiceProcessResult(sdRef);
    }
    DNSServiceRefDeallocate(sdRef);
}

#endif  // USE_BONJOUR
