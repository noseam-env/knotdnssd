/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL
 */

#if defined(USE_AVAHI)

#include "knot/dnssd.h"

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <iostream>
#include <netinet/in.h>

void loop(AvahiSimplePoll *poll, const std::function<bool()> &isStopped) {
    while (!isStopped()) {
        avahi_simple_poll_iterate(poll, 100);
    }
}

static AvahiStringList *create_avahi_txt(const std::unordered_map<std::string, std::string>& txt) {
    AvahiStringList *txt_list = nullptr;
    for (const auto& pair : txt) {
        const std::string& key = pair.first;
        const std::string& value = pair.second;
        txt_list = avahi_string_list_add_pair(txt_list, key.c_str(), value.c_str());
    }
    return txt_list;
}

struct RegisterContext {
    AvahiSimplePoll *poll;
    AvahiEntryGroup *group;
    const char *serviceName;
    const char *regType;
    const char *domain;
    unsigned short port;
    const std::unordered_map<std::string, std::string>& txt;
};

void client_callback(
        AvahiClient *client,
        AvahiClientState state,
        void* userdata
) {
    auto *context = static_cast<RegisterContext *>(userdata);

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            if (!context->group) {
                context->group = avahi_entry_group_new(client, nullptr, nullptr);

                AvahiStringList *txt_list = create_avahi_txt(context->txt);
                avahi_entry_group_add_service(context->group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AvahiPublishFlags(0), context->serviceName, context->regType, context->domain, nullptr, htons(context->port), txt_list);
                avahi_string_list_free(txt_list);
                avahi_entry_group_commit(context->group);
            }

            break;

        case AVAHI_CLIENT_FAILURE:
            fprintf(stderr, "Client failure: %s\n", avahi_strerror(avahi_client_errno(client)));
            avahi_simple_poll_quit(context->poll);

            break;

        case AVAHI_CLIENT_S_COLLISION:

            /* Let's drop our registered services. When the server is back
             * in AVAHI_SERVER_RUNNING state we will register them
             * again with the new host name. */

        case AVAHI_CLIENT_S_REGISTERING:

            /* The server records are now being established. This
             * might be caused by a host name change. We need to wait
             * for our own records to register until the host name is
             * properly esatblished. */

            /*if (group)
                avahi_entry_group_reset(group);*/

            break;

        case AVAHI_CLIENT_CONNECTING:
            ;
    }
}

void registerService(const char *serviceName, const char *regType, const char *domain, unsigned short port, const std::unordered_map<std::string, std::string>& txt, const Fn<bool()> &isStopped) {
    AvahiSimplePoll *poll;
    char *name = nullptr;
    RegisterContext *context = nullptr;
    AvahiClient *client = nullptr;
    int error;

    if (!(poll = avahi_simple_poll_new())) {
        std::cerr << "Failed to create simple poll object." << std::endl;
        goto fail;
    }

    name = avahi_strdup(serviceName);

    context = new RegisterContext{
        poll,
        nullptr,
        serviceName,
        regType,
        domain,
        port,
        txt
    };

    client = avahi_client_new(avahi_simple_poll_get(poll), AvahiClientFlags(0), client_callback, context, &error);

    if (!client) {
        std::cerr << "Failed to create client: " << avahi_strerror(error) << std::endl;
        goto fail;
    }

    loop(poll, isStopped);

fail:
    if (context && context->group) {
        avahi_entry_group_free(context->group);
    }
    //if (context)
        delete context;
    if (client)
        avahi_client_free(client);
    if (poll)
        avahi_simple_poll_free(poll);
    avahi_free(name);
}

struct BrowseContext {
    AvahiSimplePoll *poll;
    AvahiClient *client;
    const browseCallback &callback;
};

void browse_callback(
        AvahiServiceBrowser *browser,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiBrowserEvent event,
        const char *name,
        const char *type,
        const char *domain,
        AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
        void *userdata
) {
    auto *context = static_cast<BrowseContext *>(userdata);

    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            //fprintf(stderr, "(Browser) %s\n", avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(browser))));
            avahi_simple_poll_quit(context->poll);
            return;

        case AVAHI_BROWSER_NEW:
            //fprintf(stderr, "(Browser) NEW: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
            context->callback({name, type, domain});
            break;

        case AVAHI_BROWSER_REMOVE:
            //fprintf(stderr, "(Browser) REMOVE: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
            break;

        case AVAHI_BROWSER_ALL_FOR_NOW:
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            //fprintf(stderr, "(Browser) %s\n", event == AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
            break;
    }
}

void browseServices(const char *regType, const char *domain, const browseCallback &callback, const Fn<bool()> &isStopped) {
    AvahiSimplePoll *poll;
    AvahiClient *client = nullptr;
    BrowseContext *context = nullptr;
    AvahiServiceBrowser *browser = nullptr;
    int error;

    if (!(poll = avahi_simple_poll_new())) {
        std::cerr << "Failed to create simple poll object." << std::endl;
        goto fail;
    }

    client = avahi_client_new(avahi_simple_poll_get(poll), AvahiClientFlags(0), nullptr, nullptr, &error);
    if (!client) {
        std::cerr << "Failed to create client: " << avahi_strerror(error) << std::endl;
        goto fail;
    }

    context = new BrowseContext{poll, client, callback};

    if (!(browser = avahi_service_browser_new(client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, regType, domain, AvahiLookupFlags(0), browse_callback, context))) {
        std::cerr << "Failed to create service browser: " << std::string(avahi_strerror(avahi_client_errno(client))) << std::endl;
        goto fail;
    }

    loop(poll, isStopped);

fail:
    if (browser)
        avahi_service_browser_free(browser);
    //if (context)
        delete context;
    if (client)
        avahi_client_free(client);
    if (poll)
        avahi_simple_poll_free(poll);
}

void resolve_callback(
    AvahiServiceResolver *resolver,
    AVAHI_GCC_UNUSED AvahiIfIndex interface,
    AVAHI_GCC_UNUSED AvahiProtocol protocol,
    AvahiResolverEvent event,
    const char *name,
    const char *type,
    const char *domain,
    const char *host_name,
    const AvahiAddress *address,
    uint16_t port,
    AvahiStringList *txt,
    AvahiLookupResultFlags flags,
    AVAHI_GCC_UNUSED void *userdata
) {
    assert(resolver);

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(resolver))));
            break;

        case AVAHI_RESOLVER_FOUND: {
            char a[AVAHI_ADDRESS_STR_MAX], *t;

            fprintf(stderr, "Service '%s' of type '%s' in domain '%s':\n", name, type, domain);

            avahi_address_snprint(a, sizeof(a), address);
            t = avahi_string_list_to_string(txt);
            fprintf(stderr,
                    "\t%s:%u (%s)\n"
                    "\tTXT=%s\n"
                    "\tcookie is %u\n"
                    "\tis_local: %i\n"
                    "\tour_own: %i\n"
                    "\twide_area: %i\n"
                    "\tmulticast: %i\n"
                    "\tcached: %i\n",
                    host_name, port, a,
                    t,
                    avahi_string_list_get_service_cookie(txt),
                    !!(flags & AVAHI_LOOKUP_RESULT_LOCAL),
                    !!(flags & AVAHI_LOOKUP_RESULT_OUR_OWN),
                    !!(flags & AVAHI_LOOKUP_RESULT_WIDE_AREA),
                    !!(flags & AVAHI_LOOKUP_RESULT_MULTICAST),
                    !!(flags & AVAHI_LOOKUP_RESULT_CACHED));

            avahi_free(t);
        }
    }

    avahi_service_resolver_free(resolver);
}

void resolveService(const char *serviceName, const char *regType, const char *domain, const resolveCallback &callback) {

}

void queryIPv6Address(const char *hostName, const queryCallback &callback) {

}

void queryIPv4Address(const char *hostName, const queryCallback &callback) {

}


#endif  // USE_AVAHI
