/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/README.md
 */

#ifndef KNOTDNSSD_UTIL_H
#define KNOTDNSSD_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

const char* knotdnssd_parse_inet_addr(uint16_t rdlen, const void* rdata);

#ifdef __cplusplus
} // extern "C"
#endif

#endif //KNOTDNSSD_UTIL_H
