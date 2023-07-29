/*
 * This file is part of libknotdnssd.
 *
 * For license and copyright information please follow this link:
 * https://github.com/noseam-env/libknotdnssd/blob/master/LEGAL
 */
#pragma once

#include <string>
#include "cstdint"

std::string parseInetAddress(uint16_t rdlen, const void *rdata);
