#pragma once

/**
 * @file
 * @private
 * @description Internal endian helper header
 */

#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#define le32toh(x) OSSwapLittleToHostInt32 (x)
#define be32toh(x) OSSwapBigToHostInt32 (x)
#elif __has_include(<endian.h>)
#include <endian.h>
#else
#include <winsock.h>
#undef NOMINMAX

// msvc - convert x as BE to HE, then swap (x -> BE -> LE)
#define le32toh(x) (uint32_t{_byteswap_ulong(ntohl(x))})
#define be32toh(x) (uint32_t{ntohl(x)})
#endif
