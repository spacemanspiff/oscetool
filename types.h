#ifndef _TYPES_H_
#define _TYPES_H_

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#	if !defined(WIN32_LEAN_AND_MEAN)
#		define WIN32_LEAN_AND_MEAN
#	endif
#	include <windows.h>
#	include <io.h>
#
#	define snprintf _snprintf
#	define fileno _fileno
#	define strncasecmp strnicmp
#else
#	include <unistd.h>
#	include <sys/mman.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>

#if !defined(MAX_PATH)
#	define MAX_PATH 260
#endif

#ifdef min
#	undef min
#endif
#ifdef max
#	undef max
#endif

#define ES16(_val) \
	((uint16_t)(((((uint16_t)_val) & 0xff00) >> 8) | \
	       ((((uint16_t)_val) & 0x00ff) << 8)))

#define ES32(_val) \
	((uint32_t)(((((uint32_t)_val) & 0xff000000) >> 24) | \
	       ((((uint32_t)_val) & 0x00ff0000) >> 8 ) | \
	       ((((uint32_t)_val) & 0x0000ff00) << 8 ) | \
	       ((((uint32_t)_val) & 0x000000ff) << 24)))

#define ES64(_val) \
	((uint64_t)(((((uint64_t)_val) & 0xff00000000000000ull) >> 56) | \
	       ((((uint64_t)_val) & 0x00ff000000000000ull) >> 40) | \
	       ((((uint64_t)_val) & 0x0000ff0000000000ull) >> 24) | \
	       ((((uint64_t)_val) & 0x000000ff00000000ull) >> 8 ) | \
	       ((((uint64_t)_val) & 0x00000000ff000000ull) << 8 ) | \
	       ((((uint64_t)_val) & 0x0000000000ff0000ull) << 24) | \
	       ((((uint64_t)_val) & 0x000000000000ff00ull) << 40) | \
	       ((((uint64_t)_val) & 0x00000000000000ffull) << 56)))

#define countof(_array) (sizeof(_array) / sizeof(_array[0]))
#define offsetof(_type, _member) ((size_t)((char *)&((_type *)0)->_member - (char *)0))

#define min(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define max(_a, _b) ((_a) > (_b) ? (_a) : (_b))

#endif /* !_TYPES_H_ */
