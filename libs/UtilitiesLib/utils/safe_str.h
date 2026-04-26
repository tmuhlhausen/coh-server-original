#ifndef SAFE_STR_H
#define SAFE_STR_H

#include <stddef.h>
#include "stdtypes.h"
#include "network/net_typedefs.h"

C_DECLARATIONS_BEGIN

// Returns 0 on success, 1 if truncated, -1 for invalid input.
int copy_checked(char *dst, size_t dst_size, const char *src);

// Returns number of chars written on success, -1 for formatting error/invalid input, -2 if truncated.
int format_checked(char *dst, size_t dst_size, FORMAT fmt, ...);

// Reads a packet string and copies it into dst with bounds checking.
// Returns same status values as copy_checked.
int pkt_string_copy_checked(char *dst, size_t dst_size, Packet *pak);

C_DECLARATIONS_END

#endif
