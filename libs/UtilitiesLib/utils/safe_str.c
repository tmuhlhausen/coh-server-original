#include "safe_str.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "network/net_packet_common.h"

int copy_checked(char *dst, size_t dst_size, const char *src)
{
	size_t src_len;

	if (!dst || dst_size == 0 || !src)
		return -1;

	src_len = strlen(src);
	if (src_len >= dst_size)
	{
		memcpy(dst, src, dst_size - 1);
		dst[dst_size - 1] = '\0';
		return 1;
	}

	memcpy(dst, src, src_len + 1);
	return 0;
}

int format_checked(char *dst, size_t dst_size, FORMAT fmt, ...)
{
	int written;
	va_list ap;

	if (!dst || dst_size == 0 || !fmt)
		return -1;

	va_start(ap, fmt);
	written = _vsnprintf(dst, dst_size, fmt, ap);
	va_end(ap);

	if (written < 0 || (size_t)written >= dst_size)
	{
		dst[dst_size - 1] = '\0';
		return -2;
	}

	return written;
}

int pkt_string_copy_checked(char *dst, size_t dst_size, Packet *pak)
{
	if (!pak)
		return -1;

	return copy_checked(dst, dst_size, pktGetString(pak));
}
