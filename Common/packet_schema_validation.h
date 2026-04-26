#ifndef PACKET_SCHEMA_VALIDATION_H
#define PACKET_SCHEMA_VALIDATION_H

#include <string.h>
#include <ctype.h>
#include "stdtypes.h"
#include "utils.h"

typedef enum PacketSchemaCharsetPolicy
{
	PACKET_SCHEMA_CHARSET_ANY = 0,
	PACKET_SCHEMA_CHARSET_ASCII_PRINTABLE = 1,
	PACKET_SCHEMA_CHARSET_ASCII_NO_QUOTES = 2,
} PacketSchemaCharsetPolicy;

typedef struct PacketSchemaStringDesc
{
	const char *field_name;
	int max_len;
	PacketSchemaCharsetPolicy charset;
	int allow_empty;
} PacketSchemaStringDesc;

static INLINEDBG int packetSchemaStringAllowedChar(unsigned char c, PacketSchemaCharsetPolicy charset)
{
	switch (charset)
	{
		xcase PACKET_SCHEMA_CHARSET_ANY:
			return 1;
		xcase PACKET_SCHEMA_CHARSET_ASCII_PRINTABLE:
			return (c >= 32 && c <= 126);
		xcase PACKET_SCHEMA_CHARSET_ASCII_NO_QUOTES:
			return (c >= 32 && c <= 126 && c != '\'' && c != '"');
	}
	return 0;
}

static INLINEDBG int packetSchemaValidateString(const char *value, const PacketSchemaStringDesc *desc)
{
	int i;
	int len;

	if (!value || !desc)
		return 0;

	len = (int)strlen(value);
	if (!desc->allow_empty && len == 0)
		return 0;

	if (desc->max_len > 0 && len > desc->max_len)
		return 0;

	for (i = 0; i < len; ++i)
	{
		if (!packetSchemaStringAllowedChar((unsigned char)value[i], desc->charset))
			return 0;
	}

	return 1;
}

#endif
