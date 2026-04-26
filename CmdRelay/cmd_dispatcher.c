#include "cmd_dispatcher.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

#define MAX_TYPED_ARGS 64
#define MAX_TYPED_CMDLINE 10000

static BOOL containsControlChars(const char *s)
{
	for (; *s; ++s)
	{
		unsigned char c = (unsigned char)*s;
		if (c < 32 && c != '\t')
			return TRUE;
	}
	return FALSE;
}

static void setError(char *errorMsg, int errorMsgSize, const char *msg)
{
	if (!errorMsg || errorMsgSize <= 0)
		return;
	strncpyt(errorMsg, msg, errorMsgSize);
}

static BOOL shouldQuoteArg(const char *arg)
{
	return !arg[0] || strpbrk(arg, " \t\"") != 0;
}

static BOOL appendChar(char *out, int outSize, int *pos, char c)
{
	if (*pos + 1 >= outSize)
		return FALSE;
	out[(*pos)++] = c;
	out[*pos] = 0;
	return TRUE;
}

static BOOL appendText(char *out, int outSize, int *pos, const char *text)
{
	while (*text)
	{
		if (!appendChar(out, outSize, pos, *text++))
			return FALSE;
	}
	return TRUE;
}

static BOOL appendEscapedArg(char *out, int outSize, int *pos, const char *arg)
{
	int slashCount = 0;
	const char *p;
	BOOL quote = shouldQuoteArg(arg);

	if (!quote)
		return appendText(out, outSize, pos, arg);

	if (!appendChar(out, outSize, pos, '"'))
		return FALSE;

	for (p = arg; *p; ++p)
	{
		if (*p == '\\')
		{
			++slashCount;
			continue;
		}

		if (*p == '"')
		{
			while (slashCount-- >= 0)
			{
				if (!appendChar(out, outSize, pos, '\\'))
					return FALSE;
			}
			if (!appendChar(out, outSize, pos, '"'))
				return FALSE;
			slashCount = 0;
			continue;
		}

		while (slashCount-- > 0)
		{
			if (!appendChar(out, outSize, pos, '\\'))
				return FALSE;
		}
		slashCount = 0;
		if (!appendChar(out, outSize, pos, *p))
			return FALSE;
	}

	while (slashCount-- > 0)
	{
		if (!appendChar(out, outSize, pos, '\\'))
			return FALSE;
		if (!appendChar(out, outSize, pos, '\\'))
			return FALSE;
	}

	if (!appendChar(out, outSize, pos, '"'))
		return FALSE;
	return TRUE;
}

BOOL BuildWindowsCommandLine(const char *const *argv, int argc, char *out, int outSize)
{
	int i;
	int pos = 0;
	if (!out || outSize <= 0 || !argv || argc <= 0)
		return FALSE;
	out[0] = 0;

	for (i = 0; i < argc; ++i)
	{
		if (i > 0 && !appendChar(out, outSize, &pos, ' '))
			return FALSE;
		if (!appendEscapedArg(out, outSize, &pos, argv[i]))
			return FALSE;
	}

	return TRUE;
}

BOOL DispatchTypedCustomCommand(const char *commandStr, char *errorMsg, int errorMsgSize)
{
	char local[MAX_TYPED_CMDLINE];
	char *argv[MAX_TYPED_ARGS];
	int argc;
	char *cursor = 0;
	int i;
	const char *processArgv[MAX_TYPED_ARGS];

	if (!commandStr || !commandStr[0])
	{
		setError(errorMsg, errorMsgSize, "Empty typed command string");
		return FALSE;
	}
	if (containsControlChars(commandStr))
	{
		setError(errorMsg, errorMsgSize, "Typed command contains invalid control characters");
		return FALSE;
	}

	strncpyt(local, commandStr, sizeof(local));
	argc = tokenize_line_quoted_safe(local, argv, ARRAY_SIZE(argv), &cursor);
	if (argc < 2 || stricmp(argv[0], "exec") != 0)
	{
		setError(errorMsg, errorMsgSize, "Typed command format: exec <executable> [args...]");
		return FALSE;
	}

	for (i = 1; i < argc; ++i)
		processArgv[i - 1] = argv[i];

	if (!BuildWindowsCommandLine(processArgv, argc - 1, local, sizeof(local)))
	{
		setError(errorMsg, errorMsgSize, "Typed command is too long");
		return FALSE;
	}

	if (!strstr(processArgv[0], ".exe") && !strstr(processArgv[0], ".bat") && !strstr(processArgv[0], ".cmd"))
	{
		setError(errorMsg, errorMsgSize, "Typed command executable must end in .exe, .bat, or .cmd");
		return FALSE;
	}

	return TRUE;
}

BOOL ValidateLegacyCommandStrict(const char *commandStr, char *errorMsg, int errorMsgSize)
{
	const char *s;
	if (!commandStr || !commandStr[0])
	{
		setError(errorMsg, errorMsgSize, "Empty command string");
		return FALSE;
	}

	if (containsControlChars(commandStr))
	{
		setError(errorMsg, errorMsgSize, "Legacy command contains control characters");
		return FALSE;
	}

	for (s = commandStr; *s; ++s)
	{
		if (strchr("&|<>%!`", *s))
		{
			if (s == commandStr || *(s - 1) != '^')
			{
				setError(errorMsg, errorMsgSize, "Legacy command requires '^' escaping for shell metacharacters (&|<>%!`)");
				return FALSE;
			}
		}
	}

	return TRUE;
}
