#include "cmd_dispatcher.h"
#include <stdio.h>
#include <string.h>

static unsigned int s_rand = 0xC0DEF00Du;
static unsigned int fuzzRand(void)
{
	s_rand = s_rand * 1103515245u + 12345u;
	return s_rand;
}

static void makeRandomArg(char *out, int outSize)
{
	static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-./\\\"&|<>%!`^";
	int len = (int)(fuzzRand() % (unsigned int)(outSize - 1));
	int i;
	for (i = 0; i < len; ++i)
		out[i] = charset[fuzzRand() % (sizeof(charset) - 1)];
	out[len] = 0;
}

int CmdRelay_RunDispatcherFuzzTests(int iterations)
{
	int i;
	int failures = 0;
	for (i = 0; i < iterations; ++i)
	{
		char arg1[64];
		char arg2[64];
		char command[256];
		char error[256];
		const char *argv[3];
		char cmdline[512];

		makeRandomArg(arg1, sizeof(arg1));
		makeRandomArg(arg2, sizeof(arg2));

		argv[0] = "tool.exe";
		argv[1] = arg1;
		argv[2] = arg2;
		if (!BuildWindowsCommandLine(argv, 3, cmdline, sizeof(cmdline)))
			++failures;

		snprintf(command, sizeof(command), "exec tool.exe \"%s\" \"%s\"", arg1, arg2);
		if (!DispatchTypedCustomCommand(command, error, sizeof(error)) && !strstr(error, "too long"))
			++failures;

		if (!ValidateLegacyCommandStrict("dir ^& echo ok", error, sizeof(error)))
			++failures;
		if (ValidateLegacyCommandStrict("dir & echo notok", error, sizeof(error)))
			++failures;
	}

	printf("CmdRelay fuzz tests complete: iterations=%d failures=%d\n", iterations, failures);
	return failures;
}

#ifdef CMDRELAY_ENABLE_FUZZ_TEST_MAIN
int main(void)
{
	return CmdRelay_RunDispatcherFuzzTests(5000) ? 1 : 0;
}
#endif
