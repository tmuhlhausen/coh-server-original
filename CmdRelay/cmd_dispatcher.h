#ifndef CMD_DISPATCHER_H
#define CMD_DISPATCHER_H

#include "stdtypes.h"

BOOL DispatchTypedCustomCommand(const char *commandStr, char *errorMsg, int errorMsgSize);
BOOL ValidateLegacyCommandStrict(const char *commandStr, char *errorMsg, int errorMsgSize);
BOOL BuildWindowsCommandLine(const char *const *argv, int argc, char *out, int outSize);

#endif
