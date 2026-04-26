#ifndef MONITOR_H__
#define MONITOR_H__

#include "netio.h"


typedef struct
{
	NetLink	*link;
	int		authenticated;
	int		role;
	U32		session_nonce;
	int		rate_window_start;
	int		sensitive_cmd_count;
	int		audit_denied_count;

} MonitorLink;

extern NetLinkList monitor_links;

void chatMonitorInit();
void monitorTick();

#endif  // MONITOR_H__
