#include "wininclude.h"
#include "serverMonitorListener.h"
#include "comm_backend.h"
#include "sock.h"
#include <process.h>
#include <stdio.h>
#include "serverMonitor.h"
#include "processMonitor.h"
#include "utils.h"
#include "serverMonitorNet.h"
#include "serverMonitorCmdRelay.h"
#include "chatMonitor.h"
#include <time.h>


static bool g_listenThreadRunning=false;
static bool g_listenThreadStarting=false;
static bool g_commandThreadRunning=false;
static bool g_commandThreadStarting=false;
static CRITICAL_SECTION g_listenThreadCS;
static CRITICAL_SECTION g_commandThreadCS;
ServerStats g_currentStats, g_currentStats_commandThread;
HWND g_mainDlg = NULL;

void sendint(SOCKET s, const char * n, int i)
{
	char buf[32];
	sprintf(buf, "%s:%d ", n, i);
	send(s, buf, (int)strlen(buf), 0);
}

void sendfloat(SOCKET s, const char * n, float f)
{
	char buf[32];
	sprintf(buf, "%s:%f ", n, f);
	send(s, buf, (int)strlen(buf), 0);
}

static DWORD WINAPI listenThreadMain(void *data) {
	struct sockaddr_in	addr_in;
	int port=DEFAULT_SVRMON_LISTEN_PORT;
	int result;
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	SOCKET s2;
	g_listenThreadRunning=true;

	sockSetAddr(&addr_in,htonl(INADDR_ANY),port);
	if (!sockBind(s,&addr_in)) {
		g_listenThreadRunning=false;
		g_listenThreadStarting=false;
		// Error binding to port!
		MessageBox(NULL, "Error binding to port, perhaps another ServerMonitor is running?\r\nThis ServerMonitor will not monitor processes, start new processes or do CmdRelay.", "Error binding to port", MB_OK|MB_ICONERROR);
		return 0;
	}
	g_listenThreadStarting=false;
	result = listen(s, 15);
	if(result)
	{
		// Intentionally left this running so we don't get a large number of threads spiraling out of control
		MessageBox(NULL, "Error returned from listen(), SNMP-like stuff is now disabled", "Error", MB_OK|MB_ICONERROR);
		return 0;
	}
	do {
		struct linger l = {1, 15};
		ServerStats stats;

		s2 = accept(s, NULL, NULL);
		if (s2==INVALID_SOCKET)
			continue;

		setsockopt(s2, SOL_SOCKET, SO_LINGER, (char*)&l, sizeof(l));

		// copy the stats to a local var so don't block main thread on next copy
		EnterCriticalSection(&g_listenThreadCS);
		memcpy( &stats, &g_currentStats, sizeof(ServerStats) );
		LeaveCriticalSection(&g_listenThreadCS);

		sendint(s2, "dbok", !stats.dbserver_in_trouble);
		if(!stats.dbserver_in_trouble)
		{
			sendint(s2, "msok", !stats.servers_in_trouble);
			sendint(s2, "msbad", stats.servers_in_trouble);
			sendint(s2, "pcount", stats.pcount);
			sendint(s2, "mscount", stats.mscount);
			sendint(s2, "pcount_connecting", stats.pcount_connecting);
			sendint(s2, "pcount_queued", stats.pcount_queued);
			sendint(s2, "pcount_login", stats.pcount_login);
			sendint(s2, "queue_connections", stats.queue_connections);
			sendint(s2, "ecount", stats.ecount);
			sendint(s2, "mcount", stats.mcount);
			sendint(s2, "sqlwb", stats.sqlwb);
			sendint(s2, "sqlthroughput", stats.sqlthroughput);
			sendint(s2, "sqlavglat", stats.sqlavglat);
			sendint(s2, "sqlworstlat", stats.sqlworstlat);
			sendfloat(s2, "sqlforeidleratio", stats.sqlforeidleratio);
			sendfloat(s2, "sqlbackidleratio", stats.sqlbackidleratio);
			sendint(s2, "loglat", stats.loglat);
			sendint(s2, "logbytes", stats.logbytes);
			sendint(s2, "logqcnt", stats.logqcnt);
			sendint(s2, "logqmax", stats.logqmax);
			sendint(s2, "logsortmem", stats.logsortmem);
			sendint(s2, "logsortcap", stats.logsortcap);
			sendint(s2, "dbstatok", stats.dbServerMonitor && (stats.dbServerMonitor->status == PMS_RUNNING));
			sendint(s2, "lstatok", stats.launcherMonitor && (stats.launcherMonitor->status == PMS_RUNNING));
			sendint(s2, "max_sec_since_update", stats.maxSecondsSinceUpdate);
			sendint(s2, "max_crashed_maps", stats.maxCrashedMaps);
			sendint(s2, "smscount", stats.smscount);
			sendint(s2, "max_crashed_launchers", stats.maxCrashedLaunchers);
			sendint(s2, "db_sec_since_update", stats.secondsSinceDbUpdate);
			sendint(s2, "arena_sec_since_update", stats.arenaSecSinceUpdate);
			sendint(s2, "stat_sec_since_update", stats.statSecSinceUpdate);
			sendint(s2, "lcount", stats.lcount);
			sendint(s2, "sacount", stats.sacount);
			sendint(s2, "mscount_static", stats.mscount_static);
			sendint(s2, "mscount_missions", stats.mscount_missions);
			sendint(s2, "mscount_base", stats.mscount_base);
			sendint(s2, "sms_crashed_count", stats.sms_crashed_count);
			sendint(s2, "sms_long_tick_count", stats.sms_long_tick_count);
			sendint(s2, "sms_stuck_count", stats.sms_stuck_count);
			sendint(s2, "sms_stuck_starting_count", stats.sms_stuck_starting_count);
			sendint(s2, "sa_crashed_count", stats.sa_crashed_count);
			sendint(s2, "beaconwaitsec", stats.beaconWaitSeconds);
			sendint(s2, "pcount_hero", stats.pcount_hero);
			sendint(s2, "pcount_villain", stats.pcount_villain);
			sendint(s2, "pcount_ents", stats.pcount_ents);
		}
		shutdown(s2, SD_BOTH);
		closesocket(s2);
	} while (1);
	g_listenThreadRunning = false;
	return 0;
}


// Here we convert the incoming command text to the corresponding serverMonitor
//	function call.  This essentially defines the text API for the command port.
typedef enum {
	eCmdID_StartDBserver,
	eCmdID_ShutdownDBserver,
	eCmdID_ConnectChat,
	eCmdID_SendAdminMessage,
	eCmdID_EnableAutoDelink,
	eCmdID_DelinkStuckMS,
	eCmdID_KillLauncher,
	eCmdID_StartLauncher,
	eCmdID_KillMapservers,
	eCmdID_ReloadConfig,
	eCmdID_ResetMissionLink,
	eCmdID_SendOverloadProtection,
	eCmdID_NumCommands,
	eCmdID_Unknown = 0xFFFF
} CommandID;
typedef struct CommandMapping {
	CommandID id;
	const char* text;
} CommandMapping;
static CommandMapping sCommandList[eCmdID_NumCommands] = 
{
	{ eCmdID_StartDBserver,			"start_dbserver"			},
	{ eCmdID_ShutdownDBserver,		"shutdown_dbserver"			},
	{ eCmdID_ConnectChat,			"connect_chat"				},
	{ eCmdID_SendAdminMessage,		"send_admin_message"		},
	{ eCmdID_EnableAutoDelink,		"enable_autodelink"			},
	{ eCmdID_DelinkStuckMS,			"delink_stuck_ms"			},
	{ eCmdID_KillLauncher,			"kill_launcher"				},
	{ eCmdID_StartLauncher,			"start_launcher"			},
	{ eCmdID_KillMapservers,		"kill_mapservers"			},
	{ eCmdID_ReloadConfig,			"reload_config"				},
	{ eCmdID_ResetMissionLink,		"remission_link"			},
	{ eCmdID_SendOverloadProtection,"overload_protection"		},
};

static bool issueCommand(CommandID cmdID, const char* args)
{
	switch( cmdID )
	{
		case eCmdID_StartDBserver:
			cmdRelayCmdToAllClients((ListViewCallbackFunc) onRelayStartDbServer);
			break;
		case eCmdID_ShutdownDBserver:
			svrMonShutdownAll(&g_state, args);
			break;
		case eCmdID_ConnectChat:
			// tbd, optional parameter to specify chatserver ip/address?  For now we assume it is already entered.
			if( !chatMonConnected() ) {
				chatSetAutoConnect(false);
				chatMonConnect();
			}
			break;
		case eCmdID_SendAdminMessage:
			svrMonSendAdminMessage(&g_state, args);
			break;
		case eCmdID_EnableAutoDelink:
			// optional arg, set to 1 to enable, 0 to disable (default)
			svrMonSetAutoDelink(&g_state, atoi(args) != 0, g_mainDlg);
			break;
		case eCmdID_DelinkStuckMS:
			listViewForEach(g_state.lvMapsStuck, smcbMsDelink, &g_state);
			break;
		case eCmdID_KillLauncher:
			cmdRelayCmdToAllClients((ListViewCallbackFunc) onRelayKillAllLauncher);
			break;
		case eCmdID_StartLauncher:
			cmdRelayCmdToAllClients((ListViewCallbackFunc) onRelayStartLauncher);
			break;
		case eCmdID_KillMapservers:
			cmdRelayCmdToAllClients((ListViewCallbackFunc) onRelayKillAllMapserver);
			break;
		case eCmdID_ReloadConfig:
			// TBD - what command is this??
			break;
		case eCmdID_ResetMissionLink:
			svrMonResetMission(&g_state);
			break;
		case eCmdID_SendOverloadProtection:
			svrMonSendOverloadProtection(&g_state, args);
			break;
		case eCmdID_Unknown:
		default:
			return false; // unknown command, shouldn't get here
	}

	return true;
}

// simple linked list of commands, we queue these on the command thread and service on the main thread
typedef struct QueuedCommand {
	CommandID cmdID;
	char* args;
	struct QueuedCommand* next;
} QueuedCommand;
static QueuedCommand* g_commandQueueHead = NULL;

typedef enum CommandRole
{
	eCmdRole_None = 0,
	eCmdRole_Monitor,
	eCmdRole_Admin
} CommandRole;

typedef struct CommandSession
{
	bool authenticated;
	CommandRole role;
	char sessionNonce[64];
} CommandSession;

typedef struct RateLimitEntry
{
	U32 ip;
	int windowStart;
	int attempts;
} RateLimitEntry;

#define MAX_RATE_LIMIT_ENTRIES 128
#define COMMAND_ATTEMPT_WINDOW_SECS 60
#define MAX_PRIVILEGED_ATTEMPTS_PER_WINDOW 20
static RateLimitEntry s_rateLimitEntries[MAX_RATE_LIMIT_ENTRIES];
static int s_rateLimitInitialized = 0;

static U32 fnv1aHashStr(const char *str)
{
	U32 hash = 2166136261U;
	unsigned char c;
	while ((c = (unsigned char)*str++) != 0)
	{
		hash ^= c;
		hash *= 16777619U;
	}
	return hash;
}

static void formatHexU32(char *out, size_t outSize, U32 value)
{
	snprintf(out, outSize, "%08x", value);
}

static CommandRole parseRole(const char *roleText)
{
	if (!roleText || !roleText[0])
		return eCmdRole_None;
	if (!strcmpi(roleText, "admin"))
		return eCmdRole_Admin;
	if (!strcmpi(roleText, "monitor"))
		return eCmdRole_Monitor;
	return eCmdRole_None;
}

static CommandRole getRequiredRoleForCommand(CommandID cmdID)
{
	switch (cmdID)
	{
		case eCmdID_SendAdminMessage:
		case eCmdID_KillLauncher:
		case eCmdID_StartLauncher:
		case eCmdID_KillMapservers:
		case eCmdID_ShutdownDBserver:
		case eCmdID_ResetMissionLink:
			return eCmdRole_Admin;
		case eCmdID_StartDBserver:
		case eCmdID_ConnectChat:
		case eCmdID_EnableAutoDelink:
		case eCmdID_DelinkStuckMS:
		case eCmdID_ReloadConfig:
		case eCmdID_SendOverloadProtection:
			return eCmdRole_Monitor;
		default:
			return eCmdRole_None;
	}
}

static bool roleAllowsCommand(CommandRole callerRole, CommandID cmdID)
{
	CommandRole required = getRequiredRoleForCommand(cmdID);
	return callerRole >= required;
}

static RateLimitEntry* getRateLimitEntry(U32 ip, int now)
{
	int i;
	int openIndex = -1;
	if (!s_rateLimitInitialized)
	{
		memset(s_rateLimitEntries, 0, sizeof(s_rateLimitEntries));
		s_rateLimitInitialized = 1;
	}

	for (i = 0; i < MAX_RATE_LIMIT_ENTRIES; ++i)
	{
		if (s_rateLimitEntries[i].ip == ip)
			return &s_rateLimitEntries[i];
		if (openIndex < 0 && s_rateLimitEntries[i].ip == 0)
			openIndex = i;
	}

	if (openIndex < 0)
		openIndex = now % MAX_RATE_LIMIT_ENTRIES;
	s_rateLimitEntries[openIndex].ip = ip;
	s_rateLimitEntries[openIndex].windowStart = now;
	s_rateLimitEntries[openIndex].attempts = 0;
	return &s_rateLimitEntries[openIndex];
}

static bool isRateLimited(U32 ip)
{
	RateLimitEntry *entry;
	int now = (int)time(NULL);
	if (ip == 0)
		return false;

	entry = getRateLimitEntry(ip, now);
	if (now - entry->windowStart >= COMMAND_ATTEMPT_WINDOW_SECS)
	{
		entry->windowStart = now;
		entry->attempts = 0;
	}
	entry->attempts++;
	if (entry->attempts > MAX_PRIVILEGED_ATTEMPTS_PER_WINDOW)
	{
		printf("ALERT: Rate limit exceeded for privileged command attempts from ip=%u (attempts=%d window=%ds)\n",
			ip, entry->attempts, COMMAND_ATTEMPT_WINDOW_SECS);
		return true;
	}
	return false;
}

static bool verifySignedText(const char *text, const char *sigHex)
{
	char signedInput[2048];
	char expectedSig[16];
	const char *secret = getenv("SVRMON_CMD_SECRET");
	U32 hash;

	if (!secret || !secret[0] || !text || !sigHex || !sigHex[0])
		return false;

	snprintf(signedInput, sizeof(signedInput), "%s|%s", secret, text);
	hash = fnv1aHashStr(signedInput);
	formatHexU32(expectedSig, sizeof(expectedSig), hash);
	return (strcmpi(expectedSig, sigHex) == 0);
}

static bool authenticateSession(const char *args, CommandSession *session, SOCKET s, U32 sourceIp)
{
	char roleText[64] = {0};
	char nonce[64] = {0};
	char sigHex[64] = {0};
	long ts = 0;
	char signedText[256];
	int skew;
	char response[256];

	if (!args || sscanf(args, "%63s %ld %63s %63s", roleText, &ts, nonce, sigHex) != 4)
	{
		snprintf(response, sizeof(response), "ERROR: auth_session invalid args\n");
		send(s, response, (int)strlen(response), 0);
		return false;
	}

	skew = abs((int)(time(NULL) - ts));
	if (skew > 300)
	{
		snprintf(response, sizeof(response), "ERROR: auth_session rejected due to timestamp skew (%d)\n", skew);
		send(s, response, (int)strlen(response), 0);
		return false;
	}

	snprintf(signedText, sizeof(signedText), "auth|%s|%ld|%s", roleText, ts, nonce);
	if (!verifySignedText(signedText, sigHex))
	{
		snprintf(response, sizeof(response), "ERROR: auth_session bad signature\n");
		send(s, response, (int)strlen(response), 0);
		printf("ALERT: Signature verification failed during auth_session from ip=%u\n", sourceIp);
		return false;
	}

	session->role = parseRole(roleText);
	if (session->role == eCmdRole_None)
	{
		snprintf(response, sizeof(response), "ERROR: auth_session invalid role\n");
		send(s, response, (int)strlen(response), 0);
		return false;
	}
	session->authenticated = true;
	strncpy(session->sessionNonce, nonce, sizeof(session->sessionNonce));
	session->sessionNonce[sizeof(session->sessionNonce) - 1] = 0;
	snprintf(response, sizeof(response), "SUCCESS: authenticated role=%s\n", roleText);
	send(s, response, (int)strlen(response), 0);
	return true;
}

static QueuedCommand* queueCommand(char* buf, SOCKET s, ServerStats* pCurStats, CommandSession *session, U32 sourceIp)
{
	// We only accept a single argument (space separated), anything after the first arg is
	//	considered all one string.
	int len, i;
	CommandID cmdID = eCmdID_Unknown;
	QueuedCommand* pcmd;
	char response[1024];
	char *pCmdText = buf;
	char* pArgs = strchr(buf, ' ');
	char* pSig = NULL;
	char signedText[2048];
	if(pArgs) {
		*pArgs = 0; // null terminate command
		pArgs++;
	} else {
		pArgs = ""; // svrMonSendDbMessage requires to pass empty sring for args, not null
	}
	pSig = strstr(pArgs, " sig=");

	if (!session->authenticated)
	{
		snprintf(response, sizeof(response), "ERROR: command rejected; auth_session required first\n");
		send(s, response, (int)strlen(response), 0);
		printf("ALERT: Unauthenticated privileged command attempt from ip=%u cmd=%s\n", sourceIp, pCmdText);
		return NULL;
	}

	if (!pSig)
	{
		snprintf(response, sizeof(response), "ERROR: command rejected; missing signature\n");
		send(s, response, (int)strlen(response), 0);
		printf("ALERT: Unsigned privileged command attempt from ip=%u cmd=%s\n", sourceIp, pCmdText);
		return NULL;
	}

	*pSig = 0;
	pSig += 5; // skip " sig="
	snprintf(signedText, sizeof(signedText), "%s|%s|%s", session->sessionNonce, pCmdText, pArgs);
	if (!verifySignedText(signedText, pSig))
	{
		snprintf(response, sizeof(response), "ERROR: command rejected; signature invalid\n");
		send(s, response, (int)strlen(response), 0);
		printf("ALERT: Bad command signature from ip=%u cmd=%s\n", sourceIp, pCmdText);
		return NULL;
	}

	for(i=0; i<eCmdID_NumCommands; i++)
	{
		if( !strcmpi(sCommandList[i].text, pCmdText) )
		{
			cmdID = sCommandList[i].id;
			break;
		}
	}

	// create the command if successful, send a response for each command on success or failure
	if( cmdID != eCmdID_Unknown )
	{
		char extraInfo[1024];
		if (!roleAllowsCommand(session->role, cmdID))
		{
			snprintf(response, sizeof(response), "ERROR: role is not authorized for command \"%s\"\n", pCmdText);
			send(s, response, (int)strlen(response), 0);
			printf("ALERT: Unauthorized role attempt from ip=%u cmd=%s role=%d\n", sourceIp, pCmdText, session->role);
			return NULL;
		}

		// add command to our linked list of queued commands
		len = sizeof(QueuedCommand) + (int)strlen(pArgs) + 1;
		pcmd = (QueuedCommand*)malloc(len);
		pcmd->cmdID = cmdID;
		pcmd->next = NULL;
		pcmd->args = (char*)(pcmd + 1);
		strcpy(pcmd->args, pArgs);

		// add any command-specific details we want to send back to caller
		switch(cmdID) // pCurStats
		{
			case eCmdID_SendAdminMessage:
				snprintf(extraInfo, sizeof(extraInfo), " - \"%s\"", pcmd->args );
				break;
			case eCmdID_EnableAutoDelink:
				// optional arg, set to 1 to enable, 0 to disable (default)
				snprintf(extraInfo, sizeof(extraInfo), " - autolink set to %s", (atoi(pcmd->args) != 0) ? "ON":"OFF" );
				break;
			case eCmdID_DelinkStuckMS:
				snprintf(extraInfo, sizeof(extraInfo), " - delinking %d stuck MS", pCurStats->sms_stuck_count );
				break;
			case eCmdID_KillMapservers:
				snprintf(extraInfo, sizeof(extraInfo), " - killing %d MS", pCurStats->mscount );
				break;
			case eCmdID_SendOverloadProtection:
				snprintf(extraInfo, sizeof(extraInfo), " - \"%s\"", pcmd->args );
				break;
			case eCmdID_Unknown:
			default:
				extraInfo[0] = 0;
		}

		snprintf(response, sizeof(response), "SUCCESS: queued command \"%s\"%s\n", pCmdText, extraInfo);
	}
	else
	{
		pcmd = NULL;
		snprintf(response, sizeof(response), "ERROR: unknown command string \"%s\"\n", pCmdText);
	}
	send(s, response, (int)strlen(response), 0);

	return pcmd;
}

#define MAX_CMD_LEN 2048
static DWORD WINAPI commandThreadMain(void *data)
{
	struct sockaddr_in	addr_in;
	int port=DEFAULT_SVRMON_COMMAND_PORT;
	int result;
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	g_commandThreadRunning=true;

	sockSetAddr(&addr_in,htonl(INADDR_ANY),port);
	if (!sockBind(s,&addr_in)) {
		g_commandThreadRunning=false;
		g_commandThreadStarting=false;
		// Error binding to port!
		MessageBox(NULL, "Error binding to port, perhaps another ServerMonitor is running?\r\nThis ServerMonitor will not accept connectionless commands.", "Error binding to port", MB_OK|MB_ICONERROR);
		return 0;
	}
	g_commandThreadStarting=false;
	result = listen(s, 15);
	if(result)
	{
		// Intentionally left this running so we don't get a large number of threads spiraling out of control
		MessageBox(NULL, "Error returned from listen(), command port will be disabled", "Error", MB_OK|MB_ICONERROR);
		return 0;
	}

	do {
		SOCKET s2;
		struct linger l = {1, 15};
		struct sockaddr_in remoteAddr;
		int remoteLen = sizeof(remoteAddr);
		U32 sourceIp = 0;
		int total_read = 0, cur_cmd_read = 0;
		char buf[MAX_CMD_LEN+1], *cur_cmd_buf;
		QueuedCommand* pCommandsThisMessage_Head = NULL, *pCommandsThisMessage_Tail = NULL;
		ServerStats curStats;
		CommandSession session = {0};

		s2 = accept(s, (struct sockaddr*)&remoteAddr, &remoteLen);
		if (s2==INVALID_SOCKET)
			continue;
		sourceIp = ntohl(remoteAddr.sin_addr.S_un.S_addr);

		EnterCriticalSection(&g_commandThreadCS);
		memcpy( &curStats, &g_currentStats_commandThread, sizeof(ServerStats) ); // copy to local var for use below
		LeaveCriticalSection(&g_commandThreadCS);
		
		setsockopt(s2, SOL_SOCKET, SO_LINGER, (char*)&l, sizeof(l));

		cur_cmd_buf = &buf[0];
		while(total_read < MAX_CMD_LEN)
		{
			// read one char at a time so we can process multiple commands (";" is expected
			//	at end of each command, even if only a single command is sent).
			int bytes_read = recv(s2, &cur_cmd_buf[cur_cmd_read], 1, 0);
			if( bytes_read == SOCKET_ERROR || bytes_read == 0)
				break;

			// ignore any newline characters, to work better with netcap type utilities
			if( cur_cmd_buf[cur_cmd_read] == '\n' || cur_cmd_buf[cur_cmd_read] == '\r' )
				continue;

			total_read += bytes_read;

			// check to see if this character is a command terminator
			#define COMMAND_TERMINATOR_CHAR  ';'
			if( cur_cmd_buf[cur_cmd_read] == COMMAND_TERMINATOR_CHAR)
			{
				cur_cmd_buf[cur_cmd_read] = 0; // null terminate command string
				
				if( strlen(cur_cmd_buf) == 0 )
				{
					// this command is empty, indicates end of command string.  We allow
					//	multiple commands in one string, so ";;" is required at the end
					//	of each command string.
					break;
				}
				else
				{
					// create command and store in local queue (will move to master queue after get all 
					//	commands in this message)
					if (isRateLimited(sourceIp))
					{
						const char *rateLimitedResp = "ERROR: command rejected; rate limit exceeded\n";
						send(s2, rateLimitedResp, (int)strlen(rateLimitedResp), 0);
						pCommandsThisMessage_Head = NULL;
						pCommandsThisMessage_Tail = NULL;
						break;
					}

					if (!strnicmp(cur_cmd_buf, "auth_session ", 13))
					{
						authenticateSession(cur_cmd_buf + 13, &session, s2, sourceIp);
						cur_cmd_buf = &buf[total_read];
						cur_cmd_read = 0;
						continue;
					}

					QueuedCommand* pcmd = queueCommand(cur_cmd_buf, s2, &curStats, &session, sourceIp);
					if(pcmd) {
						if( !pCommandsThisMessage_Head ) {
							pCommandsThisMessage_Head = pCommandsThisMessage_Tail = pcmd;
						} else {
							pCommandsThisMessage_Tail->next = pcmd;
							pCommandsThisMessage_Tail = pcmd;
						}
					}
					cur_cmd_buf = &buf[total_read];
					cur_cmd_read = 0;
					continue;
				}
			}

			cur_cmd_read += bytes_read;			
		}
		
		shutdown(s2, SD_SEND);
		while( recv(s2, &buf[0], MAX_CMD_LEN, 0) >= 1); // read all remaining data to make for a clean shutdown

		closesocket(s2);

		// add local command list to the end of the master list 
		//	(shared with main thread so lock it)
		EnterCriticalSection(&g_commandThreadCS);
		if( !g_commandQueueHead ) {
			g_commandQueueHead = pCommandsThisMessage_Head;
		} else {
			QueuedCommand* plastCmd = g_commandQueueHead;
			while(plastCmd->next != NULL)
				plastCmd = plastCmd->next;
			plastCmd->next = pCommandsThisMessage_Head;
		}
		LeaveCriticalSection(&g_commandThreadCS);

	} while (1);
	g_commandThreadRunning = false;
	return 0;
}

static void processCommands(void)
{
	QueuedCommand *pCurCmd, *pNextCmd;

	if( !g_commandThreadRunning )
		return;

	// snag command queue, then service it without blocking command thread
	EnterCriticalSection(&g_commandThreadCS);
	memcpy( &g_currentStats_commandThread, &g_state.stats, sizeof(ServerStats) ); // so we can give intelligent feedback on command response
	pCurCmd = g_commandQueueHead;
	g_commandQueueHead = NULL;
	LeaveCriticalSection(&g_commandThreadCS);

	while( pCurCmd )
	{
		pNextCmd = pCurCmd->next;
		issueCommand(pCurCmd->cmdID, pCurCmd->args);
		free(pCurCmd);
		pCurCmd = pNextCmd;
	}
}

void serverMonitorListenSetMainDlg(HWND dlg)
{
	g_mainDlg = dlg;
}

void serverMonitorListenThreadBegin(void)
{
	int ret;
	if (g_listenThreadRunning) {
		//printf("Thread already running\n");
		return;
	}
	sockStart();

	InitializeCriticalSection( &g_listenThreadCS );
	InitializeCriticalSection( &g_commandThreadCS );

	// listen thread is for cacti requests
	g_listenThreadRunning = true;
	g_listenThreadStarting = true;
	ret = _beginthreadex(NULL, 0, listenThreadMain, NULL, 0, NULL);
	while (g_listenThreadStarting)
		Sleep(1);

	// command thread is for connectionless command requests from scripts
	g_commandThreadRunning = true;
	g_commandThreadStarting = true;
	ret = _beginthreadex(NULL, 0, commandThreadMain, NULL, 0, NULL);
	while (g_commandThreadStarting)
		Sleep(1);

	if (!g_listenThreadRunning && !g_commandThreadRunning) {
		g_primaryServerMonitor=false;
	}
}

void serverMonitorListenTick(void)
{
	if( g_primaryServerMonitor )
	{
		// make local copy of stats for listen thread to use
		EnterCriticalSection(&g_listenThreadCS);
		memcpy( &g_currentStats, &g_state.stats, sizeof(ServerStats) );
		LeaveCriticalSection(&g_listenThreadCS);

		// process any queued commands
		processCommands();
	}
}
