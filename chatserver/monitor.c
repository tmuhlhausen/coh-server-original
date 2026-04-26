#include "monitor.h"
#include "chatMonitor.h"
#include "error.h"
#include "comm_backend.h"
#include "timing.h"
#include "net_linklist.h"
#include "chatdb.h"
#include "reserved_names.h"
#include "shardnet.h"
#include "csr.h"
#include "performance.h"
#include "users.h"
#include "log.h"
#include "chatsqldb.h"
#include "crypt.h"
#include "packet_schema_validation.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

NetLinkList	monitor_links;
extern NetLinkList	net_links;

#define MONITOR_ROLE_NONE		0
#define MONITOR_ROLE_READONLY	1
#define MONITOR_ROLE_PRIVILEGED 2

#define MONITOR_RATE_WINDOW_SECONDS	10
#define MONITOR_RATE_LIMIT_SENSITIVE	8
static U32 s_monitor_packet_rejects = 0;

static int monitorValidateSchemaString(const char *value, const PacketSchemaStringDesc *desc, const char *context)
{
	if (packetSchemaValidateString(value, desc))
		return 1;

	++s_monitor_packet_rejects;
	LOG_OLD_ERR("security.packet_reject subsystem=chat_monitor context=%s field=%s max_len=%d charset=%d rejects=%u\n",
		context ? context : "unknown",
		desc && desc->field_name ? desc->field_name : "unknown",
		desc ? desc->max_len : -1,
		desc ? desc->charset : -1,
		s_monitor_packet_rejects);
	return 0;
}

static void monitorDropLink(NetLink *link, const char *reason)
{
	LOG_OLD_ERR("monitor_security: dropping %s:%d (%s)\n", makeIpStr(link->addr.sin_addr.S_un.S_addr), link->addr.sin_port, reason);
	lnkBatchSend(link);
	netRemoveLink(link);
}

static int monitorCommandRequiresPrivilege(int cmd)
{
	switch(cmd)
	{
		xcase SVRMONTOCHATSVR_ADMIN_SENDALL:
		xcase SVRMONTOCHATSVR_SHUTDOWN:
			return 1;
	}
	return 0;
}

static int monitorRateLimitCommand(MonitorLink *client, int cmd)
{
	int now = timerSecondsSince2000();
	int sensitive = monitorCommandRequiresPrivilege(cmd);

	if (!sensitive)
		return 1;

	if (now - client->rate_window_start > MONITOR_RATE_WINDOW_SECONDS)
	{
		client->rate_window_start = now;
		client->sensitive_cmd_count = 0;
	}

	client->sensitive_cmd_count++;
	if (client->sensitive_cmd_count > MONITOR_RATE_LIMIT_SENSITIVE)
		return 0;

	return 1;
}

static int monitorValidateHandshakeMac(NetLink *link, int protocol, int role, U32 nonce, const char *provided_hex)
{
	static const char *secret_name = "CHATMON_SHARED_SECRET";
	U32 mac_words[5];
	U32 parsed_words[5];
	char msg[256];
	const char *secret = getenv(secret_name);
	HMAC_SHA1_Handle hmac;
	char *endptr = NULL;
	int i;
	U32 mismatch = 0;

	if (!secret || !secret[0] || !provided_hex)
		return 0;
	if (strlen(provided_hex) != 40)
		return 0;

	for (i = 0; i < 5; ++i)
	{
		char chunk[9];
		memcpy(chunk, provided_hex + (i * 8), 8);
		chunk[8] = 0;
		parsed_words[i] = strtoul(chunk, &endptr, 16);
		if (!endptr || *endptr)
			return 0;
	}

	sprintf_s(msg, sizeof(msg), "CHATMON|%d|%u|%d|%u", protocol, nonce, role, link->addr.sin_addr.S_un.S_addr);
	hmac = cryptHMAC_SHA1Create((const U8*)secret, (int)strlen(secret));
	if (!hmac)
		return 0;
	cryptHMAC_SHA1Update(hmac, (const U8*)msg, (int)strlen(msg));
	cryptHMAC_SHA1Final(hmac, mac_words);
	cryptHMAC_SHA1Destroy(hmac);

	for (i = 0; i < 5; ++i)
		mismatch |= (mac_words[i] ^ parsed_words[i]);

	return mismatch == 0;
}

int monitorCreateCb(NetLink *link)
{
	MonitorLink	*client = link->userData;

	client->link = link;
	client->authenticated = 0;
	client->role = MONITOR_ROLE_NONE;
	client->session_nonce = 0;
	client->rate_window_start = timerSecondsSince2000();
	client->sensitive_cmd_count = 0;
	client->audit_denied_count = 0;
	netLinkSetMaxBufferSize(link, BothBuffers, 8*1024*1024); // Set max size to auto-grow to
	netLinkSetBufferSize(link, BothBuffers, 1*1024*1024);

	return 1;
}

int monitorDeleteCb(NetLink *link)
{
	return 1;
}


int handleMonitorMsg(Packet *pak,int cmd, NetLink *link)
{
	MonitorLink *client = link->userData;

	if (!client)
	{
		monitorDropLink(link, "missing monitor session state");
		return 0;
	}

	if (cmd != SVRMONTOCHATSVR_CONNECT && !client->authenticated)
	{
		LOG_OLD_ERR("monitor_security: rejected unauthenticated cmd=%d from %s:%d\n", cmd, makeIpStr(link->addr.sin_addr.S_un.S_addr), link->addr.sin_port);
		monitorDropLink(link, "unauthenticated monitor command");
		return 0;
	}

	if (!monitorRateLimitCommand(client, cmd))
	{
		LOG_OLD_ERR("monitor_security: rate-limited cmd=%d from %s:%d\n", cmd, makeIpStr(link->addr.sin_addr.S_un.S_addr), link->addr.sin_port);
		monitorDropLink(link, "sensitive monitor command rate limit exceeded");
		return 0;
	}

	switch(cmd)
	{
		xcase SVRMONTOCHATSVR_CONNECT:
			{
				static const PacketSchemaStringDesc handshakeMacSchema = { "handshake_mac", 40, PACKET_SCHEMA_CHARSET_ASCII_PRINTABLE, 0 };
 				int protocol = pktGetBits(pak, 32);
				U32 nonce = pktGetBits(pak, 32);
				int role = pktGetBitsPack(pak, 2);
				const char *mac_hex = pktGetString(pak);
				if (!monitorValidateSchemaString(mac_hex, &handshakeMacSchema, "connect"))
				{
					monitorDropLink(link, "invalid handshake schema");
					return 0;
				}
 				if(protocol != CHATMON_PROTOCOL_VERSION)
				{
					Packet * pkt2 = pktCreateEx(link, CHATMON_PROTOCOL_MISMATCH);
					pktSendBits(pkt2, 32, CHATMON_PROTOCOL_VERSION);
					pktSend(&pkt2, link);
					monitorDropLink(link, "protocol mismatch");
					return 0;
				}

				if (role != MONITOR_ROLE_READONLY && role != MONITOR_ROLE_PRIVILEGED)
				{
					monitorDropLink(link, "invalid monitor role");
					return 0;
				}

				if (!monitorValidateHandshakeMac(link, protocol, role, nonce, mac_hex))
				{
					monitorDropLink(link, "integrity/authentication check failed");
					return 0;
				}

				client->authenticated = 1;
				client->role = role;
				client->session_nonce = nonce;
			}
			break;
		xcase SVRMONTOCHATSVR_ADMIN_SENDALL:
			{
				static const PacketSchemaStringDesc broadcastSchema = { "broadcast_message", 1024, PACKET_SCHEMA_CHARSET_ASCII_PRINTABLE, 0 };
				const char *broadcast = 0;
				if (client->role != MONITOR_ROLE_PRIVILEGED)
				{
					client->audit_denied_count++;
					LOG_OLD_ERR("monitor_security: denied broadcast cmd from %s:%d role=%d denied_count=%d\n", makeIpStr(link->addr.sin_addr.S_un.S_addr), link->addr.sin_port, client->role, client->audit_denied_count);
					monitorDropLink(link, "unauthorized broadcast command");
					return 0;
				}
				broadcast = pktGetString(pak);
				if (!monitorValidateSchemaString(broadcast, &broadcastSchema, "admin_sendall"))
				{
					monitorDropLink(link, "invalid broadcast schema");
					return 0;
				}
				csrSendAllAnon((char*)broadcast);
			}
			break;
		xcase SVRMONTOCHATSVR_SHUTDOWN:
			{
				static const PacketSchemaStringDesc shutdownReasonSchema = { "shutdown_reason", 256, PACKET_SCHEMA_CHARSET_ASCII_PRINTABLE, 1 };
				const char *shutdownReason = 0;
				if (client->role != MONITOR_ROLE_PRIVILEGED)
				{
					client->audit_denied_count++;
					LOG_OLD_ERR("monitor_security: denied shutdown cmd from %s:%d role=%d denied_count=%d\n", makeIpStr(link->addr.sin_addr.S_un.S_addr), link->addr.sin_port, client->role, client->audit_denied_count);
					monitorDropLink(link, "unauthorized shutdown command");
					return 0;
				}
				shutdownReason = pktGetString(pak);
				if (!monitorValidateSchemaString(shutdownReason, &shutdownReasonSchema, "shutdown"))
				{
					monitorDropLink(link, "invalid shutdown schema");
					return 0;
				}
				chatServerShutdown(0,(char*)shutdownReason);
			}
			break;
		default:
			LOG_OLD_ERR("monitor_errs: Unknown command %d\n",cmd);
			monitorDropLink(link, "unknown command");
			return 0;
	}

	return 1;
}

void chatMonitorInit()
{
	netLinkListAlloc(&monitor_links,10,sizeof(MonitorLink),monitorCreateCb);
	netInit(&monitor_links,0,DEFAULT_CHATMON_PORT);
	monitor_links.destroyCallback = monitorDeleteCb;
	NMAddLinkList(&monitor_links, handleMonitorMsg);
}

void sendStatus(NetLink * link_out)
{	
	int i;
	MEMORYSTATUSEX memoryStatus;
	
	Packet * pak = pktCreateEx(link_out, CHATMON_STATUS);

	pktSendBitsPack(pak, 1, chatUserGetCount());
	pktSendBitsPack(pak, 1, chatChannelGetCount());
	pktSendBitsPack(pak, 1, g_online_count);
	pktSendBitsPack(pak, 1, GetReservedNameCount());


	pktSendF32(pak, g_stats.crossShardRate);
	pktSendF32(pak, g_stats.invalidRate);
	
	pktSendBitsPack(pak, 1, g_stats.send_rate);
	pktSendBitsPack(pak, 1, g_stats.recv_rate);

	pktSendBitsPack(pak, 1, g_stats.sendMsgRate);
	pktSendBitsPack(pak, 1, g_stats.recvMsgRate);

	pktSendBitsPack(pak, 1, monitor_links.links->size);

	// indiv link info
	pktSendBitsPack(pak, 1, net_links.links->size);
	for(i=0; i<net_links.links->size; i++)
	{
		NetLink * link = net_links.links->storage[i];
		ClientLink * client = (ClientLink*)link->userData;
		
		pktSendBitsPack(pak, 1, link->addr.sin_addr.S_un.S_addr);
		pktSendBitsPack(pak, 1, (client->linkType == kChatLink_Shard));

		pktSendBitsPack(pak, 1, client->online);
		pktSendString(pak, client->shard_name);

		pktSendBitsPack(pak, 1, pktRate(&link->sendHistory)>>10);
 		pktSendBitsPack(pak, 1, pktRate(&link->recvHistory)>>10);

//		pktSendBitsPack(pak, 1, client->sendMsgRate);
//		pktSendBitsPack(pak, 1, client->recvMsgRate);
	}

	// Send total memory usage numbers
	ZeroMemory(&memoryStatus,sizeof(MEMORYSTATUSEX));
	memoryStatus.dwLength = sizeof(MEMORYSTATUSEX);

	GlobalMemoryStatusEx(&memoryStatus);
	pktSendBits(pak, 32, memoryStatus.ullTotalPhys>>10);
	pktSendBits(pak, 32, memoryStatus.ullAvailPhys>>10);
	pktSendBits(pak, 32, memoryStatus.ullTotalPageFile>>10);
	pktSendBits(pak, 32, memoryStatus.ullAvailPageFile>>10);
//	pktSendBitsPack(pak, 2, num_processors);

	perfSendTrackedInfo(pak);

	pktSend(&pak, link_out);
}

void monitorTick()
{
	static int timer=0;
	static int lock=0;

	if (lock)
		return;
	lock++;

	if (timer==0) {
		timer = timerAlloc();
	}
	if (timerElapsed(timer) > 2.f) {
		timerStart(timer);
		
		perfGetList(); // should move up outside of for-loop
		netForEachLink(&monitor_links, sendStatus);
	}
	lock--;
}
