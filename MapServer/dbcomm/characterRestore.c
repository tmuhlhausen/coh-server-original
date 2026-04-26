#include <conio.h>
#include <stdio.h>
#include <process.h>
#include <time.h>
#include <errno.h>
#include "utils.h"
#include "EArray.h"
#include "sock.h"
#include "network\netio.h"
#include "net_socket.h"
#include "entity.h"
#include "dbquery.h"
#include "timing.h"
#include "file.h"


static void columnPrintf(int columnWidth, char spacer, const char *str, ...)
{
	char buf[1024];
	int i, len;
	char spacerStr[2] = {spacer, 0};

	va_list arg;
	va_start(arg, str);
	vsprintf(buf, str, arg);
	va_end(arg);

	len = strlen(buf);
	if (len > columnWidth)
		buf[columnWidth] = 0;
	
	printf(buf);

	for (i = len; i < columnWidth; i++)
		printf(spacerStr);
}

static void crErrorMessage(const char *msg)
{
	consoleSetColor(COLOR_RED|COLOR_BRIGHT, 0);
	printf("\n%s\n", msg);
	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
	getch();
}

static int readLine(char* buf, size_t len)
{
	size_t inputLen;

	if (!buf || len == 0)
		return 0;

	if (!fgets(buf, len, stdin))
	{
		buf[0] = 0;
		return 0;
	}

	inputLen = strlen(buf);
	if (inputLen > 0 && buf[inputLen - 1] == '\n')
		buf[inputLen - 1] = 0;
	else
	{
		int c;
		while ((c = fgetc(stdin)) != '\n' && c != EOF) { }
	}

	return 1;
}

static int parseIntInRange(const char *str, int minValue, int maxValue, int *outValue)
{
	char *endPtr;
	long parsed;

	if (!str || !outValue || str[0] == 0)
		return 0;

	errno = 0;
	parsed = strtol(str, &endPtr, 10);
	if (errno != 0 || *endPtr != 0)
		return 0;
	if (parsed < minValue || parsed > maxValue)
		return 0;

	*outValue = (int)parsed;
	return 1;
}


#define FIND_RESULTS_PER_PAGE 10
#define READ_EOF 0x0fffffff

typedef struct
{
	char characterName[128];
	char accountName[128];
	char ipAddress[64];
	struct
	{
		int year;
		int month;
		int day;
		int hours;
		int minutes;
		int seconds;
	} date;
	char *data;
} DeletionHeader;

typedef struct
{
	char *logFilename;
	DeletionHeader **records;
} DeletionLog;

static int crReadLogString(char *string, char *filedata, int filesize, int *fileposition)
{
	int i;
	char c;

	i = 0;
	while (*fileposition < filesize)
	{
		c = filedata[*fileposition];
		(*fileposition)++;
		
		if (c == '\t' || c == '\n')
			break;

		string[i] = c;
		i++;
	}
	string[i] = 0;
	if (*fileposition >= filesize)
		return READ_EOF;

	return c;
}

static int crReadLogString_Alloc(char **string, char *filedata, int filesize, int *fileposition)
{
	int i, startpos = *fileposition;
	char c;

	i = 0;
	while (*fileposition < filesize)
	{
		c = filedata[*fileposition];
		(*fileposition)++;
		
		if (c == '\t' || c == '\n')
			break;

		i++;
	}

	*string = malloc(i+10); // extra in case

	*fileposition = startpos;

	return crReadLogString(*string, filedata, filesize, fileposition);
}

static void crFreeDeletionHeader(DeletionHeader *header)
{
	if (!header)
		return;

	if (header->data)
		free(header->data);

	free(header);
}

static DeletionHeader *crReadDeletionHeader(char *filedata, int filesize, int *fileposition)
{
	char datestr[128];
	char *curstr;
	int ret, i;

	DeletionHeader *header = malloc(sizeof(DeletionHeader));
	header->data = NULL;

	// date
	ret = crReadLogString(datestr, filedata, filesize, fileposition);
	if (ret == '\n' || ret == READ_EOF)
		goto badentry;

	curstr = datestr;

	i = 0;
	while (curstr[i] != '-') i++;
	curstr[i] = 0;
    header->date.month = atoi(curstr);
	curstr += i + 1;

	i = 0;
	while (curstr[i] != '-') i++;
	curstr[i] = 0;
	header->date.day = atoi(curstr);
	curstr += i + 1;

	i = 0;
	while (curstr[i] != ' ') i++;
	curstr[i] = 0;
	header->date.year = atoi(curstr);
	curstr += i + 1;

	i = 0;
	while (curstr[i] != ':') i++;
	curstr[i] = 0;
	header->date.hours = atoi(curstr);
	curstr += i + 1;

	i = 0;
	while (curstr[i] != ':') i++;
	curstr[i] = 0;
	header->date.minutes = atoi(curstr);
	curstr += i + 1;

	header->date.seconds = atoi(curstr);


	// ip
	ret = crReadLogString(header->ipAddress, filedata, filesize, fileposition);
	if (ret == '\n' || ret == READ_EOF)
		goto badentry;


	// account name
	ret = crReadLogString(header->accountName, filedata, filesize, fileposition);
	if (ret == '\n' || ret == READ_EOF)
		goto badentry;


	// character name
	ret = crReadLogString(header->characterName, filedata, filesize, fileposition);
	if (ret == '\n' || ret == READ_EOF)
		goto badentry;


	// data
	ret = crReadLogString_Alloc(&(header->data), filedata, filesize, fileposition);
	if (ret == '\n' || ret == READ_EOF)
		return header;

badentry:
	consoleSetColor(COLOR_RED|COLOR_BRIGHT, 0);
	printf("Bad header found.\n");
	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
	crFreeDeletionHeader(header);
	return NULL;
}

static void crFreeDeletionLog(DeletionLog *log)
{
	int i;

	if (!log)
		return;
	
	if (log->logFilename)
		free(log->logFilename);
	log->logFilename = 0;

	if (log->records)
	{
		for (i = eaSize(&log->records) - 1; i >= 0; i--)
			crFreeDeletionHeader(eaGet(&log->records, i));
			
		eaDestroy(&log->records);
	}

	free(log);
}

static void crPrintHeader(DeletionHeader *header)
{
	columnPrintf(15, ' ', header->accountName);
	columnPrintf(15, ' ', header->characterName);
	columnPrintf(13, ' ', "%02d-%02d-%04d", header->date.month, header->date.day, header->date.year);
	columnPrintf(13, ' ', "%02d:%02d:%02d", header->date.hours, header->date.minutes, header->date.seconds);
	columnPrintf(15, ' ', header->ipAddress);
}

static void crRestoreCharacter(DeletionHeader *header)
{
	int ret;
	char inputLine[100];
	char *filename = "C:/restoretemp.txt";
	FILE *f;
	char *unescapedData;

	printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	consoleSetColor(COLOR_GREEN|COLOR_BRIGHT, 0);
	crPrintHeader(header);
	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
	printf("\n\n\n\n");

	printf("Enter the IP address of the destination DBServer (none to cancel): ");
	readLine(inputLine, sizeof(inputLine));

	if (inputLine[0] == 0)
		return;

	f = fopen(filename, "wt");
	if (f)
	{
		unescapedData = unescapeString(header->data);
		if (!unescapedData)
		{
			consoleSetColor(COLOR_RED|COLOR_BRIGHT, 0);
			printf("Error unescaping character data.\n");
			consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
			ret = 1;
		}
		else
		{
			if (fputs(unescapedData, f) == EOF || ferror(f))
			{
				consoleSetColor(COLOR_RED|COLOR_BRIGHT, 0);
				printf("Error writing restore file '%s'.\n", filename);
				consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
				ret = 1;
			}
			else
				ret = dbQueryPutCharacter(filename);
		}

		fclose(f);
	}
	else
		ret = 1;

	if (ret != 0)
		crErrorMessage("Error restoring character!");
	else
		crErrorMessage("Character restored!");

	unlink(filename);
}

static void crHandleFindResults(DeletionHeader **results)
{
	int start, total, end, i;
	char inputLine[100];

	start = 0;
	total = eaSize(&results);

	if (total == 0)
	{
		crErrorMessage("No matching deletions found!");
		return;
	}

	do
	{
		end = (total > (start + FIND_RESULTS_PER_PAGE)) ? (start + FIND_RESULTS_PER_PAGE) : total;

		consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
		printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
		columnPrintf(80, '-', "---- Find - Page %02d of %02d -", 1+(start / FIND_RESULTS_PER_PAGE), 1+(total/FIND_RESULTS_PER_PAGE));
		printf("\n");
		consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE, 0);
		columnPrintf(5, ' ', "Num");
		columnPrintf(15, ' ', "Auth");
		columnPrintf(15, ' ', "Character");
		columnPrintf(13, ' ', "Date");
		columnPrintf(13, ' ', "Time");
		columnPrintf(15, ' ', "IP");
		consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
		printf("\n");

		for (i = start; i < end ; i++)
		{
			columnPrintf(5, ' ', "%02d. ", i+1);
			crPrintHeader(results[i]);
			printf("\n");
		}

		columnPrintf(80, '-', "");

		printf("\n\nX. Exit\nP. Previous Page\nN. Next Page\n");
		printf("\n\nEnter selection: ");
		readLine(inputLine, sizeof(inputLine));

		if (stricmp(inputLine, "p")==0)
		{
			if (start > 0)
				start -= FIND_RESULTS_PER_PAGE;
		}
		else if (inputLine[0]==0 || stricmp(inputLine, "n")==0)
		{
			if (total > start + FIND_RESULTS_PER_PAGE)
				start += FIND_RESULTS_PER_PAGE;
		}
		else if (stricmp(inputLine, "x")==0)
		{
		}
		else
		{
			int selection = atoi(inputLine);
			if (selection < 1 || selection > total)
			{
				crErrorMessage("Invalid Entry!");
			}
			else
			{
				crRestoreCharacter(results[selection-1]);
			}
		}

	} while(stricmp(inputLine, "x")!=0);
}

static DeletionLog *crOpenDeletionLogByFilename(char *filename)
{
	DeletionLog *log;
	DeletionHeader *header;
	int filesize, fileposition = 0;
	char *filedata;
	char buf[MAX_PATH];
	char fnamePrefix[MAX_PATH];
	int filenum = 1;

	strcpy(fnamePrefix, filename);
	if (strEndsWith(fnamePrefix, ".log.gz"))
		fnamePrefix[strlen(fnamePrefix)-7] = 0;


	filedata = fileAllocEx_dbg(filename, &filesize, "rbz", 0 MEM_DBG_PARMS_INIT);
	if (!filedata)
	{
		consoleSetColor(COLOR_RED|COLOR_BRIGHT, 0);
		printf("Could not open file!\n");
		consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
		return NULL;
	}

	log = malloc(sizeof(DeletionLog));
	log->logFilename = strdup(filename);
	eaCreate(&log->records);

	do
	{
		while (fileposition < filesize)
		{
			header = crReadDeletionHeader(filedata, filesize, &fileposition);
			if (header)
				eaPush(&log->records, header);
		}

		free(filedata);

		// rollover filenames:
		sprintf(buf, "%s_%d.log.gz",fnamePrefix,filenum++);
		filedata = fileAllocEx_dbg(buf, &filesize, "rbz", 0 MEM_DBG_PARMS_INIT);
		fileposition = 0;
	} while (filedata);

	return log;
}

static DeletionLog *crOpenDeletionLog()
{
	char inputLine[MAX_PATH];

	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
//	printf("---- Open ----------------------------------------------\n");
	printf("\n\nEnter deletion log filename (none to cancel): ");
	readLine(inputLine, sizeof(inputLine));
	if (inputLine[0] == 0)
		return NULL;

	return crOpenDeletionLogByFilename(inputLine);
}

static void crFindByAccount(DeletionLog *log)
{
	char inputLine[100];
	DeletionHeader **results;
	int i, size;

	if (!log)
		return;

	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
//	printf("---- Find ----------------------------------------------\n");
	printf("\n\nEnter full or partial auth name (none to cancel): ");
	readLine(inputLine, sizeof(inputLine));
	if (inputLine[0] == 0)
		return;

	eaCreate(&results);

	size = eaSize(&log->records);
	for (i = 0; i < size; i++)
	{
		if (strnicmp(inputLine, log->records[i]->accountName, strlen(inputLine))==0)
			eaPush(&results, log->records[i]);
	}

	crHandleFindResults(results);

	eaDestroy(&results);
}

static void crFindByCharacter(DeletionLog *log)
{
	char inputLine[100];
	DeletionHeader **results;
	int i, size;

	if (!log)
		return;

	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
//	printf("---- Find ----------------------------------------------\n");
	printf("\n\nEnter full or partial character name (none to cancel): ");
	readLine(inputLine, sizeof(inputLine));
	if (inputLine[0] == 0)
		return;

	eaCreate(&results);

	size = eaSize(&log->records);
	for (i = 0; i < size; i++)
	{
		if (strnicmp(inputLine, log->records[i]->characterName, strlen(inputLine))==0)
			eaPush(&results, log->records[i]);
	}

	crHandleFindResults(results);

	eaDestroy(&results);
}

static void crFindByIP(DeletionLog *log)
{
	char inputLine[100];
	DeletionHeader **results;
	int i, size;

	if (!log)
		return;

	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
//	printf("---- Find ----------------------------------------------\n");
	printf("\n\nEnter full or partial ip address (none to cancel): ");
	readLine(inputLine, sizeof(inputLine));
	if (inputLine[0] == 0)
		return;

	eaCreate(&results);

	size = eaSize(&log->records);
	for (i = 0; i < size; i++)
	{
		if (strnicmp(inputLine, log->records[i]->ipAddress, strlen(inputLine))==0)
			eaPush(&results, log->records[i]);
	}

	crHandleFindResults(results);

	eaDestroy(&results);
}

static void crFindByDate(DeletionLog *log)
{
	char inputLine[100];
	DeletionHeader **results;
	int i, size;
	struct tm a, b;
	U32 minTime, maxTime, recordTime;
	int parsed;

	if (!log)
		return;

	consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
//	printf("---- Find ----------------------------------------------\n");

	printf("\n\nEnter min year: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 1900, 9999, &parsed))
		return;
	a.tm_year = parsed - 1900;
	
	printf("\nEnter min month: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 1, 12, &parsed))
		return;
	a.tm_mon = parsed - 1;
	
	printf("\nEnter min day: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 1, 31, &parsed))
		return;
	a.tm_mday = parsed;
	
	printf("\nEnter min hour: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 0, 23, &parsed))
		return;
	a.tm_hour = parsed;
	
	printf("\nEnter min minute: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 0, 59, &parsed))
		return;
	a.tm_min = parsed;
	
	a.tm_sec = 0;
	

	printf("\n\nEnter max year: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 1900, 9999, &parsed))
		return;
	b.tm_year = parsed - 1900;
	
	printf("\nEnter max month: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 1, 12, &parsed))
		return;
	b.tm_mon = parsed - 1;
	
	printf("\nEnter max day: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 1, 31, &parsed))
		return;
	b.tm_mday = parsed;
	
	printf("\nEnter max hour: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 0, 23, &parsed))
		return;
	b.tm_hour = parsed;
	
	printf("\nEnter max minute: ");
	readLine(inputLine, sizeof(inputLine));
	if (!parseIntInRange(inputLine, 0, 59, &parsed))
		return;
	b.tm_min = parsed;
	
	b.tm_sec = 59;

	minTime = timerGetSecondsSince2000FromTimeStruct(&a);
	maxTime = timerGetSecondsSince2000FromTimeStruct(&b);
	if (maxTime < minTime)
		maxTime = minTime + 1;

	eaCreate(&results);

	size = eaSize(&log->records);
	for (i = 0; i < size; i++)
	{
		log->records[i];
		a.tm_year = log->records[i]->date.year - 1900;
		a.tm_mon = log->records[i]->date.month - 1;
		a.tm_mday = log->records[i]->date.day;
		a.tm_hour = log->records[i]->date.hours;
		a.tm_min = log->records[i]->date.minutes;
		a.tm_sec = log->records[i]->date.seconds;

		recordTime = timerGetSecondsSince2000FromTimeStruct(&a);

		if (recordTime >= minTime && recordTime <= maxTime)
			eaPush(&results, log->records[i]);
	}

	crHandleFindResults(results);

	eaDestroy(&results);
}

void characterRestore()
{
	char inputLine[1000];
	int selection;
	DeletionLog *log;
	char *s;

	strcpy(inputLine,fileDataDir());
	s = strrchr(inputLine,'/');
	if (s)
		*s = 0;

	strcat(inputLine, "/logs/dbserver/deletion.log.gz");

	log = crOpenDeletionLogByFilename(inputLine);

	do
	{
		consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
		printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
		columnPrintf(80, '-', "---- Menu -");
		printf( "\n"
				" 1. Open Deletion Log (Currently %s)\n"
				, (log && log->logFilename[0]) ? log->logFilename : "none");
		if (!log)
			consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE, 0);
		printf(	" 2. Find By Deleter Auth Name\n"
				" 3. Find By Deleted Character Name\n"
				" 4. Find By Deleter IP\n"
				" 5. Find By Deletion Date\n");
		consoleSetColor(COLOR_RED|COLOR_GREEN|COLOR_BLUE|COLOR_BRIGHT, 0);
		printf(	" 6. Exit\n");
		columnPrintf(80, '-', "");

		printf("\n\n\nEnter Selection: ");
		readLine(inputLine, sizeof(inputLine));
		if (!parseIntInRange(inputLine, 1, 6, &selection))
			selection = 0;

		switch (selection)
		{
		case 1:
			{
				DeletionLog *newlog = crOpenDeletionLog();
				if (newlog)
				{
					if (log)
						crFreeDeletionLog(log);
					log = newlog;
				}
			}
			break;
		case 2:
			crFindByAccount(log);
			break;
		case 3:
			crFindByCharacter(log);
			break;
		case 4:
			crFindByIP(log);
			break;
		case 5:
			crFindByDate(log);
			break;
		case 6:
			break;
		default:
			crErrorMessage("Invalid Selection!");
			break;
		}

		if (!log && selection > 1 && selection < 6)
			crErrorMessage("No deletion log open!");

	} while (selection != 6);

	if (log)
		crFreeDeletionLog(log);

}



