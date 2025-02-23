#ifndef DNS_APP_H

struct app_context
{
    b32 IsDebug;
    char *DebugFileName;

    char *DomainName;
    char *DNSServer;

    char *DumpName;
    b32 DumpToFile;
};

#define DNS_APP_H
#endif
