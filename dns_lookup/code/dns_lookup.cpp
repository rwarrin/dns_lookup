/**
 * NOTE(rick):
 * Super simple DNS query program.
 *
 * Docs:
 * https://datatracker.ietf.org/doc/html/rfc1035
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <winsock2.h>
#include <windows.h>

typedef int32_t b32;
#define ArrayCount(Array) (sizeof((Array)) / sizeof((Array)[0]))

#pragma comment(lib, "ws2_32.lib")

#pragma pack(push, 1)
struct dns_header
{
    uint16_t ID;

    uint8_t RecursionDesired : 1;
    uint8_t TruncateFlag : 1;
    uint8_t AuthorativeAnswerFlag : 1;
    uint8_t OpCode : 4;
    uint8_t QueryReponseFlag : 1;
    uint8_t ResponseCode : 4;
    uint8_t CheckingDisabled : 1;
    uint8_t AuthenticatedData : 1;
    uint8_t ZeroReserved_ : 1;
    uint8_t RecursionAvailable : 1;

    uint16_t QuestionCount;
    uint16_t AnswerCount;
    uint16_t AuthorityRecordCount;
    uint16_t AdditionalRecordCount;
};

struct dns_question
{
    // NOTE(rick): An N-length "Name" field preceeds the Type field.
    // The name is a sequence of a length octet followed by length count of
    // octets ending with a terminating length zero octet.
    uint16_t Type;
    uint16_t Class;
};

struct dns_answer
{
    uint16_t NameOffset; // NOTE(rick): Bytes from the beginning of the message
                         // to the location of the name that this answer is for.
    union
    {
        struct
        {
            uint16_t Type;
            uint16_t Class;
            uint32_t TimeToLive;
            uint16_t RDLength;
        };
        uint16_t E[4];
    };
};
#pragma pack(pop)

enum resource_record_class
{
    RRClass_IN = 1, // NOTE(rick): Internet
    RRClass_CS, // NOTE(rick): CSNet (Obsolete)
    RRClass_CH, // NOTE(rick): Chaos
    RRClass_HS, // NOTE(rick): Hesiod

    RRClass_Count,
};

enum resource_record_type
{
    RRType_A = 1, // NOTE(rick): A host address
    RRType_NS, // NOTE(rick): An authoritative name server
    RRType_MD, // NOTE(rick): A mail destination (Obsolete - use MX)
    RRType_MF, // NOTE(rick): A mail forwarder (Obsolete - use MX)
    RRType_CNAME, // NOTE(rick): The canonical name for an alias
    RRType_SOA, // NOTE(rick): Marks the start of a zone of authority
    RRType_MB, // NOTE(rick): A mailbox domain name (experimental)
    RRType_MG, // NOTE(rick): A mail group member (experimental)
    RRType_MR, // NOTE(rick): A mail rename domain name (experimental)
    RRType_NULL, // NOTE(rick): A null RR (experimental)
    RRType_WKS, // NOTE(rick): A well known service description
    RRType_PTR, // NOTE(rick): A domain name pointer
    RRType_HINFO, // NOTE(rick): Host information
    RRType_MINFO, // NOTE(rick): Mailbox or mail list information
    RRType_MX, // NOTE(rick): Mail exchange
    RRType_TXT, // NOTE(rick): Text strings

    RRType_Count,
};

inline uint32_t
StringToPacketNameFormat(uint8_t *Buffer, uint8_t *String)
{
    uint8_t *WritePtr = Buffer;
    uint8_t *SequenceStart = String;
    for(uint8_t *StringAt = String; ; ++StringAt)
    {
        uint8_t ThisCharacter = StringAt[0];
        if((ThisCharacter == '.') || (ThisCharacter == 0))
        {
            uint32_t Length = StringAt - SequenceStart;
            *WritePtr++ = Length;
            memcpy(WritePtr, SequenceStart, Length);
            WritePtr += Length;

            ++StringAt;
            SequenceStart = StringAt;
        }

        if(ThisCharacter == 0)
        {
            *WritePtr++ = 0;
            break;
        }
    }

    return(WritePtr - Buffer);
}

inline void
ParseNameForRecord(uint8_t *Response, uint16_t OffsetToName, char *NameBuffer)
{
    uint8_t *ResponseAt = Response + OffsetToName;
    uint8_t *NameAt = (uint8_t *)NameBuffer;
    for(;;)
    {
        uint8_t Length = *ResponseAt;
        if((Length & 0xC0) == 0xC0)
        {
            // NOTE(rick): Length is a pointer so compute the new offset and
            // resume parsing.
            uint16_t NewOffset = (Length & 0x3FFF);
            ResponseAt = Response + NewOffset;
        }
        else
        {
            // NOTE(rick): Length is a not a pointer it could be an octet count
            // of the number of bytes to read or zero terminator.
            ++ResponseAt;

            if(Length == 0)
            {
                if(NameAt > (uint8_t *)NameBuffer)
                {
                    --NameAt;
                    *NameAt = 0;
                }
                break;
            }

            for(uint8_t i = 0; i < Length; ++i)
            {
                *NameAt++ = *ResponseAt++;
            }
            *NameAt++ = '.';
        }
    }
}

#define RESOURCE_RECORD_HANDLER(name) b32 name(uint8_t *Data, uint16_t DataLength)
typedef RESOURCE_RECORD_HANDLER(resource_record_handler);

// NOTE(rick): Parse internet address record
//Parse_A_IN(uint8_t *Data, uint16_t DataLength)
static RESOURCE_RECORD_HANDLER(Parse_A_IN)
{
    b32 Result = false;

    // NOTE(rick): This is an IP address, 4 octets, we should expect a length of
    // 4 followed by 4 octets representing the IP.
    if(DataLength == 4)
    {
        char IPBuffer[16] = {0};
        snprintf(IPBuffer, ArrayCount(IPBuffer), "%d.%d.%d.%d\0",
                 Data[0], Data[1], Data[2], Data[3]);
        printf("Address: %s\n", IPBuffer);
        Result = true;
    }

    return(Result);
}

static RESOURCE_RECORD_HANDLER(Parse_CNAME_IN)
{
    char Buffer[512] = {0};
    ParseNameForRecord(Data, 0, Buffer);
    printf("CNAME: %s\n", Buffer);
    return(true);
}

//typedef b32 (* resource_record_handler)(uint8_t *, uint16_t);
static resource_record_handler *ResourceRecordHandlerTable[RRType_Count][RRClass_Count] =
{
    {0, 0, 0, 0, 0},
    {0, Parse_A_IN, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, Parse_CNAME_IN, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0},
};

#define DNS_ID 0x6969
#define MAX_PACKET_SIZE 4096
#define DNS_PORT 53

inline void
SetDNSQueryHeader(dns_header *Header)
{
    Header->ID = DNS_ID;
    Header->RecursionDesired = true;
    Header->QuestionCount = htons(1);
}

static b32
ParseDNSResponse(uint8_t *Buffer, uint32_t BufferSize, uint32_t EchoLength)
{
    b32 Result = false;

    dns_header *DNSHeader = (dns_header *)Buffer;
    b32 IsValidResponse = ((DNSHeader->ResponseCode == 0) &&
                           (DNSHeader->ID == DNS_ID));
    if(IsValidResponse)
    {
        b32 IsAuthoritative = DNSHeader->AuthorativeAnswerFlag;
        if(!IsAuthoritative)
        {
            printf("Non-authoritative answer:\n");
        }

        uint16_t AnswerCount = ntohs(DNSHeader->AnswerCount);
        uint8_t *AnswersBegin = Buffer + EchoLength;
        uint8_t *AnswerAt = AnswersBegin;
        for(uint16_t AnswerIndex = 0; AnswerIndex < AnswerCount; ++AnswerIndex)
        {
            printf("(%02d) ", AnswerIndex+1);
            dns_answer *DNSAnswer = (dns_answer *)AnswerAt;
            // NOTE(rick): Network to host conversion for dns_answer fields.
            DNSAnswer->Type = ntohs(DNSAnswer->Type);
            DNSAnswer->Class = ntohs(DNSAnswer->Class);
            DNSAnswer->TimeToLive = ntohl(DNSAnswer->TimeToLive);
            DNSAnswer->RDLength = ntohs(DNSAnswer->RDLength);

            uint32_t NameOffset = ntohs(DNSAnswer->NameOffset) & 0x3FFF;
            if(NameOffset)
            {
                char Name[512] = {0};
                ParseNameForRecord(Buffer, NameOffset, Name);
                printf("Name: %s\n     ", Name);
            }

            uint8_t *DataAt = (uint8_t *)(AnswerAt + sizeof(*DNSAnswer));
            resource_record_handler *RecordHandler = 
                ResourceRecordHandlerTable[DNSAnswer->Type][DNSAnswer->Class];
            if(RecordHandler)
            {
                b32 Success = RecordHandler(DataAt, DNSAnswer->RDLength);
            }
            else
            {
                fprintf(stderr, "Unhandled Resource Record. Class (%d), Type (%d)\n",
                        DNSAnswer->Class, DNSAnswer->Type);
            }

            AnswerAt += sizeof(*DNSAnswer) + DNSAnswer->RDLength;
        }

        Result = true;
    }
    else
    {
        fprintf(stderr, "Invalid DNS Response\n");
    }

    return(Result);
}

struct app_context
{
    b32 IsDebug;
    char *DebugFileName;

    char *DomainName;
    char *DNSServer;

    char *DumpName;
    b32 DumpToFile;
};

static void
ParseCommandLineArguments(int32_t ArgCount, char **Args, app_context *Context)
{
    if(Context)
    {
        for(int32_t ArgIndex = 1; ArgIndex < ArgCount; ++ArgIndex)
        {
            if(strcmp("--debug", Args[ArgIndex]) == 0)
            {
                Context->IsDebug = true;
                Context->DebugFileName = Args[++ArgIndex];
            }
            else if(strcmp("--server", Args[ArgIndex]) == 0)
            {
                Context->DNSServer = Args[++ArgIndex];
            }
            else if(strcmp("--dump", Args[ArgIndex]) == 0)
            {
                Context->DumpToFile = true;
                Context->DumpName = Args[++ArgIndex];
            }
            else
            {
                if(Args[ArgIndex][0] != '-')
                {
                    Context->DomainName = Args[ArgIndex];
                }
            }
        }
    }
};

static void
PrintHelp(char *Command)
{
    fprintf(stderr, "Usage: %s [url] [options]\n", Command);
    fprintf(stderr, "  %-24s%-56s\n", "url", "The URL to lookup.");
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  %-24s%-56s\n", "--debug filename", "Reads a DNS response from the file specified by filename.");
    fprintf(stderr, "  %-24s%-56s\n", "--server address", "Address to send the DNS query to. Default is Google \"8.8.8.8\".");
    fprintf(stderr, "  %-24s%-56s\n", "--dump filename", "Dumps the DNS response to the file spcified by filename.");
}

int main(int32_t ArgCount, char **Args)
{
    if(ArgCount < 2)
    {
        PrintHelp(Args[0]);
        return(1);
    }

    app_context Context = {0};
    ParseCommandLineArguments(ArgCount, Args, &Context);

    if(!Context.DomainName)
    {
        fprintf(stderr, "Missing required argument: [url]\n");
        return(4);
    }

    if(Context.IsDebug)
    {
        uint8_t ReceiveBuffer[MAX_PACKET_SIZE] = {0};
        FILE *File = fopen(Context.DebugFileName, "rb");
        if(File)
        {
            fseek(File, 0, SEEK_END);
            uint32_t FileSize = ftell(File);
            fseek(File, 0, SEEK_SET);

            fread(ReceiveBuffer, 1, FileSize, File);

            uint32_t *SentPacketSize = (uint32_t *)ReceiveBuffer;
            uint8_t *ResponseData = (uint8_t *)(ReceiveBuffer + sizeof(uint32_t));
            b32 ParseSuccess = ParseDNSResponse(ResponseData, MAX_PACKET_SIZE, *SentPacketSize);

            fclose(File);
        }

        return(999);
    }
    else
    {
        WSADATA WSAData = {0};
        if(WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
        {
            fprintf(stderr, "WSAStartup failed (%d)\n", WSAGetLastError());
            return(2);
        }

        SOCKET Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(Socket == INVALID_SOCKET)
        {
            fprintf(stderr, "socket error (%d)\n", WSAGetLastError());
            WSACleanup();
            return(2);
        }

        sockaddr_in ServerAddr = {0};
        ServerAddr.sin_family = AF_INET;
        ServerAddr.sin_port = htons(DNS_PORT);
        ServerAddr.sin_addr.s_addr = inet_addr(Context.DNSServer ? Context.DNSServer : "8.8.8.8"); // NOTE(rick): Google DNS

        // NOTE(rick): DNS Query
        uint32_t SendPacketLength = 0;
        b32 SendSuccess = false;
        {
            uint8_t PacketBuffer[MAX_PACKET_SIZE] = {0};
            uint8_t *PacketBufferWritePtr = PacketBuffer;

            SetDNSQueryHeader((dns_header *)PacketBufferWritePtr);
            PacketBufferWritePtr += sizeof(dns_header);

            uint32_t BytesWritten = StringToPacketNameFormat(PacketBufferWritePtr, (uint8_t *)Context.DomainName);
            PacketBufferWritePtr += BytesWritten;

            dns_question *Question = (dns_question *)PacketBufferWritePtr;
            Question->Type = htons(1); // NOTE(rick): 0x01 -> A -> Host address
            Question->Class = htons(1); // NOTE(rick): 0x01 -> The internet
            PacketBufferWritePtr += sizeof(dns_question);

            int breakhere = 5;

            SendPacketLength = PacketBufferWritePtr - PacketBuffer;
            uint32_t BytesSent = sendto(Socket, (char *)PacketBuffer, SendPacketLength, 0, (sockaddr *)&ServerAddr, sizeof(ServerAddr));
            SendSuccess = (BytesSent > 0);

            if(!SendSuccess)
            {
                fprintf(stderr, "sendto failed (%d)\n", WSAGetLastError());
                return(2);
            }
        }

        // NOTE(rick): DNS Response
        {
            if(SendSuccess)
            {
                uint8_t ReceiveBuffer[MAX_PACKET_SIZE] = {0};

                sockaddr_in ReceiveServerAddr = {0};
                int32_t ServerAddrSize = sizeof(ReceiveServerAddr);
                int32_t BytesReceived = recvfrom(Socket, (char *)ReceiveBuffer, MAX_PACKET_SIZE, 0, (sockaddr *)&ReceiveServerAddr, &ServerAddrSize);
                printf("Response from: %s\n", inet_ntoa(ReceiveServerAddr.sin_addr));
                if(BytesReceived <= 0)
                {
                    fprintf(stderr, "recvfrom failed (%d)\n", WSAGetLastError());
                    closesocket(Socket);
                    WSACleanup();
                    return(2);
                }

                if(Context.DumpToFile)
                {
                    FILE *File = fopen(Context.DumpName, "wb");
                    if(File)
                    {
                        fwrite((void *)&SendPacketLength, sizeof(uint32_t), 1, File);
                        fwrite(ReceiveBuffer, sizeof(uint8_t), BytesReceived, File);
                        fflush(File);
                        fclose(File);
                    }
                }

                b32 ParseSuccess = ParseDNSResponse(ReceiveBuffer, MAX_PACKET_SIZE, SendPacketLength);
            }
        }

        closesocket(Socket);
        WSACleanup();
    }

    return(0);
}
