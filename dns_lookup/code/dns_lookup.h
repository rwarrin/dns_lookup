#ifndef DNS_LOOKUP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <winsock2.h>
#include <windows.h>

typedef int32_t b32;
#define ArrayCount(Array) (sizeof((Array)) / sizeof((Array)[0]))

#pragma comment(lib, "ws2_32.lib")

#define DNS_ID 0x6969
#define MAX_PACKET_SIZE 4096
#define DNS_PORT 53

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

enum r_code_type
{
    RCodeType_NoError = 0,
    RCodeType_FormatError,
    RCodeType_ServerFailure,
    RCodeType_NameError,
    RCodeType_NotImplemented,
    RCodeType_Refused,
};

#define RESOURCE_RECORD_HANDLER(name) b32 name(uint8_t *Data, uint16_t DataLength)
typedef RESOURCE_RECORD_HANDLER(resource_record_handler);

#define DNS_LOOKUP_H
#endif
