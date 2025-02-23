/**
 * NOTE(rick):
 * Super simple DNS query program.
 *
 * Docs:
 * https://datatracker.ietf.org/doc/html/rfc1035
 **/

#include "dns_lookup.h"
#include "dns_app.h"

void ParseNameForRecord(uint8_t *Response, uint16_t OffsetToName, char *NameBuffer);
#include "dns_rr_handler.cpp"
#include "dns_app.cpp"

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
    b32 IsValidResponse = ((DNSHeader->ResponseCode == RCodeType_NoError) &&
                           (DNSHeader->ID == DNS_ID));
    if(IsValidResponse)
    {
        b32 IsAuthoritative = DNSHeader->AuthorativeAnswerFlag;
        printf("Answer is %s.\n", IsAuthoritative ? "authoritative" : "non-authoritative");

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
        switch(DNSHeader->ResponseCode)
        {
            case RCodeType_FormatError:
            {
                fprintf(stderr, "Format error - Name server was unable to interpret the query.\n");
            } break;
            case RCodeType_ServerFailure:
            {
                fprintf(stderr, "Server failure - Name server was unable to process the query.\n");
            } break;
            case RCodeType_NameError:
            {
                fprintf(stderr, "Name error - Domain does not exist.\n");
            } break;
            case RCodeType_NotImplemented:
            {
                fprintf(stderr, "Not implemented - Name server does not support this kind of query.\n");
            } break;
            case RCodeType_Refused:
            {
                fprintf(stderr, "Refused - Name server refused to perform the specified operation.\n");
            } break;
            default:
            {
                fprintf(stderr, "Invalid DNS Response\n");
            } break;
        }
    }

    return(Result);
}

int main(int32_t ArgCount, char **Args)
{
    if(ArgCount < 2)
    {
        PrintHelp(Args[0]);
        return(1);
    }

    app_context Context = {0};
    b32 CommandsResult = ParseCommandLineArguments(ArgCount, Args, &Context);
    if(!CommandsResult)
    {
        PrintHelp(Args[0]);
        return(1);
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
        if(!Context.DomainName)
        {
            fprintf(stderr, "Missing required argument: [url]\n");
            return(4);
        }

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
                printf("Response from %s:\n", inet_ntoa(ReceiveServerAddr.sin_addr));
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
