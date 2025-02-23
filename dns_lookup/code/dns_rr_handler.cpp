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

