static b32
ParseCommandLineArguments(int32_t ArgCount, char **Args, app_context *Context)
{
    b32 Result = false;
    if(Context)
    {
        for(int32_t ArgIndex = 1; ArgIndex < ArgCount; ++ArgIndex)
        {
            b32 HasNextArg = ((ArgIndex + 1) < ArgCount);
            if(strcmp("--debug", Args[ArgIndex]) == 0)
            {
                if(HasNextArg)
                {
                    Context->IsDebug = true;
                    Context->DebugFileName = Args[++ArgIndex];
                    Result = true;
                }
            }
            else if(strcmp("--server", Args[ArgIndex]) == 0)
            {
                if(HasNextArg)
                {
                    Context->DNSServer = Args[++ArgIndex];
                }
            }
            else if(strcmp("--dump", Args[ArgIndex]) == 0)
            {
                if(HasNextArg)
                {
                    Context->DumpToFile = true;
                    Context->DumpName = Args[++ArgIndex];
                }
            }
            else
            {
                if(Args[ArgIndex][0] != '-')
                {
                    Context->DomainName = Args[ArgIndex];
                    Result = true;
                }
            }
        }
    }
    return(Result);
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
