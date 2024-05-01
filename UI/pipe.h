#ifndef PIPE_H
#define PIPE_H

#include <Windows.h>
#include <iostream>

// Define BUFFER_SIZE
#define BUFFER_SIZE 512

class Pipe
{
private:
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    bool isConnected;
    OVERLAPPED overlapped;

public:
    Pipe(const char* pipeName);
    ~Pipe();

    char* GetPipeBuffer();
    bool GetPipeConnected();
    HANDLE GetPipeHandle();
    void waitForConnection();
    bool piReadMessageAsync();
    bool piGetOverlappedResult(DWORD& bytesRead);
};

#endif