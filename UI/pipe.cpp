#include "pipe.h"
#include <ioapiset.h>

Pipe::Pipe(const char* pipeName) : hPipe(INVALID_HANDLE_VALUE), isConnected(false) {
    std::string fullPipeName = "\\\\.\\pipe\\" + std::string(pipeName);

    // Initialize buffer with zeros
    ZeroMemory(buffer, BUFFER_SIZE);

    this->hPipe = CreateNamedPipe(fullPipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // Enable overlapped mode
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        BUFFER_SIZE,
        BUFFER_SIZE,
        0,
        NULL);
}


Pipe::~Pipe() {
    CloseHandle(hPipe);
}

char* Pipe::GetPipeBuffer() {
    return this->buffer;
}

bool Pipe::GetPipeConnected() {
    return this->isConnected;
}

HANDLE Pipe::GetPipeHandle() {
    return this->hPipe;
}

void Pipe::waitForConnection() {
    if (this->hPipe != INVALID_HANDLE_VALUE) {
        if (ConnectNamedPipe(this->hPipe, NULL)) {
            this->isConnected = true;
        }
    }
}

bool Pipe::piReadMessageAsync() {
    if (this->hPipe == INVALID_HANDLE_VALUE || !this->isConnected) {
        return false; // Pipe not initialized or not connected
    }

    ZeroMemory(&this->overlapped, sizeof(this->overlapped));
    BOOL success = ReadFileEx(this->hPipe, this->buffer, BUFFER_SIZE, &this->overlapped,nullptr );
    return success != 0;
}

bool Pipe::piGetOverlappedResult(DWORD& bytesRead) {
    if (this->hPipe == INVALID_HANDLE_VALUE || !this->isConnected) {
        return false; // Pipe not initialized or not connected
    }

    DWORD dwBytesTransferred = 0;
    BOOL success = GetOverlappedResult(this->hPipe, &this->overlapped, &dwBytesTransferred, TRUE);

    if (!success) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_IO_INCOMPLETE) {
            // Operation is still pending
            bytesRead = 0; // Set bytesRead to 0
            return true;   // Return true to indicate pending operation
        }
        else {
            // Error occurred
            // Handle the error here, such as logging or throwing an exception
            return false;
        }
    }
    else {
        // Operation completed successfully
        bytesRead = dwBytesTransferred;
        return true;
    }
}
