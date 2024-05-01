#ifndef MEMORY_H
#define MEMORY_H


#pragma once
#include <Windows.h>
#include <iostream>

class Memory
{
private:
	DWORD id = 0;
	HANDLE process = NULL;

public:
	Memory(const char* processName);
	~Memory();

	DWORD GetProcessId();
	HANDLE GetProcessHandle();

	/*uintptr_t GetModuleAddress(const char* moduleName);*/

    //void CallRemoteFunction() {
    //    // Get the handle to the target process
    //    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, mem.GetProcessId() /* Process ID */);
    //    if (hProcess != NULL) {
    //        // Get the address of the target function in the remote process
    //        DWORD_PTR address = 0x1F3230/* Address of the function sub_5F3230 */;
    //        // Allocate memory in the remote process to store the function address
    //        LPVOID pRemoteFuncAddr = VirtualAllocEx(hProcess, NULL, sizeof(address), MEM_COMMIT, PAGE_READWRITE);
    //        if (pRemoteFuncAddr != NULL) {
    //            // Write the function address to the allocated memory
    //            WriteProcessMemory(hProcess, pRemoteFuncAddr, &address, sizeof(address), NULL);
    //            // Get the address of LoadLibraryA function
    //            HMODULE hKernel32 = GetModuleHandle("Kernel32.dll");
    //            FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    //            // Create a remote thread in the target process to execute LoadLibraryA
    //            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteFuncAddr, 0, NULL);
    //            if (hThread != NULL) {
    //                // Wait for the remote thread to finish
    //                WaitForSingleObject(hThread, INFINITE);
    //                // Close the remote thread handle
    //                CloseHandle(hThread);
    //            }
    //            // Free the allocated memory
    //            VirtualFreeEx(hProcess, pRemoteFuncAddr, 0, MEM_RELEASE);
    //        }
    //        // Close the handle to the target process
    //        CloseHandle(hProcess);
    //    }
    //}







	template <typename T>
	T Read(uintptr_t address) 
	{
		T value;
		ReadProcessMemory(this->process, (LPCVOID)address, &value, sizeof(T), NULL);
		return value;
	}

	template <typename T>
	bool Write(uintptr_t address,T value)
	{
		return WriteProcessMemory(this->process, (LPVOID)address, &value, sizeof(T), NULL);

	}


};

#endif // MEMORY_H