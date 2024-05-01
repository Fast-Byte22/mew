#include <Windows.h>
#include <iostream>

#include <thread>
#include "offsets.hpp"
#include <tchar.h>
#include "Aclapi.h"
#include "sddl.h"

#include <atlbase.h>
#include <Shlobj.h>
#include <string>
#include "src/minhook/include/MinHook.h"



HANDLE hPipe = INVALID_HANDLE_VALUE;




LPCSTR ConvertWideCharToLPCSTR(const wchar_t* wideString)
{
    // Calculate the required buffer size for the narrow character string
    int bufferSize = WideCharToMultiByte(CP_ACP, 0, wideString, -1, NULL, 0, NULL, NULL);
    if (bufferSize == 0) {
        // Handle error
        return nullptr;
    }

    // Allocate memory for the narrow character string
    char* narrowString = new char[bufferSize];

    // Convert the wide character string to a narrow character string
    WideCharToMultiByte(CP_ACP, 0, wideString, -1, narrowString, bufferSize, NULL, NULL);

    // Return the converted narrow character string
    return narrowString;
}

// https://www.unknowncheats.me/forum/general-programming-and-reversing/177183-basic-intermediate-techniques-uwp-app-modding.html
// https://thewover.github.io/Introducing-Donut/
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
// https://github.com/gabime/spdlog/blob/v1.x/example/example.cpp
// Path to modified game files store in AppData
std::wstring MOD_FILES_PATH;

// Path to the apps protected resources in WindowsApps
// Don't use the full path name, just keep the Publisher.AppName part
std::wstring APP_LOCATION(L"C:\\Program Files\\WindowsApps\\A278AB0D.MarchofEmpires_8.2.1.0_x86__h6adky7gbf63m");

// Sets a hook on the function at origAddress function and provides a trampoline to the original function
BOOL setHook(LPVOID* origAddress, LPVOID* hookFunction, LPVOID* trampFunction);

// Attaches a hook on a function given the name of the owning module and the name of the function
BOOL attach(LPCSTR wstrModule, LPCSTR strFunction, LPVOID* hook, LPVOID* original);

// Basic hook setup for CreateFileW
typedef HANDLE(WINAPI* PfnCreateFileW)(LPCWSTR lpFilename, DWORD dwAccess, DWORD dwSharing, LPSECURITY_ATTRIBUTES saAttributes, DWORD dwCreation, DWORD dwAttributes, HANDLE hTemplate);
PfnCreateFileW pfnCreateFileW = NULL; // Will hold the trampoline to the original CreateFileW function

// CreateFileW hook function
HANDLE WINAPI HfnCreateFileW(LPCWSTR lpFilename, DWORD dwAccess, DWORD dwSharing, LPSECURITY_ATTRIBUTES saAttributes, DWORD dwCreation, DWORD dwAttributes, HANDLE hTemplate)
{
    std::wstring filePath(lpFilename);

    // Check if the app is accessing protected resources
    if (filePath.find(APP_LOCATION) != filePath.npos)
    {
        std::wstring newPath(MOD_FILES_PATH);

        // Windows provides the app the location of the WindowsApps directory, so the first half the file path will use back slashes
        // After that, some apps will use back slashes while others use forward slashes so be aware of what the app uses
        newPath += filePath.substr(filePath.find(L"\\", APP_LOCATION.size()) + 1, filePath.size());

        // Check if the file being accessed exists at the new path and reroute access to that file
        // Don't reroute directories as bad things can happen such as directories being ghost locked


        if (PathFileExists(ConvertWideCharToLPCSTR(newPath.c_str())) && !PathIsDirectory(ConvertWideCharToLPCSTR(newPath.c_str())))
            return pfnCreateFileW(newPath.c_str(), dwAccess, dwSharing, saAttributes, dwCreation, dwAttributes, hTemplate);
    }

    // Let the app load other files normally
    return pfnCreateFileW(lpFilename, dwAccess, dwSharing, saAttributes, dwCreation, dwAttributes, hTemplate);
}

BOOL Initialize()
{

    // Initialize MinHook
    if (MH_Initialize() != MH_OK)
        return FALSE;



    // Get the path to the apps AppData folder
    // When inside a UWP app, CSIDL_LOCAL_APPDATA returns the location of the apps AC folder in AppData
    TCHAR szPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, szPath)))
    {
        // Get the path to the mod files folder
#ifdef UNICODE

        std::wstring appData(szPath);

#else
        std::wstring appData(szPath, szPath + strlen(szPath));
#endif


        appData = appData.substr(0, appData.rfind(L"AC")); // Get the base directory
        appData += L"LocalState\\ModFiles\\"; // Get the location of any new files you want the app to use

        MOD_FILES_PATH = appData;
    }
    else
        return FALSE;

    // Attach a hook on CreateProcessW and return the status of the hook
    BOOL hook = TRUE;
    hook &= attach("KernelBase.dll", "CreateFileW", (LPVOID*)&HfnCreateFileW, (LPVOID*)&pfnCreateFileW);
    return hook;
}

 BOOL Uninitialize()
{
    // Uninitialize MinHook
    if (MH_Uninitialize() != MH_OK)
        return FALSE; // This status will end up being ignored

    return TRUE;
}



 BOOL setHook(LPVOID* origAddress, LPVOID* hookFunction, LPVOID* trampFunction)
{
    if (MH_CreateHook(origAddress, hookFunction, reinterpret_cast<LPVOID*>(trampFunction)) != MH_OK)
        return FALSE;

    if (MH_EnableHook(origAddress) != MH_OK)
        return FALSE;

    return TRUE;
}

 BOOL attach(LPCSTR wstrModule, LPCSTR strFunction, LPVOID* hook, LPVOID* original)
{
    HMODULE hModule = GetModuleHandle(wstrModule);
    if (hModule == NULL)
        return FALSE;

    FARPROC hFunction = GetProcAddress(hModule, strFunction);
    if (hFunction == NULL)
        return FALSE;

    return setHook((LPVOID*)hFunction, hook, original);
}









 DWORD SetPermissions(std::wstring wstrFilePath)
{
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESSW eaAccess; // Use EXPLICIT_ACCESSW for wide character strings
    SECURITY_INFORMATION siInfo = DACL_SECURITY_INFORMATION;
    DWORD dwResult = ERROR_SUCCESS;
    PSID pSID = NULL;
    LPWSTR pStringSID = NULL; // Use LPWSTR for wide character strings

    // Get a pointer to the existing DACL
    dwResult = GetNamedSecurityInfoW(wstrFilePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD); // Use GetNamedSecurityInfoW
    if (dwResult != ERROR_SUCCESS)
        goto Cleanup;

    // Get the SID for ALL APPLICATION PACKAGES using its SID string
    if (!ConvertStringSidToSid("S-1-15-2-1", &pSID))
    {
        dwResult = GetLastError();
        goto Cleanup;
    }

    // Convert the binary SID to a string SID
    if (!ConvertSidToStringSidW(pSID, &pStringSID)) // Use ConvertSidToStringSidW
    {
        dwResult = GetLastError();
        goto Cleanup;
    }

    ZeroMemory(&eaAccess, sizeof(EXPLICIT_ACCESSW)); // Use EXPLICIT_ACCESSW
    eaAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
    eaAccess.grfAccessMode = SET_ACCESS;
    eaAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    eaAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    eaAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

    // Assign the string SID to ptstrName
    eaAccess.Trustee.ptstrName = pStringSID;

    // Create a new ACL that merges the new ACE into the existing DACL
    dwResult = SetEntriesInAclW(1, &eaAccess, pOldDACL, &pNewDACL); // Use SetEntriesInAclW
    if (dwResult != ERROR_SUCCESS)
        goto Cleanup;

    // Attach the new ACL as the object's DACL
    dwResult = SetNamedSecurityInfoW(wstrFilePath.data(), SE_FILE_OBJECT, siInfo, NULL, NULL, pNewDACL, NULL); // Use SetNamedSecurityInfoW

Cleanup:
    if (pSID != NULL)
        LocalFree(pSID);
    if (pStringSID != NULL)
        LocalFree(pStringSID);
    if (pSD != NULL)
        LocalFree((HLOCAL)pSD);
    if (pNewDACL != NULL)
        LocalFree((HLOCAL)pNewDACL);

    return dwResult;
}










 BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
 {



     switch (ul_reason_for_call)
     {
     case DLL_PROCESS_ATTACH:
         return Initialize(); // If initialization failed, the DLL will detach
         break;
     case DLL_THREAD_ATTACH:
         break;
     case DLL_THREAD_DETACH:
         break;
     case DLL_PROCESS_DETACH:
         Uninitialize(); // Return value doesn't matter when detaching
         break;
     }
     return TRUE;
 }














//
//
//void CallRemoteFunction() {
//    // Get the handle to the target process
//    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,NULL /* Process ID */);
//
//    if (hProcess != NULL) {
//        // Get the address of the target function in the remote process
//        DWORD_PTR address = offset::uichange/* Address of the function sub_5F3230 */;
//
//        // Allocate memory in the remote process to store the function address
//        LPVOID pRemoteFuncAddr = VirtualAllocEx(hProcess, NULL, sizeof(address), MEM_COMMIT, PAGE_READWRITE);
//
//        if (pRemoteFuncAddr != NULL) {
//            // Write the function address to the allocated memory
//            WriteProcessMemory(hProcess, pRemoteFuncAddr, &address, sizeof(address), NULL);
//
//            // Get the address of LoadLibraryA function
//            HMODULE hKernel32 = GetModuleHandle("Kernel32.dll");
//            FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
//
//            // Create a remote thread in the target process to execute LoadLibraryA
//            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteFuncAddr, 0, NULL);
//
//            if (hThread != NULL) {
//                // Wait for the remote thread to finish
//                WaitForSingleObject(hThread, INFINITE);
//
//                // Close the remote thread handle
//                CloseHandle(hThread);
//            }
//
//            // Free the allocated memory
//            VirtualFreeEx(hProcess, pRemoteFuncAddr, 0, MEM_RELEASE);
//        }
//
//        // Close the handle to the target process
//        CloseHandle(hProcess);
//    }
//}
//
//
//void UnloadDLL(HMODULE hModule, int exit,HANDLE hpipe)
//{
//    if (hModule)
//    {
//
//
//        // Unload the DLL
//        FreeLibraryAndExitThread(hModule, exit);
//    }
//}
//
//
//void InjectedFunction(LPVOID instance)
//{
//    //spdlog::info("Welcome to spdlog version {}.{}.{}  !", SPDLOG_VER_MAJOR, SPDLOG_VER_MINOR, SPDLOG_VER_PATCH);
//    //spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
//    //logger->error("This is an error message");
//
//    HMODULE hModule = GetModuleHandle(NULL);
//
//    hPipe = CreateFile("\\\\.\\pipe\\Marceline",
//        GENERIC_READ | GENERIC_WRITE,
//        0,
//        NULL,
//        OPEN_EXISTING,
//        0,
//        NULL);
//
//
//    // Connect to named pipe server
//
//    static int i, result = 0;
//
//    while (i < 1)
//    {
//
//
//
//
//
//
//
//        if (hPipe != INVALID_HANDLE_VALUE) {
//            // Send data to server
//            char message[] = "Hello from client!";
//            DWORD bytesWritten;
//            WriteFile(hPipe, message, sizeof(message), &bytesWritten, NULL);
//
//            // Close pipe handle
//        }
//
//
//
//
//
//
//
//
//        Sleep(1000);
//    }
//
//
//
//    Sleep(6000);
//
//    UnloadDLL(hModule, result,hPipe);
//
//
//}
//
//
//BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
//{
//    // Check if the DLL is being loaded
//    if (fdwReason == DLL_PROCESS_ATTACH)
//    {
//        // Call the injected function
//
//
//
//
//        const HANDLE thread = CreateThread(
//            nullptr,
//            NULL,
//            reinterpret_cast<LPTHREAD_START_ROUTINE>(InjectedFunction),
//            hinstDLL,
//            NULL,
//            nullptr
//        );
//
//    }
//
//    // Return true to indicate successful initialization
//    return TRUE;
//}