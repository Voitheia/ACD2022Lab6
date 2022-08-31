#include <windows.h>
#include <string>
#include <iostream>
#include <TlHelp32.h>
#include <lmcons.h>
#include "../include/lab6.h"

#define MAX_NAME 256

namespace lab6 {

// constants for the flags
const char* kFlagPrefix = "ACDLAB6{";
const char* kBadAdminFlag = "Never_should_have_come_here}";
const char* kImageFileExecFlag = "Can't_touch_this}";
const char* kFirewallFlag = "They_took_down_our_shields!}";
const char* kCurrentVersionRunFlag = "Autobots_roll_out}";
const char* kSSHFlag = "I_think_this_is_the_wrong_OS}";
const char* kNetcatFlag = "Nyancat_bootloader_time}";
const char* kSpawnedCMDFlag = "Hey_you_shouldn't_be_running_there}";
const char* kInstalledServiceFlag = "Definitely_a_legit_service}";
const char* kTaskSchedulerFlag = "Wanna_see_me_run_it_again}";

// names of the bad admin users
const char* kBadAdminName1 = "Spongebob";
const char* kBadAdminName2 = "Patrick";
const char* kBadAdminName3 = "Mr. Krabs";
const char* kBadAdminName4 = "Sandy";
const char* kBadAdminName5 = "Plankton";

std::string EnableDebugPrivs() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return "[ERROR] OpenProcessToken/GetCurrentProcess failed. GetLastError: " + GetLastError();
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        return "[ERROR] LookupPrivilegeValue failed. GetLastError: " + GetLastError();
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        return "[ERROR] AdjustTokenPrivileges failed. GetLastError: " + GetLastError();
    }

    return "SUCCESS";
}

BOOL GetLogonFromToken (HANDLE hToken, std::string& strUser, std::string& strdomain) 
{
   DWORD dwSize = MAX_NAME;
   BOOL bSuccess = FALSE;
   DWORD dwLength = 0;
   strUser = "";
   strdomain = "";
   PTOKEN_USER ptu = NULL;
 //Verify the parameter passed in is not NULL.
    if (NULL == hToken)
        goto Cleanup;

       if (!GetTokenInformation(
         hToken,         // handle to the access token
         TokenUser,    // get information about the token's groups 
         (LPVOID) ptu,   // pointer to PTOKEN_USER buffer
         0,              // size of buffer
         &dwLength       // receives required buffer size
      )) 
   {
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) 
         goto Cleanup;

      ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
         HEAP_ZERO_MEMORY, dwLength);

      if (ptu == NULL)
         goto Cleanup;
   }

    if (!GetTokenInformation(
         hToken,         // handle to the access token
         TokenUser,    // get information about the token's groups 
         (LPVOID) ptu,   // pointer to PTOKEN_USER buffer
         dwLength,       // size of buffer
         &dwLength       // receives required buffer size
         )) 
   {
      goto Cleanup;
   }
    SID_NAME_USE SidType;
    char lpName[MAX_NAME];
    char lpDomain[MAX_NAME];

    if( !LookupAccountSidA( NULL , ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) )                                    
    {
        DWORD dwResult = GetLastError();
        if( dwResult == ERROR_NONE_MAPPED )
           strcpy (lpName, "NONE_MAPPED" );
        else 
        {
            // printf("LookupAccountSid Error %u\n", GetLastError());
        }
    }
    else
    {
        // printf( "Current user is  %s\\%s\n", 
        //         lpDomain, lpName );
        strUser = lpName;
        strdomain = lpDomain;
        bSuccess = TRUE;
    }

Cleanup: 

   if (ptu != NULL)
      HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
   return bSuccess;
}

HRESULT GetUserFromProcess(const DWORD procId,  std::string& strUser, std::string& strdomain)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,procId); 
    if(hProcess == NULL)
        return E_FAIL;
    HANDLE hToken = NULL;

    if( !OpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) )
    {
        CloseHandle( hProcess );
        return E_FAIL;
    }
    BOOL bres = GetLogonFromToken (hToken, strUser,  strdomain);

    CloseHandle( hToken );
    CloseHandle( hProcess );
    return bres?S_OK:E_FAIL;
}

std::string ElevateToSystem() {
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 1);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return "[ERROR] CreateToolhelp32Snapshot failed. GetLastError: " + GetLastError();
    }

    if (Process32First(hSnapshot, &pe) != TRUE) {
        return "[ERROR] Process32First failed. GetLastError: " + GetLastError();
    }

    BOOL success = FALSE;

    do {
        std::string strUser;
        std::string strdomain;
        GetUserFromProcess(pe.th32ProcessID, strUser, strdomain);
        if (strUser.compare(std::string("SYSTEM")) == 0) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc != NULL) {
                HANDLE hToken;
                if (OpenProcessToken(hProc, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &hToken)) {
                    HANDLE hDupeToken;
                    if (DuplicateToken(hToken, SecurityImpersonation, &hDupeToken)) {
                        if (SetThreadToken(NULL, hDupeToken)) {
                            success = TRUE;
                        } else {
                            std::cout << "SetThreadToken GetLastError: " << GetLastError() << std::endl;
                        }
                    } else {
                        std::cout << "DuplicateToken GetLastError: " << GetLastError() << std::endl;
                    }
                    CloseHandle(hDupeToken);
                } else {
                    std::cout << "OpenProcessToken GetLastError: " << GetLastError() << std::endl;
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProc);
        }
    } while (Process32Next(hSnapshot, &pe) == TRUE && !success);

    return "SUCCESS";
}

std::string CheckCurrentUsername() {
    char username[UNLEN+1];
    DWORD username_len = UNLEN+1;
    GetUserNameA(username, &username_len);
    return std::string(username);
}

std::string DestroyDefender() {
    HKEY hkResult;
    DWORD dwDisposition;
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Policies\\Microsoft\\", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    RegCloseKey(hkResult);

    return "";

    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
}

std::string MakeBadAdmins() {
    return "";
}

std::string AddImageFileExecutionOptionsKeys() {
    return "";
}

std::string MisconfigureFirewall() {
    return "";
}

std::string AddCurrentVersionRunKeys() {
    return "";
}

std::string InstallAndRunSSHServer() {
    return "";
}

std::string RunNetcatListeners() {
    return "";
}

std::string InjectCMDs() {
    return "";
}

std::string InstallService() {
    return "";
}

std::string AddTaskScheduler() {
    return "";
}

} // namespace lab6

int main (int argc, char *argv[]) {
    std::cout << "EnableDebugPrivs: " << lab6::EnableDebugPrivs() << std::endl;
    std::cout << "ElevateToSystem: " << lab6::ElevateToSystem() << std::endl;
    std::cout << "CheckCurrentUsername: " << lab6::CheckCurrentUsername() << std::endl;
    std::cout << "DestroyDefender: " << lab6::DestroyDefender() << std::endl;
    int x;
    std::cin >> x;
    return 0;
}