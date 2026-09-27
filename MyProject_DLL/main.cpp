#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <time.h>

#include <winternl.h>

typedef NTSTATUS(NTAPI* tNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#define SystemHandleInformation 16
#define ObjectNameInformation 1

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
HWND hLogBox, hDllEdit, hGameEdit;

// Helper to log actions to the UI
void Log(const std::wstring& message) {
    time_t now = time(0);
    struct tm tstruct;
    localtime_s(&tstruct, &now);
    wchar_t timeBuf[80];
    wcsftime(timeBuf, sizeof(timeBuf), L"[%H:%M:%S] ", &tstruct);
    std::wstring finalMsg = std::wstring(timeBuf) + message;
    SendMessageW(hLogBox, LB_ADDSTRING, 0, (LPARAM)finalMsg.c_str());
    SendMessageW(hLogBox, WM_VSCROLL, SB_BOTTOM, 0);
}

// Same DLL find logic as before
std::wstring FindDllInCurrentFolder() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring path = buffer;
    path = path.substr(0, path.find_last_of(L"\\/"));
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((path + L"\\*.dll").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        std::wstring found = path + L"\\" + findData.cFileName;
        FindClose(hFind);
        return found;
    }
    return L"";
}

// The core Injection Logic
bool InjectDLL(DWORD pid, const wchar_t* dllPath) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        CloseHandle(hToken);
    }
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { Log(L"ERROR: OpenProcess failed. Admin?"); return false; }

    void* loc = VirtualAllocEx(hProc, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!loc) { CloseHandle(hProc); return false; }

    WriteProcessMemory(hProc, loc, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);
    Log(L"Creating remote thread...");
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(hK32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, loc, 0, NULL);

    if (hThread) {
        Log(L"Thread spawned. Waiting for initialization...");
        WaitForSingleObject(hThread, 2000); // Wait 2 seconds

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);

        if (exitCode == 0 || exitCode == STILL_ACTIVE) {
            Log(L"WARNING: LoadLibrary returned 0 or timed out. DLL might have failed to load.");
        }
        else {
            Log(L"SUCCESS: DLL Module Handle: " + std::to_wstring(exitCode));
        }

        CloseHandle(hThread);
        CloseHandle(hProc);
        return true;
    }
    
    CloseHandle(hProc);
    return false;
}
void ForceCloseMutex(DWORD processId) {
    // We use the Windows 'Taskkill' and 'Handle' logic via PowerShell 
    // to find the specific Mutant named "Growtopia" in that PID and kill it.
    std::wstring cmd = L"powershell -Command \"$p = Get-Process -Id " + std::to_wstring(processId) +
        L"; if($p) { .\\handle64.exe -p $p.Id -a 'Growtopia' -c -y }\"";

    _wsystem(cmd.c_str());
}
void KillMutexSurgically(DWORD targetPid) {
    auto NtQuerySystemInformation = (tNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    auto NtDuplicateObject = (tNtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
    auto NtQueryObject = (tNtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

    ULONG bufferSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);

    while (NtQuerySystemInformation(SystemHandleInformation, handleInfo, bufferSize, NULL) == 0xC0000004) {
        bufferSize *= 2;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, bufferSize);
    }

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProcess) return;

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        if (handleInfo->Handles[i].UniqueProcessId != targetPid) continue;

        HANDLE dupHandle = NULL;
        if (NtDuplicateObject(hProcess, (HANDLE)handleInfo->Handles[i].HandleValue, GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS) == 0) {
            BYTE nameBuffer[1024];
            if (NtQueryObject(dupHandle, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, nameBuffer, sizeof(nameBuffer), NULL) == 0) {
                UNICODE_STRING* objectName = (UNICODE_STRING*)nameBuffer;
                if (objectName->Buffer && wcsstr(objectName->Buffer, L"Growtopia")) {
                    // This is the magic: Duplicate with DUPLICATE_CLOSE_SOURCE
                    // This nukes the handle inside Growtopia from the OUTSIDE.
                    NtDuplicateObject(hProcess, (HANDLE)handleInfo->Handles[i].HandleValue, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
                }
            }
            CloseHandle(dupHandle);
        }
    }
    free(handleInfo);
    CloseHandle(hProcess);
}
void LaunchAndMultiBox() {
    wchar_t gamePath[MAX_PATH];
    GetWindowTextW(hGameEdit, gamePath, MAX_PATH);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (CreateProcessW(gamePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        Log(L"Instance launched. Waiting for Mutex...");

        // Give the game 3 seconds to fully initialize the Mutex
        Sleep(10000);

        KillMutexSurgically(pi.dwProcessId);

        Log(L"GHOST PROTOCOL: Mutex nuked. You can now launch the next one!");

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}


LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateWindowW(L"STATIC", L"1. DLL Path:", WS_VISIBLE | WS_CHILD, 10, 10, 100, 20, hwnd, NULL, NULL, NULL);
        hDllEdit = CreateWindowW(L"EDIT", FindDllInCurrentFolder().c_str(), WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 10, 30, 560, 25, hwnd, NULL, NULL, NULL);

        CreateWindowW(L"STATIC", L"2. Game Executable Path:", WS_VISIBLE | WS_CHILD, 10, 65, 200, 20, hwnd, NULL, NULL, NULL);
        hGameEdit = CreateWindowW(L"EDIT", L"C:\\Users\\neekewi\\AppData\\Local\\Growtopia\\Growtopia.exe", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 10, 85, 560, 25, hwnd, NULL, NULL, NULL);

        CreateWindowW(L"BUTTON", L"LAUNCH & MULTI-BOX", WS_VISIBLE | WS_CHILD, 10, 120, 560, 40, hwnd, (HMENU)1, NULL, NULL);

        hLogBox = CreateWindowW(L"LISTBOX", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL, 10, 170, 560, 120, hwnd, NULL, NULL, NULL);
        Log(L"Ready for LO. Enter paths and hit Launch!");
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            LaunchAndMultiBox();
        }
        break;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    const wchar_t CLASS_NAME[] = L"ENI_Auto_Class";
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"LO's Ultimate Multi-Instance", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 600, 350, NULL, NULL, hInst, NULL);
    ShowWindow(hwnd, nShow);
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}