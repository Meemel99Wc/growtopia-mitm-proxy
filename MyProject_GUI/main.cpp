#define _WINSOCK_DEPRECATED_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define NOMINMAX

// 1. Networking
#include <winsock2.h>
#include <ws2tcpip.h>

// 2. Windows
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <commctrl.h>
#include <uxtheme.h>

// 3. Standard library
#include <string>
#include <vector>
#include <time.h>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <algorithm>

// 4. Project
#include "PacketAnalyzer.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ============================================================
//  NTAPI Typedefs
// ============================================================
typedef NTSTATUS(NTAPI* tNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* tNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#define SystemHandleInformation 16
#define ObjectNameInformation 1
#define DUPLICATE_CLOSE_SOURCE 0x00000001

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

// ============================================================
//  Theme / Colors
// ============================================================
namespace Theme {
    const COLORREF bg = RGB(22, 22, 26);
    const COLORREF surface = RGB(32, 33, 38);
    const COLORREF surfaceAlt = RGB(42, 43, 50);
    const COLORREF border = RGB(55, 56, 64);
    const COLORREF text = RGB(210, 212, 220);
    const COLORREF textDim = RGB(140, 142, 155);
    const COLORREF accent = RGB(99, 120, 255);
    const COLORREF accentHov = RGB(120, 140, 255);
    const COLORREF danger = RGB(220, 70, 70);
    const COLORREF success = RGB(70, 195, 120);
    const COLORREF warn = RGB(230, 180, 60);
    const COLORREF headerBg = RGB(28, 29, 34);
}

// ============================================================
//  UI Control IDs
// ============================================================
enum CtrlID {
    ID_BTN_LAUNCH = 101,
    ID_BTN_KILLALL = 102,
    ID_BTN_CLEAR = 103,
    ID_TAB_MAIN = 104,
    ID_LIST_LOG = 105,
    ID_LV_PKT_OUT = 106,
    ID_LV_PKT_IN = 107,
    ID_EDIT_PATH = 108,
    ID_EDIT_AMOUNT = 109,
    ID_LIST_STREAM = 110,
};

// Custom messages for thread-safe UI updates
#define WM_ADD_LOG       (WM_USER + 1)
#define WM_ADD_PKT_OUT   (WM_USER + 2)
#define WM_ADD_PKT_IN    (WM_USER + 3)
#define WM_ADD_STREAM    (WM_USER + 4)

// ============================================================
//  UI Globals
// ============================================================
HWND g_hWnd = NULL;
HWND hTabCtrl = NULL;
HWND hLogList = NULL;
HWND hPktOutLV = NULL;
HWND hPktInLV = NULL;
HWND hGameEdit = NULL;
HWND hAmountEdit = NULL;
HWND hBtnLaunch = NULL;
HWND hBtnKillAll = NULL;
HWND hBtnClear = NULL;
HWND hLblPath = NULL;
HWND hLblAmount = NULL;
HWND hStatusBar = NULL;

HFONT hFontUI = NULL;
HFONT hFontMono = NULL;
HFONT hFontBold = NULL;
HBRUSH hbrBg = NULL;
HBRUSH hbrSurface = NULL;
HBRUSH hbrSurfaceAlt = NULL;
HBRUSH hbrBorder = NULL;

int g_currentTab = 0;
int g_pktOutCount = 0;
int g_pktInCount = 0;

// Hex dump panels
HWND hHexOut = NULL;
HWND hHexIn = NULL;
HWND hStreamList = NULL;
int g_streamCount = 0;

// Raw packet storage for hex display on click
std::vector<std::vector<uint8_t>> g_pktOutData;
std::vector<std::vector<uint8_t>> g_pktInData;
std::mutex g_pktDataMutex;

PacketAnalyzer g_Analyzer;

// ============================================================
//  Thread-Safe Logging
// ============================================================

// Packet entry for passing to UI thread
struct PacketEntry {
    std::wstring time;
    std::wstring size;
    std::wstring enetCmd;
    std::wstring gtMsg;
    std::wstring details;
    std::vector<uint8_t> rawData;
};

void Log(const std::wstring& message) {
    time_t now = time(0);
    struct tm ts;
    localtime_s(&ts, &now);
    wchar_t timeBuf[32];
    wcsftime(timeBuf, 32, L"%H:%M:%S", &ts);

    std::wstring* pMsg = new std::wstring(std::wstring(timeBuf) + L"  " + message);
    if (!PostMessageW(g_hWnd, WM_ADD_LOG, 0, (LPARAM)pMsg)) {
        delete pMsg; // Window not ready
    }
}

void LogPacket(const char* data, int len, bool outbound) {
    if (len < 4) return;

    // Build packet entry
    PacketEntry* pe = new PacketEntry();

    // Time
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm t;
    localtime_s(&t, &time);
    wchar_t timeBuf[32];
    swprintf(timeBuf, 32, L"%02d:%02d:%02d.%03d", t.tm_hour, t.tm_min, t.tm_sec, (int)ms.count());
    pe->time = timeBuf;

    // Size
    pe->size = std::to_wstring(len) + L"B";

    // Parse ENet header - try both header sizes, use whichever gives valid results
    if (len >= 4) {
        const uint8_t* d = (const uint8_t*)data;

        // Try hdr=4 first, then hdr=2
        int bestHdr = 4;
        int headerSizes[] = { 4, 2 };
        for (int hi = 0; hi < 2; hi++) {
            int h = headerSizes[hi];
            if (h + 4 > len) continue;
            uint8_t cmd = d[h] & 0x0F;
            if (cmd == 6 && h + 6 <= len) {
                int pOff = h + 6;
                if (pOff + 4 <= len) {
                    uint32_t gt = *(uint32_t*)(data + pOff);
                    if (gt <= 8) { bestHdr = h; break; }
                }
            }
            else if (cmd == 7 && h + 8 <= len) {
                int pOff = h + 8;
                if (pOff + 4 <= len) {
                    uint32_t gt = *(uint32_t*)(data + pOff);
                    if (gt <= 8) { bestHdr = h; break; }
                }
            }
            else if (cmd >= 1 && cmd <= 13) {
                bestHdr = h; break;
            }
        }

        int offset = bestHdr;
        if (offset + 4 <= len) {
            uint8_t cmdType = d[offset] & 0x0F;

            const wchar_t* cmdNames[] = {
                L"NONE", L"ACK", L"CONNECT", L"VERIFY_CONN", L"DISCONNECT",
                L"PING", L"RELIABLE", L"UNRELIABLE", L"---", L"FRAGMENT",
                L"---", L"UNSEQUENCED", L"BW_LIMIT", L"THROTTLE"
            };
            pe->enetCmd = (cmdType < 14) ? cmdNames[cmdType] : L"UNK";
            pe->gtMsg = L"-";
            pe->details = L"";

            int payloadOffset = -1;
            if (cmdType == 6 && offset + 6 <= len) {
                uint16_t dataLen = (d[offset + 4] << 8) | d[offset + 5];
                payloadOffset = offset + 6;
                pe->details = L"Len=" + std::to_wstring(dataLen);
            }
            else if (cmdType == 7 && offset + 8 <= len) {
                uint16_t dataLen = (d[offset + 6] << 8) | d[offset + 7];
                payloadOffset = offset + 8;
                pe->details = L"Len=" + std::to_wstring(dataLen);
            }
            else if (cmdType == 9 && offset + 24 <= len) {
                uint32_t fragNum = (d[offset + 16] << 24) | (d[offset + 17] << 16) | (d[offset + 18] << 8) | d[offset + 19];
                uint32_t fragCount = (d[offset + 12] << 24) | (d[offset + 13] << 16) | (d[offset + 14] << 8) | d[offset + 15];
                uint32_t totalLen = (d[offset + 20] << 24) | (d[offset + 21] << 16) | (d[offset + 22] << 8) | d[offset + 23];
                pe->details = L"Frag " + std::to_wstring(fragNum) + L"/" + std::to_wstring(fragCount)
                    + L" Total=" + std::to_wstring(totalLen);
                if (fragNum == 0) payloadOffset = offset + 24;
            }
            else if (cmdType == 2 && offset + 48 <= len) {
                uint32_t mtu = (d[offset + 12] << 24) | (d[offset + 13] << 16) | (d[offset + 14] << 8) | d[offset + 15];
                uint32_t channels = (d[offset + 20] << 24) | (d[offset + 21] << 16) | (d[offset + 22] << 8) | d[offset + 23];
                pe->details = L"MTU=" + std::to_wstring(mtu) + L" Ch=" + std::to_wstring(channels);
            }

            if (payloadOffset > 0 && payloadOffset + 4 <= len) {
                uint32_t gtType = *(uint32_t*)(data + payloadOffset);
                const wchar_t* gtNames[] = {
                    L"UNKNOWN", L"HELLO", L"TEXT", L"GAME_MSG",
                    L"GAME_PKT", L"ERROR", L"TRACK", L"LOG_REQ", L"LOG_RESP"
                };
                pe->gtMsg = (gtType < 9) ? gtNames[gtType] : (L"GT_" + std::to_wstring(gtType));

                if ((gtType == 2 || gtType == 3) && payloadOffset + 5 <= len) {
                    int textLen = len - payloadOffset - 4;
                    std::string raw(data + payloadOffset + 4, std::min(textLen, 120));
                    for (char& c : raw) { if (c < 32 || c > 126) c = '.'; }
                    pe->details = L"\"" + std::wstring(raw.begin(), raw.end()) + L"\"";
                }
                else if (gtType == 4 && payloadOffset + 5 <= len) {
                    uint8_t pktType = (uint8_t)data[payloadOffset + 4];
                    const wchar_t* pktNames[] = {
                        L"STATE", L"CALL_FUNC", L"UPD_STATUS", L"TILE_CHG",
                        L"MAP_DATA", L"TILE_UPD", L"TILE_DATA", L"---",
                        L"MOD_INV", L"ITEM_ACT", L"TILE_ACT"
                    };
                    std::wstring pktName = (pktType < 11) ? pktNames[pktType] : (L"PKT_" + std::to_wstring(pktType));
                    pe->details = pktName;

                    if (pktType == 0 && payloadOffset + 36 <= len) {
                        float x = *(float*)(data + payloadOffset + 28);
                        float y = *(float*)(data + payloadOffset + 32);
                        if (x != 0 || y != 0) {
                            pe->details += L" (" + std::to_wstring((int)x) + L"," + std::to_wstring((int)y) + L")";
                        }
                    }
                }
            }
        }
    }
    // Store raw bytes for hex dump on click
    pe->rawData.assign((uint8_t*)data, (uint8_t*)data + len);

    // === LIVE STREAM: auto-detect ENet header and show game data ===
    std::wstring* pStream = nullptr;
    if (len >= 6) {
        const uint8_t* d = (const uint8_t*)data;

        // Try both header sizes (4 and 2) - use whichever gives a valid GT type
        int headerSizes[] = { 4, 2 };
        for (int hi = 0; hi < 2 && !pStream; hi++) {
            int hdr = headerSizes[hi];
            if (hdr + 4 > len) continue;

            uint8_t cmd0 = d[hdr] & 0x0F;
            if (cmd0 != 6 && cmd0 != 7 && cmd0 != 9) continue;

            int payOff = -1;
            int payLen = 0;

            if (cmd0 == 6 && hdr + 6 <= len) {
                payLen = (d[hdr + 4] << 8) | d[hdr + 5];
                payOff = hdr + 6;
            }
            else if (cmd0 == 7 && hdr + 8 <= len) {
                payLen = (d[hdr + 6] << 8) | d[hdr + 7];
                payOff = hdr + 8;
            }
            else if (cmd0 == 9 && hdr + 24 <= len) {
                uint32_t fragNum = (d[hdr + 16] << 24) | (d[hdr + 17] << 16) | (d[hdr + 18] << 8) | d[hdr + 19];
                if (fragNum == 0) {
                    payLen = (d[hdr + 6] << 8) | d[hdr + 7];
                    payOff = hdr + 24;
                }
            }

            if (payOff < 0 || payOff + 4 > len) continue;

            uint32_t gtType = *(uint32_t*)(data + payOff);
            if (gtType > 8) continue; // Not a valid GT type with this header size, try next

            // Valid parse! Build the stream line
            pStream = new std::wstring();
            std::wstring dir = outbound ? L"\x25B6" : L"\x25C0";
            *pStream = pe->time + L"  " + dir + L"  ";

            if (gtType == 1) {
                *pStream += L"SERVER_HELLO";
            }
            else if ((gtType == 2 || gtType == 3) && payOff + 5 <= len) {
                int txtLen = std::min(payLen - 4, len - payOff - 4);
                std::wstring label = (gtType == 2) ? L"TEXT  " : L"MSG   ";
                if (txtLen > 0) {
                    std::string raw(data + payOff + 4, std::min(txtLen, 300));
                    for (char& c : raw) { if (c < 32 || c > 126) c = '.'; }
                    *pStream += label + std::wstring(raw.begin(), raw.end());
                }
                else {
                    *pStream += label + L"(empty)";
                }
            }
            else if (gtType == 4 && payOff + 60 <= len) {
                uint8_t pktType = d[payOff + 4];
                int32_t netID = *(int32_t*)(data + payOff + 8);
                uint32_t flags = *(uint32_t*)(data + payOff + 16);
                int32_t intVal = *(int32_t*)(data + payOff + 52);
                int32_t intX = *(int32_t*)(data + payOff + 20);
                int32_t intY = *(int32_t*)(data + payOff + 24);
                float posX = *(float*)(data + payOff + 28);
                float posY = *(float*)(data + payOff + 32);

                switch (pktType) {
                case 0:
                    *pStream += L"STATE  ";
                    if (flags & 0x20) *pStream += L"PUNCH ";
                    if (flags & 0x1) *pStream += L"LEFT ";
                    if (flags & 0x2) *pStream += L"MOVE ";
                    if (flags & 0x4) *pStream += L"JUMP ";
                    *pStream += L"NetID=" + std::to_wstring(netID);
                    if (posX != 0 || posY != 0)
                        *pStream += L" (" + std::to_wstring((int)posX) + L"," + std::to_wstring((int)posY) + L")";
                    break;
                case 1:  *pStream += L"CALL_FUNC  IntVal=" + std::to_wstring(intVal); break;
                case 3:
                    *pStream += L"TILE_CHANGE  (" + std::to_wstring(intX) + L"," + std::to_wstring(intY) + L") Item=" + std::to_wstring(intVal);
                    break;
                case 4:  *pStream += L"MAP_DATA"; break;
                case 5:
                    *pStream += L"TILE_UPDATE  (" + std::to_wstring(intX) + L"," + std::to_wstring(intY) + L")";
                    break;
                case 6:  *pStream += L"TILE_DATA"; break;
                case 8:  *pStream += L"MODIFY_INV  Item=" + std::to_wstring(intVal); break;
                case 9:  *pStream += L"ITEM_ACTIVATE  Item=" + std::to_wstring(intVal); break;
                case 10:
                    *pStream += L"TILE_ACTIVATE  (" + std::to_wstring(intX) + L"," + std::to_wstring(intY) + L")";
                    break;
                case 14: *pStream += L"CHAR_STATE  Flags=0x" + std::to_wstring(flags); break;
                case 18: *pStream += L"PING_REPLY"; break;
                case 19: *pStream += L"PING_REQ"; break;
                case 20:
                    *pStream += L"PUNCHED  NetID=" + std::to_wstring(netID) + L" (" + std::to_wstring(intX) + L"," + std::to_wstring(intY) + L")";
                    break;
                case 24: *pStream += L"DISCONNECT"; break;
                case 26:
                    *pStream += L"USE_DOOR  (" + std::to_wstring(intX) + L"," + std::to_wstring(intY) + L")";
                    break;
                default:
                    *pStream += L"PKT_" + std::to_wstring(pktType);
                    if (netID) *pStream += L" NetID=" + std::to_wstring(netID);
                    if (intVal) *pStream += L" IntVal=" + std::to_wstring(intVal);
                    break;
                }

                if (flags & 0x8) {
                    int extLen = (payOff + 60 <= len) ? *(int*)(data + payOff + 56) : 0;
                    *pStream += L"  +Ext=" + std::to_wstring(extLen) + L"B";
                }
            }
            else if (gtType == 4) {
                // GAME_PACKET but too short for full decode
                *pStream += L"GAME_PKT (short, " + std::to_wstring(len - payOff) + L"B payload)";
            }
            else if (gtType == 5) {
                *pStream += L"ERROR";
            }
            else {
                *pStream += L"GT_" + std::to_wstring(gtType);
            }

            // Hex snippet
            if (pStream) {
                int hexStart = payOff;
                int hexLen = std::min(len - hexStart, 16);
                if (hexLen > 0) {
                    *pStream += L"  [";
                    for (int h = 0; h < hexLen; h++) {
                        wchar_t hx[4];
                        swprintf(hx, 4, L"%02X", (uint8_t)data[hexStart + h]);
                        *pStream += hx;
                        if (h < hexLen - 1) *pStream += L" ";
                    }
                    if (len - hexStart > 16) *pStream += L"...";
                    *pStream += L"]";
                }
            }
        }
    }

    UINT msg = outbound ? WM_ADD_PKT_OUT : WM_ADD_PKT_IN;
    if (!PostMessageW(g_hWnd, msg, 0, (LPARAM)pe)) {
        delete pe;
    }

    // Post stream line
    if (pStream) {
        if (!PostMessageW(g_hWnd, WM_ADD_STREAM, 0, (LPARAM)pStream)) {
            delete pStream;
        }
    }
}

// ============================================================
//  Forward Declarations
// ============================================================
void KillSurgicalObjects(DWORD targetPid);
DWORD WINAPI ProxyListenerThread(LPVOID param);

// ============================================================
//  Process Helpers
// ============================================================
void SetProcessSuspendedState(DWORD pid, bool suspend) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (hThread) {
                        if (suspend) SuspendThread(hThread);
                        else ResumeThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }
}

void KillAllGrowtopia() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (wcsstr(pe.szExeFile, L"Growtopia.exe")) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                    Log(L"Terminated PID: " + std::to_wstring(pe.th32ProcessID));
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    Log(L"Cleanup complete.");
}

void RandomizeMAC() {
    HKEY hKey;
    const wchar_t* regPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        wchar_t newMac[13];
        swprintf(newMac, 13, L"02%010X", rand() % 0xFFFFFFFFFF);
        if (RegSetValueExW(hKey, L"NetworkAddress", 0, REG_SZ, (BYTE*)newMac, (wcslen(newMac) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
            Log(L"MAC spoofed: " + std::wstring(newMac));
        }
        RegCloseKey(hKey);
    }
    else {
        Log(L"MAC spoof failed (run as admin?)");
    }
}

struct QueryData { HANDLE h; BYTE* buffer; ULONG size; NTSTATUS status; };

DWORD WINAPI SafeQueryThread(LPVOID param) {
    QueryData* qd = (QueryData*)param;
    auto pNtQueryObject = (tNtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
    if (pNtQueryObject) {
        qd->status = pNtQueryObject(qd->h, (OBJECT_INFORMATION_CLASS)1, qd->buffer, qd->size, NULL);
    }
    return 0;
}

bool InjectDLL(DWORD pid, const std::string& dllPath) {
    Log(L"Injecting DLL...");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;
    LPVOID pRemoteBuf = VirtualAllocEx(hProc, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf) {
        WriteProcessMemory(hProc, pRemoteBuf, dllPath.c_str(), dllPath.size() + 1, NULL);
        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
            pRemoteBuf, 0, NULL);
        if (hThread) { WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread); }
    }
    CloseHandle(hProc);
    return true;
}

// ============================================================
//  SOCKS5 Proxy
// ============================================================
struct ProxySettings {
    u_short localPort;
    std::string proxyIp;
    u_short proxyPort;
    std::string user;
    std::string pass;
};

bool AuthenticateSocks(SOCKET tcpSock, std::string user, std::string pass) {
    char handshake[] = { 0x05, 0x01, 0x02 };
    send(tcpSock, handshake, 3, 0);
    char response[2];
    recv(tcpSock, response, 2, 0);
    if (response[1] != 0x02) return false;
    std::string authPkg;
    authPkg += (char)0x01;
    authPkg += (char)user.length();
    authPkg += user;
    authPkg += (char)pass.length();
    authPkg += pass;
    send(tcpSock, authPkg.c_str(), (int)authPkg.length(), 0);
    recv(tcpSock, response, 2, 0);
    return response[1] == 0x00;
}

DWORD WINAPI ProxyListenerThread(LPVOID param) {
    ProxySettings* ps = (ProxySettings*)param;

    sockaddr_in proxyAddr = { 0 };
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(ps->proxyPort);
    inet_pton(AF_INET, ps->proxyIp.c_str(), &proxyAddr.sin_addr);

    // --- LOCAL LISTENERS (persistent, survive reconnects) ---
    SOCKET localUdpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET localTcpSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    int opt = 1;
    setsockopt(localUdpSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    setsockopt(localTcpSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in bindAddr = { 0 };
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(ps->localPort);
    bindAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(localUdpSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        Log(L"UDP bind failed port " + std::to_wstring(ps->localPort));
        return 0;
    }
    if (bind(localTcpSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        Log(L"TCP bind failed port " + std::to_wstring(ps->localPort));
        return 0;
    }
    listen(localTcpSock, SOMAXCONN);
    Log(L"Relay active on port " + std::to_wstring(ps->localPort));

    // Persistent state across reconnects
    uint32_t currentTargetIP = 0;
    uint16_t currentTargetPort = 0;
    bool gameFound = false;
    sockaddr_in gameClientAddr = { 0 };
    SOCKET gameTcpSock = INVALID_SOCKET;
    SOCKET proxyTcpSock = INVALID_SOCKET;

    // === OUTER RECONNECTION LOOP ===
    while (true) {
        SOCKET udpCtrlSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (udpCtrlSock == INVALID_SOCKET) {
            Log(L"Proxy: socket creation failed");
            Sleep(3000); continue;
        }

        if (connect(udpCtrlSock, (sockaddr*)&proxyAddr, sizeof(proxyAddr)) == SOCKET_ERROR) {
            Log(L"Proxy: control connection failed, retry in 3s...");
            closesocket(udpCtrlSock); Sleep(3000); continue;
        }

        if (!AuthenticateSocks(udpCtrlSock, ps->user, ps->pass)) {
            Log(L"Proxy: SOCKS5 auth failed, retry in 3s...");
            closesocket(udpCtrlSock); Sleep(3000); continue;
        }

        char udpAssoc[] = { 0x05, 0x03, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x00 };
        u_short localPortNet = htons(ps->localPort);
        memcpy(&udpAssoc[8], &localPortNet, 2);
        send(udpCtrlSock, udpAssoc, 10, 0);
        char reply[10];
        int recvd = recv(udpCtrlSock, reply, 10, 0);
        if (recvd <= 0 || reply[1] != 0x00) {
            Log(L"UDP Associate rejected, retry in 3s...");
            closesocket(udpCtrlSock); Sleep(3000); continue;
        }

        sockaddr_in relayAddr = { 0 };
        relayAddr.sin_family = AF_INET;
        memcpy(&relayAddr.sin_addr, &reply[4], 4);
        memcpy(&relayAddr.sin_port, &reply[8], 2);
        if (relayAddr.sin_addr.s_addr == 0) {
            inet_pton(AF_INET, ps->proxyIp.c_str(), &relayAddr.sin_addr);
        }

        char rIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &relayAddr.sin_addr, rIP, INET_ADDRSTRLEN);
        Log(L"SOCKS5 relay established -> " + std::wstring(rIP, rIP + strlen(rIP))
            + L":" + std::to_wstring(ntohs(relayAddr.sin_port)));
        DWORD lastRelayResponse = GetTickCount();
        bool relayAlive = true;
        char buf[8192];

        // === INNER RELAY LOOP ===
        while (relayAlive) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(localUdpSock, &readSet);
            FD_SET(localTcpSock, &readSet);
            FD_SET(udpCtrlSock, &readSet);
            if (gameTcpSock != INVALID_SOCKET) FD_SET(gameTcpSock, &readSet);
            if (proxyTcpSock != INVALID_SOCKET) FD_SET(proxyTcpSock, &readSet);

            timeval tv = { 5, 0 };
            int sel = select(0, &readSet, NULL, NULL, &tv);

            if (sel == 0) {
                if (gameFound && (GetTickCount() - lastRelayResponse > 30000)) {
                    Log(L"No relay response for 30s, reconnecting...");
                    relayAlive = false; break;
                }
                continue;
            }
            if (sel < 0) break;

            if (FD_ISSET(udpCtrlSock, &readSet)) {
                char probe[1];
                if (recv(udpCtrlSock, probe, 1, 0) <= 0) {
                    Log(L"UDP ASSOCIATE control dropped, reconnecting...");
                    relayAlive = false; break;
                }
            }

            // --- A. UDP ---
            if (FD_ISSET(localUdpSock, &readSet)) {
                sockaddr_in senderAddr;
                int senderLen = sizeof(senderAddr);
                int bytes = recvfrom(localUdpSock, buf, sizeof(buf), 0, (sockaddr*)&senderAddr, &senderLen);

                if (bytes > 0) {
                    if (bytes == 10 && memcmp(buf, "META", 4) == 0) {
                        memcpy(&currentTargetIP, buf + 4, 4);
                        memcpy(&currentTargetPort, buf + 8, 2);
                        Log(L"[META] Target updated: " + std::to_wstring(ntohs(currentTargetPort)));
                        gameFound = true;
                        continue;
                    }

                    if (gameFound &&
                        senderAddr.sin_addr.s_addr == relayAddr.sin_addr.s_addr &&
                        senderAddr.sin_port == relayAddr.sin_port) {

                        lastRelayResponse = GetTickCount();
                        int headerSize = 0;
                        if (bytes >= 4) {
                            uint8_t atyp = (uint8_t)buf[3];
                            if (atyp == 0x01) headerSize = 10;
                            else if (atyp == 0x04) headerSize = 22;
                            else if (atyp == 0x03 && bytes >= 5) headerSize = 4 + 1 + (uint8_t)buf[4] + 2;
                        }
                        if (headerSize > 0 && bytes > headerSize) {
                            LogPacket(buf + headerSize, bytes - headerSize, false);
                            sendto(localUdpSock, buf + headerSize, bytes - headerSize, 0,
                                (sockaddr*)&gameClientAddr, sizeof(gameClientAddr));
                        }
                    }
                    else if (senderAddr.sin_addr.s_addr == inet_addr("127.0.0.1")) {
                        gameFound = true;
                        gameClientAddr = senderAddr;
                        if (currentTargetIP == 0 || currentTargetPort == htons(443)) continue;

                        LogPacket(buf, bytes, true);

                        std::vector<char> socksPacket;
                        socksPacket.push_back(0x00);
                        socksPacket.push_back(0x00);
                        socksPacket.push_back(0x00);
                        socksPacket.push_back(0x01);
                        socksPacket.insert(socksPacket.end(), (char*)&currentTargetIP, (char*)&currentTargetIP + 4);
                        socksPacket.insert(socksPacket.end(), (char*)&currentTargetPort, (char*)&currentTargetPort + 2);
                        socksPacket.insert(socksPacket.end(), buf, buf + bytes);

                        sendto(localUdpSock, socksPacket.data(), (int)socksPacket.size(), 0,
                            (sockaddr*)&relayAddr, sizeof(relayAddr));
                    }
                }
            }

            // --- B. TCP ACCEPT ---
            if (FD_ISSET(localTcpSock, &readSet)) {
                sockaddr_in clientAddr;
                int clientLen = sizeof(clientAddr);
                SOCKET newSock = accept(localTcpSock, (sockaddr*)&clientAddr, &clientLen);

                if (newSock != INVALID_SOCKET) {
                    if (currentTargetIP == 0) {
                        Log(L"[TCP] Waiting for META...");
                        for (int retry = 0; retry < 50 && currentTargetIP == 0; retry++) {
                            fd_set metaSet;
                            FD_ZERO(&metaSet);
                            FD_SET(localUdpSock, &metaSet);
                            timeval mtv = { 0, 10000 };
                            if (select(0, &metaSet, NULL, NULL, &mtv) > 0) {
                                sockaddr_in sa; int sal = sizeof(sa);
                                int b = recvfrom(localUdpSock, buf, sizeof(buf), 0, (sockaddr*)&sa, &sal);
                                if (b == 10 && memcmp(buf, "META", 4) == 0) {
                                    memcpy(&currentTargetIP, buf + 4, 4);
                                    memcpy(&currentTargetPort, buf + 8, 2);
                                    Log(L"[META] Got target during TCP wait");
                                }
                            }
                            Sleep(10);
                        }
                        if (currentTargetIP == 0) {
                            Log(L"[TCP] No META, dropping");
                            closesocket(newSock); continue;
                        }
                    }

                    if (gameTcpSock != INVALID_SOCKET) closesocket(gameTcpSock);
                    if (proxyTcpSock != INVALID_SOCKET) { shutdown(proxyTcpSock, SD_BOTH); closesocket(proxyTcpSock); }

                    gameTcpSock = newSock;
                    proxyTcpSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

                    if (connect(proxyTcpSock, (sockaddr*)&proxyAddr, sizeof(proxyAddr)) == SOCKET_ERROR) {
                        Log(L"[TCP] SOCKS5 proxy unreachable");
                        closesocket(gameTcpSock); gameTcpSock = INVALID_SOCKET; continue;
                    }
                    if (!AuthenticateSocks(proxyTcpSock, ps->user, ps->pass)) {
                        Log(L"[TCP] SOCKS5 auth failed");
                        closesocket(gameTcpSock); gameTcpSock = INVALID_SOCKET; continue;
                    }

                    unsigned char tcpConnectReq[10] = { 0x05, 0x01, 0x00, 0x01 };
                    memcpy(&tcpConnectReq[4], &currentTargetIP, 4);
                    memcpy(&tcpConnectReq[8], &currentTargetPort, 2);
                    send(proxyTcpSock, (char*)tcpConnectReq, 10, 0);

                    char tcpReply[10];
                    recv(proxyTcpSock, tcpReply, 10, 0);
                    if (tcpReply[1] == 0x00) {
                        Log(L"[TCP] Tunnel to port " + std::to_wstring(ntohs(currentTargetPort)));
                    }
                    else {
                        Log(L"[TCP] Tunnel refused: " + std::to_wstring((int)tcpReply[1]));
                        closesocket(gameTcpSock); gameTcpSock = INVALID_SOCKET;
                    }
                }
            }

            // --- C. TCP DATA ---
            if (gameTcpSock != INVALID_SOCKET && FD_ISSET(gameTcpSock, &readSet)) {
                int b = recv(gameTcpSock, buf, sizeof(buf), 0);
                if (b > 0) { send(proxyTcpSock, buf, b, 0); }
                else { closesocket(gameTcpSock); gameTcpSock = INVALID_SOCKET; }
            }

            if (proxyTcpSock != INVALID_SOCKET && FD_ISSET(proxyTcpSock, &readSet)) {
                int b = recv(proxyTcpSock, buf, sizeof(buf), 0);
                if (b > 0) {
                    for (int i = 0; i < b - 5; i++) {
                        if (memcmp(&buf[i], "host|", 5) == 0) {
                            std::string raw(buf + i, b - i);
                            size_t hostPos = 5;
                            size_t pipePos = raw.find("|", hostPos);
                            size_t portLabelPos = raw.find("port|", pipePos);
                            size_t portPos = portLabelPos + 5;
                            size_t portPipePos = raw.find("|", portPos);
                            if (pipePos != std::string::npos && portLabelPos != std::string::npos) {
                                std::string newIp = raw.substr(hostPos, pipePos - hostPos);
                                std::string newPortStr = raw.substr(portPos, portPipePos - portPos);
                                currentTargetIP = inet_addr(newIp.c_str());
                                currentTargetPort = htons((uint16_t)std::stoi(newPortStr));
                                Log(L"Redirect -> " + std::wstring(newIp.begin(), newIp.end())
                                    + L":" + std::to_wstring(std::stoi(newPortStr)));
                            }
                            break;
                        }
                    }
                    send(gameTcpSock, buf, b, 0);
                }
                else {
                    closesocket(proxyTcpSock); proxyTcpSock = INVALID_SOCKET;
                }
            }
        } // end inner relay loop

        // Cleanup SOCKS5 (keep local listeners alive)
        closesocket(udpCtrlSock);
        if (gameTcpSock != INVALID_SOCKET) { closesocket(gameTcpSock); gameTcpSock = INVALID_SOCKET; }
        if (proxyTcpSock != INVALID_SOCKET) { closesocket(proxyTcpSock); proxyTcpSock = INVALID_SOCKET; }

        // Reset state so the game goes through a clean auth cycle
        gameFound = false;
        currentTargetIP = 0;
        currentTargetPort = 0;

        Log(L"Reconnecting SOCKS5 in 2s...");
        Sleep(2000);
    } // end outer reconnection loop

    closesocket(localUdpSock);
    closesocket(localTcpSock);
    return 0;
}

// ============================================================
//  Handle Nuking
// ============================================================
void KillSurgicalObjects(DWORD targetPid) {
    auto NtQuerySystemInformation = (tNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    auto NtDuplicateObject = (tNtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
    auto NtQueryObject = (tNtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

    ULONG bufferSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
    while (NtQuerySystemInformation(SystemHandleInformation, handleInfo, bufferSize, NULL) == 0xC0000004) {
        bufferSize *= 2;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfo, bufferSize);
    }

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProcess) { free(handleInfo); return; }

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        if (handleInfo->Handles[i].UniqueProcessId != targetPid) continue;
        HANDLE dupHandle = NULL;
        if (NtDuplicateObject(hProcess, (HANDLE)handleInfo->Handles[i].HandleValue,
            GetCurrentProcess(), &dupHandle, 0, 0, 0) == 0) {
            BYTE nameBuffer[1024];
            ULONG returnLength;
            if (NtQueryObject(dupHandle, (OBJECT_INFORMATION_CLASS)ObjectNameInformation,
                nameBuffer, sizeof(nameBuffer), &returnLength) == 0) {
                UNICODE_STRING* objectName = (UNICODE_STRING*)nameBuffer;
                if (objectName->Buffer && objectName->Length > 0) {
                    if (wcsstr(objectName->Buffer, L"Growtopia")) {
                        if (!wcsstr(objectName->Buffer, L"HarddiskVolume3")) {
                            NtDuplicateObject(hProcess, (HANDLE)handleInfo->Handles[i].HandleValue,
                                NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
                        }
                    }
                }
            }
            CloseHandle(dupHandle);
        }
    }
    free(handleInfo);
    CloseHandle(hProcess);
}

// ============================================================
//  Launch Sequence
// ============================================================
struct WindowSearchData { DWORD targetPID; HWND foundHWND; };

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    WindowSearchData* data = (WindowSearchData*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == data->targetPID && GetWindow(hwnd, GW_OWNER) == (HWND)0 && IsWindowVisible(hwnd)) {
        data->foundHWND = hwnd;
        return FALSE;
    }
    return TRUE;
}

struct LaunchData { std::wstring path; int amount; };

DWORD WINAPI LaunchSequenceThread(LPVOID param) {
    LaunchData* ld = (LaunchData*)param;
    std::vector<DWORD> activePids;

    std::wstring gameDir = ld->path;
    size_t lastSlash = gameDir.find_last_of(L"\\/");
    if (std::wstring::npos != lastSlash) gameDir = gameDir.substr(0, lastSlash);

    for (int i = 1; i <= ld->amount; i++) {
        Log(L"--- Instance " + std::to_wstring(i) + L" ---");
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        LPWCH systemEnv = GetEnvironmentStringsW();
        if (!systemEnv) { Log(L"Failed to get environment"); return 0; }

        std::wstring proxyVar = L"GT_PROXY=127.0.0.1:" + std::to_wstring(1080 + i);
        std::vector<wchar_t> finalEnv;
        finalEnv.insert(finalEnv.end(), proxyVar.begin(), proxyVar.end());
        finalEnv.push_back(L'\0');
        LPWCH curr = systemEnv;
        while (*curr) {
            int len = lstrlenW(curr);
            finalEnv.insert(finalEnv.end(), curr, curr + len);
            finalEnv.push_back(L'\0');
            curr += len + 1;
        }
        finalEnv.push_back(L'\0');
        FreeEnvironmentStringsW(systemEnv);

        ProxySettings* settings = new ProxySettings();
        settings->localPort = (u_short)(1080 + i);
        settings->proxyIp = "127.0.0.1";
        settings->proxyPort = 1080;
        settings->user = "veeoesjp";
        settings->pass = "labwfw9s12222xo";

        CreateThread(NULL, 0, ProxyListenerThread, settings, 0, NULL);

        if (CreateProcessW(ld->path.c_str(), NULL, NULL, NULL, FALSE,
            CREATE_UNICODE_ENVIRONMENT, finalEnv.data(), gameDir.c_str(), &si, &pi)) {
            activePids.push_back(pi.dwProcessId);

            Log(L"Waiting for window...");
            for (int retry = 0; retry < 40; retry++) {
                WindowSearchData sd = { pi.dwProcessId, NULL };
                EnumWindows(EnumWindowsProc, (LPARAM)&sd);
                if (sd.foundHWND) break;
                Sleep(500);
            }
            Sleep(4000);
            std::string fullDllPath = "C:\\Users\\neekewi\\source\\repos\\MyProject_GUI\\x64\\Release\\Yalla.dll";
            InjectDLL(pi.dwProcessId, fullDllPath);
            Log(L"Injected port " + std::to_wstring(1080 + i));

            if (i < ld->amount) {
                SetProcessSuspendedState(pi.dwProcessId, true);
                KillSurgicalObjects(pi.dwProcessId);
                Sleep(500);
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        Sleep(1000);
    }

    Log(L"Thawing all instances...");
    for (DWORD pid : activePids) SetProcessSuspendedState(pid, false);
    Log(L"Launch complete!");
    EnableWindow(hBtnLaunch, TRUE);
    delete ld;
    return 0;
}

// ============================================================
//  UI: Create ListView with columns
// ============================================================
HWND CreatePacketListView(HWND parent, int id, int x, int y, int w, int h) {
    HWND hLV = CreateWindowExW(0, WC_LISTVIEWW, NULL,
        WS_CHILD | WS_CLIPSIBLINGS | LVS_REPORT | LVS_SINGLESEL | LVS_NOSORTHEADER | WS_BORDER,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);

    ListView_SetExtendedListViewStyle(hLV,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

    // Set dark background/text colors
    ListView_SetBkColor(hLV, Theme::surface);
    ListView_SetTextBkColor(hLV, Theme::surface);
    ListView_SetTextColor(hLV, Theme::text);

    // Columns: Time | Size | ENet Cmd | GT Msg | Details
    struct { const wchar_t* name; int width; } cols[] = {
        { L"Time",     95 },
        { L"Size",     55 },
        { L"ENet",     90 },
        { L"GT Msg",   90 },
        { L"Details", 350 },
    };

    for (int i = 0; i < 5; i++) {
        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        lvc.fmt = LVCFMT_LEFT;
        lvc.cx = cols[i].width;
        lvc.pszText = (LPWSTR)cols[i].name;
        ListView_InsertColumn(hLV, i, &lvc);
    }

    return hLV;
}

// ============================================================
//  Hex Dump Formatter
// ============================================================
std::wstring FormatHexDump(const std::vector<uint8_t>& data) {
    if (data.empty()) return L"(no data)";

    std::wstringstream ss;
    int len = (int)data.size();

    // Header
    ss << L"  Offset   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\r\n";
    ss << L"  ------   -----------------------------------------------   ----------------\r\n";

    for (int row = 0; row < len; row += 16) {
        // Offset
        wchar_t off[16];
        swprintf(off, 16, L"  %06X   ", row);
        ss << off;

        // Hex bytes
        for (int col = 0; col < 16; col++) {
            if (col == 8) ss << L" "; // gap in middle
            if (row + col < len) {
                wchar_t hex[4];
                swprintf(hex, 4, L"%02X ", data[row + col]);
                ss << hex;
            }
            else {
                ss << L"   ";
            }
        }

        // ASCII
        ss << L"  ";
        for (int col = 0; col < 16 && row + col < len; col++) {
            uint8_t b = data[row + col];
            ss << (wchar_t)((b >= 32 && b <= 126) ? b : L'.');
        }
        ss << L"\r\n";
    }

    // Decoded summary
    ss << L"\r\n  --- Decoded ---\r\n";
    ss << L"  Total: " << len << L" bytes\r\n";

    if (len >= 4) {
        // ENet header
        uint16_t peerID = (data[0] << 8) | data[1];
        uint16_t sentTime = (data[2] << 8) | data[3];
        ss << L"  ENet PeerID: " << (peerID >> 4) << L"  SentTime: " << sentTime << L"\r\n";

        // Walk commands
        int offset = 4;
        int cmdIdx = 0;
        while (offset + 4 <= len) {
            uint8_t cmd = data[offset] & 0x0F;
            uint8_t flags = data[offset] & 0xF0;
            uint8_t channel = data[offset + 1];
            uint16_t relSeq = (data[offset + 2] << 8) | data[offset + 3];

            const wchar_t* cmdNames[] = {
                L"NONE", L"ACK", L"CONNECT", L"VERIFY_CONN", L"DISCONNECT",
                L"PING", L"RELIABLE", L"UNRELIABLE", L"---", L"FRAGMENT",
                L"---", L"UNSEQUENCED", L"BW_LIMIT", L"THROTTLE"
            };
            std::wstring cmdName = (cmd < 14) ? cmdNames[cmd] : (L"UNK_" + std::to_wstring(cmd));

            ss << L"\r\n  [CMD " << cmdIdx << L"] " << cmdName
                << L"  Flags=0x" << std::hex << (int)flags << std::dec
                << L"  Ch=" << (int)channel
                << L"  Seq=" << relSeq << L"\r\n";

            // Parse specific commands
            if (cmd == 1 && offset + 8 <= len) { // ACK
                uint16_t ackSeq = (data[offset + 4] << 8) | data[offset + 5];
                uint16_t ackTime = (data[offset + 6] << 8) | data[offset + 7];
                ss << L"    AckSeq=" << ackSeq << L"  AckTime=" << ackTime << L"\r\n";
                offset += 8;
            }
            else if (cmd == 2 && offset + 48 <= len) { // CONNECT
                uint32_t mtu = (data[offset + 12] << 24) | (data[offset + 13] << 16) | (data[offset + 14] << 8) | data[offset + 15];
                uint32_t chCount = (data[offset + 20] << 24) | (data[offset + 21] << 16) | (data[offset + 22] << 8) | data[offset + 23];
                uint32_t connID = (data[offset + 36] << 24) | (data[offset + 37] << 16) | (data[offset + 38] << 8) | data[offset + 39];
                ss << L"    MTU=" << mtu << L"  Channels=" << chCount
                    << L"  ConnectID=0x" << std::hex << connID << std::dec << L"\r\n";
                offset += 48;
            }
            else if (cmd == 3 && offset + 44 <= len) { // VERIFY_CONNECT
                offset += 44;
            }
            else if (cmd == 4) { // DISCONNECT
                if (offset + 8 <= len) {
                    uint32_t ddata = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
                    ss << L"    Data=0x" << std::hex << ddata << std::dec << L"\r\n";
                }
                offset += 8;
            }
            else if (cmd == 5) { // PING
                offset += 4;
            }
            else if (cmd == 6 && offset + 8 <= len) { // RELIABLE
                uint16_t dataLen = (data[offset + 6] << 8) | data[offset + 7];
                ss << L"    DataLen=" << dataLen << L"\r\n";
                int payOff = offset + 8;
                if (payOff + 4 <= len && payOff < offset + 8 + dataLen) {
                    uint32_t gtType = *(uint32_t*)(data.data() + payOff);
                    const wchar_t* gtNames[] = {
                        L"UNKNOWN", L"HELLO", L"TEXT", L"GAME_MSG",
                        L"GAME_PKT", L"ERROR", L"TRACK", L"LOG_REQ", L"LOG_RESP"
                    };
                    std::wstring gtName = (gtType < 9) ? gtNames[gtType] : (L"GT_" + std::to_wstring(gtType));
                    ss << L"    GT Message: " << gtName << L"\r\n";

                    if ((gtType == 2 || gtType == 3) && payOff + 5 <= len) {
                        int txtLen = std::min((int)dataLen - 4, len - payOff - 4);
                        if (txtLen > 0) {
                            std::string raw((char*)data.data() + payOff + 4, std::min(txtLen, 500));
                            for (char& c : raw) { if (c < 32 || c > 126) c = '.'; }
                            std::wstring wtxt(raw.begin(), raw.end());
                            ss << L"    Text: \"" << wtxt << L"\"\r\n";
                        }
                    }
                    else if (gtType == 4 && payOff + 60 <= len) {
                        uint8_t pktType = data[payOff + 4];
                        const wchar_t* pktNames[] = {
                            L"STATE", L"CALL_FUNC", L"UPD_STATUS", L"TILE_CHG",
                            L"MAP_DATA", L"TILE_UPD", L"TILE_DATA", L"---",
                            L"MOD_INV", L"ITEM_ACT", L"TILE_ACT"
                        };
                        std::wstring pktName = (pktType < 11) ? pktNames[pktType] : (L"PKT_" + std::to_wstring(pktType));
                        ss << L"    PacketType: " << pktName << L" (" << (int)pktType << L")\r\n";

                        int32_t netID = *(int32_t*)(data.data() + payOff + 8);
                        float x = *(float*)(data.data() + payOff + 28);
                        float y2 = *(float*)(data.data() + payOff + 32);
                        uint32_t pktFlags = *(uint32_t*)(data.data() + payOff + 16);
                        int32_t intVal = *(int32_t*)(data.data() + payOff + 52);
                        ss << L"    NetID=" << netID << L"  Pos=(" << (int)x << L"," << (int)y2 << L")"
                            << L"  Flags=0x" << std::hex << pktFlags << std::dec
                            << L"  IntVal=" << intVal << L"\r\n";
                    }
                }
                offset += 8 + dataLen;
            }
            else if (cmd == 7 && offset + 10 <= len) { // UNRELIABLE
                uint16_t unrelSeq = (data[offset + 4] << 8) | data[offset + 5];
                uint16_t dataLen = (data[offset + 8] << 8) | data[offset + 9];
                ss << L"    UnrelSeq=" << unrelSeq << L"  DataLen=" << dataLen << L"\r\n";
                offset += 10 + dataLen;
            }
            else if (cmd == 9 && offset + 28 <= len) { // FRAGMENT
                uint16_t dataLen = (data[offset + 8] << 8) | data[offset + 9];
                uint32_t fragCount = (data[offset + 12] << 24) | (data[offset + 13] << 16) | (data[offset + 14] << 8) | data[offset + 15];
                uint32_t fragNum = (data[offset + 16] << 24) | (data[offset + 17] << 16) | (data[offset + 18] << 8) | data[offset + 19];
                uint32_t totalLen = (data[offset + 20] << 24) | (data[offset + 21] << 16) | (data[offset + 22] << 8) | data[offset + 23];
                uint32_t fragOff = (data[offset + 24] << 24) | (data[offset + 25] << 16) | (data[offset + 26] << 8) | data[offset + 27];
                ss << L"    Frag " << fragNum << L"/" << fragCount
                    << L"  Total=" << totalLen << L"  Offset=" << fragOff
                    << L"  DataLen=" << dataLen << L"\r\n";
                offset += 28 + dataLen;
            }
            else {
                // Unknown or can't parse further
                ss << L"    (cannot parse further)\r\n";
                break;
            }
            cmdIdx++;
        }
    }

    return ss.str();
}

void ShowHexForPacket(HWND hHex, const std::vector<std::vector<uint8_t>>& store, int index) {
    std::lock_guard<std::mutex> lock(g_pktDataMutex);
    if (index >= 0 && index < (int)store.size()) {
        std::wstring hex = FormatHexDump(store[index]);
        SetWindowTextW(hHex, hex.c_str());
    }
}

void AddPacketToListView(HWND hLV, const PacketEntry* pe, int& count) {
    LVITEMW lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = count++;
    lvi.pszText = (LPWSTR)pe->time.c_str();
    int idx = ListView_InsertItem(hLV, &lvi);

    ListView_SetItemText(hLV, idx, 1, (LPWSTR)pe->size.c_str());
    ListView_SetItemText(hLV, idx, 2, (LPWSTR)pe->enetCmd.c_str());
    ListView_SetItemText(hLV, idx, 3, (LPWSTR)pe->gtMsg.c_str());
    ListView_SetItemText(hLV, idx, 4, (LPWSTR)pe->details.c_str());

    // Auto-scroll to bottom
    ListView_EnsureVisible(hLV, idx, FALSE);
}

// ============================================================
//  Tab Subclass - paint dark background
// ============================================================
WNDPROC g_OldTabProc = NULL;

LRESULT CALLBACK TabSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_ERASEBKGND) {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH hBr = CreateSolidBrush(Theme::bg);
        FillRect(hdc, &rc, hBr);
        DeleteObject(hBr);
        return 1;
    }
    return CallWindowProcW(g_OldTabProc, hwnd, uMsg, wParam, lParam);
}

// ============================================================
//  UI: Layout / Resize
// ============================================================
void LayoutControls(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right;
    int H = rc.bottom;
    int pad = 12;

    // Row 1: Path label + edit
    int y = pad;
    MoveWindow(hLblPath, pad, y, 120, 18, TRUE);
    y += 20;
    MoveWindow(hGameEdit, pad, y, W - pad * 2, 24, TRUE);
    y += 32;

    // Row 2: Instances edit + buttons
    MoveWindow(hLblAmount, pad, y + 2, 65, 18, TRUE);
    MoveWindow(hAmountEdit, pad + 68, y, 50, 24, TRUE);

    int btnX = pad + 140;
    MoveWindow(hBtnLaunch, btnX, y - 4, 120, 32, TRUE);
    MoveWindow(hBtnKillAll, btnX + 130, y - 4, 120, 32, TRUE);
    MoveWindow(hBtnClear, btnX + 260, y - 4, 90, 32, TRUE);
    y += 36;

    // Tab control fills the rest
    int tabY = y;
    int tabH = H - tabY;
    if (tabH < 50) tabH = 50;
    MoveWindow(hTabCtrl, 0, tabY, W, tabH, TRUE);

    // Get the content area inside the tab (below the tab headers)
    // TabCtrl_AdjustRect with FALSE shrinks the rect to the display area
    RECT tabRc = { 0, 0, W, tabH };
    TabCtrl_AdjustRect(hTabCtrl, FALSE, &tabRc);

    // These are relative to the tab control, convert to parent coords
    int cX = tabRc.left;
    int cY = tabY + tabRc.top;
    int cW = tabRc.right - tabRc.left;
    int cH = tabRc.bottom - tabRc.top;

    MoveWindow(hLogList, cX, cY, cW, cH, TRUE);

    // Split packet tabs: top = list, bottom = hex dump
    int listH = (cH * 55) / 100;
    int hexY = cY + listH + 2;
    int hexH = cH - listH - 2;
    if (hexH < 60) { listH = cH - 62; hexY = cY + listH + 2; hexH = 60; }

    MoveWindow(hPktOutLV, cX, cY, cW, listH, TRUE);
    MoveWindow(hPktInLV, cX, cY, cW, listH, TRUE);
    MoveWindow(hHexOut, cX, hexY, cW, hexH, TRUE);
    MoveWindow(hHexIn, cX, hexY, cW, hexH, TRUE);
    MoveWindow(hStreamList, cX, cY, cW, cH, TRUE);
}

void SwitchTab(int tab) {
    g_currentTab = tab;
    ShowWindow(hLogList, tab == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(hPktOutLV, tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(hHexOut, tab == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(hPktInLV, tab == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(hHexIn, tab == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(hStreamList, tab == 3 ? SW_SHOW : SW_HIDE);

    HWND toTop[] = { NULL, NULL };
    if (tab == 0) { toTop[0] = hLogList; }
    else if (tab == 1) { toTop[0] = hPktOutLV; toTop[1] = hHexOut; }
    else if (tab == 2) { toTop[0] = hPktInLV;  toTop[1] = hHexIn; }
    else { toTop[0] = hStreamList; }
    for (int i = 0; i < 2 && toTop[i]; i++)
        SetWindowPos(toTop[i], HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// ============================================================
//  Custom draw button
// ============================================================
void DrawButton(LPDRAWITEMSTRUCT dis) {
    HWND btn = dis->hwndItem;
    int id = dis->CtlID;
    bool pressed = (dis->itemState & ODS_SELECTED);
    bool disabled = (dis->itemState & ODS_DISABLED);

    COLORREF bgColor = Theme::surfaceAlt;
    COLORREF txtColor = Theme::text;

    if (id == ID_BTN_LAUNCH) bgColor = pressed ? RGB(60, 100, 60) : Theme::success;
    else if (id == ID_BTN_KILLALL) bgColor = pressed ? RGB(150, 40, 40) : Theme::danger;
    else if (id == ID_BTN_CLEAR) bgColor = pressed ? RGB(50, 55, 70) : Theme::surfaceAlt;

    if (disabled) { bgColor = Theme::surface; txtColor = Theme::textDim; }

    // Fill
    HBRUSH hBr = CreateSolidBrush(bgColor);
    HBRUSH hBrBorder = CreateSolidBrush(Theme::border);
    FillRect(dis->hDC, &dis->rcItem, hBr);
    FrameRect(dis->hDC, &dis->rcItem, hBrBorder);
    DeleteObject(hBr);
    DeleteObject(hBrBorder);

    // Text
    wchar_t text[64];
    GetWindowTextW(btn, text, 64);
    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, txtColor);
    SelectObject(dis->hDC, hFontBold);
    DrawTextW(dis->hDC, text, -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

// ============================================================
//  Window Procedure
// ============================================================
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // Fonts
        hFontUI = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        hFontBold = CreateFontW(14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI Semibold");
        hFontMono = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Cascadia Mono");

        // Brushes
        hbrBg = CreateSolidBrush(Theme::bg);
        hbrSurface = CreateSolidBrush(Theme::surface);
        hbrSurfaceAlt = CreateSolidBrush(Theme::surfaceAlt);
        hbrBorder = CreateSolidBrush(Theme::border);

        // Labels
        hLblPath = CreateWindowW(L"STATIC", L"Game Executable", WS_VISIBLE | WS_CHILD,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);
        hLblAmount = CreateWindowW(L"STATIC", L"Instances", WS_VISIBLE | WS_CHILD,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);

        // Edits
        hGameEdit = CreateWindowExW(0, L"EDIT",
            L"C:\\Users\\neekewi\\AppData\\Local\\Growtopia\\Growtopia.exe",
            WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)ID_EDIT_PATH, NULL, NULL);
        hAmountEdit = CreateWindowExW(0, L"EDIT", L"1",
            WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER | ES_CENTER,
            0, 0, 0, 0, hwnd, (HMENU)ID_EDIT_AMOUNT, NULL, NULL);

        // Buttons (owner-drawn)
        hBtnLaunch = CreateWindowW(L"BUTTON", L"LAUNCH",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, (HMENU)ID_BTN_LAUNCH, NULL, NULL);
        hBtnKillAll = CreateWindowW(L"BUTTON", L"KILL ALL",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, (HMENU)ID_BTN_KILLALL, NULL, NULL);
        hBtnClear = CreateWindowW(L"BUTTON", L"CLEAR",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 0, 0, hwnd, (HMENU)ID_BTN_CLEAR, NULL, NULL);

        // Tab control
        hTabCtrl = CreateWindowExW(0, WC_TABCONTROLW, NULL,
            WS_VISIBLE | WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | TCS_TABS,
            0, 0, 0, 0, hwnd, (HMENU)ID_TAB_MAIN, NULL, NULL);
        SendMessageW(hTabCtrl, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        g_OldTabProc = (WNDPROC)SetWindowLongPtrW(hTabCtrl, GWLP_WNDPROC, (LONG_PTR)TabSubclassProc);

        // Tab items
        TCITEMW tci = { 0 };
        tci.mask = TCIF_TEXT;
        tci.pszText = (LPWSTR)L"Log";
        TabCtrl_InsertItem(hTabCtrl, 0, &tci);
        tci.pszText = (LPWSTR)L"Packets Out  \x25B6";
        TabCtrl_InsertItem(hTabCtrl, 1, &tci);
        tci.pszText = (LPWSTR)L"Packets In  \x25C0";
        TabCtrl_InsertItem(hTabCtrl, 2, &tci);
        tci.pszText = (LPWSTR)L"Live Stream";
        TabCtrl_InsertItem(hTabCtrl, 3, &tci);

        // Log listbox
        hLogList = CreateWindowExW(0, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_CLIPSIBLINGS | LBS_NOINTEGRALHEIGHT,
            0, 0, 0, 0, hwnd, (HMENU)ID_LIST_LOG, NULL, NULL);
        SendMessageW(hLogList, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        // Live stream listbox
        hStreamList = CreateWindowExW(0, L"LISTBOX", NULL,
            WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_CLIPSIBLINGS | LBS_NOINTEGRALHEIGHT,
            0, 0, 0, 0, hwnd, (HMENU)ID_LIST_STREAM, NULL, NULL);
        SendMessageW(hStreamList, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        // Packet ListViews
        hPktOutLV = CreatePacketListView(hwnd, ID_LV_PKT_OUT, 0, 0, 100, 100);
        hPktInLV = CreatePacketListView(hwnd, ID_LV_PKT_IN, 0, 0, 100, 100);
        SendMessageW(hPktOutLV, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessageW(hPktInLV, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        // Hex dump panels (read-only, scrollable edit controls)
        hHexOut = CreateWindowExW(0, L"EDIT", L"  Click a packet to view hex dump + decoded data",
            WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_CLIPSIBLINGS |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            0, 0, 100, 100, hwnd, NULL, NULL, NULL);
        hHexIn = CreateWindowExW(0, L"EDIT", L"  Click a packet to view hex dump + decoded data",
            WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_CLIPSIBLINGS |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            0, 0, 100, 100, hwnd, NULL, NULL, NULL);
        SendMessageW(hHexOut, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessageW(hHexIn, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        // Apply font to all children
        EnumChildWindows(hwnd, [](HWND child, LPARAM font) -> BOOL {
            wchar_t cls[32];
            GetClassNameW(child, cls, 32);
            if (wcscmp(cls, L"Edit") == 0 || wcscmp(cls, L"Static") == 0) {
                SendMessageW(child, WM_SETFONT, font, TRUE);
            }
            return TRUE;
            }, (LPARAM)hFontUI);

        // Initial layout
        SwitchTab(0);
        PostMessage(hwnd, WM_SIZE, 0, 0);
        break;
    }

    case WM_SIZE:
        LayoutControls(hwnd);
        break;

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 520;
        mmi->ptMinTrackSize.y = 450;
        break;
    }

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, hbrBg);
        return 1;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, Theme::textDim);
        SetBkColor(hdc, Theme::bg);
        return (LRESULT)hbrBg;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, Theme::text);
        SetBkColor(hdc, Theme::surface);
        return (LRESULT)hbrSurface;
    }

    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, Theme::text);
        SetBkColor(hdc, Theme::surface);
        return (LRESULT)hbrSurface;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            DrawButton(dis);
            return TRUE;
        }
        break;
    }

    case WM_NOTIFY: {
        NMHDR* pnm = (NMHDR*)lParam;
        if (pnm->hwndFrom == hTabCtrl && pnm->code == TCN_SELCHANGE) {
            SwitchTab(TabCtrl_GetCurSel(hTabCtrl));
        }
        // Selection changed in packet list -> show hex dump
        if (pnm->code == LVN_ITEMCHANGED) {
            LPNMLISTVIEW pnmlv = (LPNMLISTVIEW)lParam;
            if (pnmlv->uNewState & LVIS_SELECTED) {
                if (pnm->hwndFrom == hPktOutLV) {
                    ShowHexForPacket(hHexOut, g_pktOutData, pnmlv->iItem);
                }
                else if (pnm->hwndFrom == hPktInLV) {
                    ShowHexForPacket(hHexIn, g_pktInData, pnmlv->iItem);
                }
            }
        }
        // Custom draw for ListView
        if (pnm->code == NM_CUSTOMDRAW) {
            LPNMCUSTOMDRAW pCD = (LPNMCUSTOMDRAW)lParam;
            if (pnm->hwndFrom == hPktOutLV || pnm->hwndFrom == hPktInLV) {
                if (pCD->dwDrawStage == CDDS_PREPAINT) {
                    return CDRF_NOTIFYITEMDRAW;
                }
                if (pCD->dwDrawStage == CDDS_ITEMPREPAINT) {
                    // Alternate row colors
                    if (pCD->dwItemSpec % 2 == 1) {
                        LPNMLVCUSTOMDRAW plvcd = (LPNMLVCUSTOMDRAW)lParam;
                        plvcd->clrTextBk = Theme::surfaceAlt;
                    }
                    return CDRF_DODEFAULT;
                }
            }
        }
        break;
    }

                  // Thread-safe log message
    case WM_ADD_LOG: {
        std::wstring* pMsg = (std::wstring*)lParam;
        SendMessageW(hLogList, LB_ADDSTRING, 0, (LPARAM)pMsg->c_str());
        int count = (int)SendMessageW(hLogList, LB_GETCOUNT, 0, 0);
        SendMessageW(hLogList, LB_SETTOPINDEX, count - 1, 0);
        // Update status bar with latest
        if (hStatusBar) {
            // Keep max 2000 lines
            while (count > 2000) {
                SendMessageW(hLogList, LB_DELETESTRING, 0, 0);
                count--;
            }
        }
        delete pMsg;
        return 0;
    }

    case WM_ADD_PKT_OUT: {
        PacketEntry* pe = (PacketEntry*)lParam;
        {
            std::lock_guard<std::mutex> lock(g_pktDataMutex);
            g_pktOutData.push_back(std::move(pe->rawData));
        }
        AddPacketToListView(hPktOutLV, pe, g_pktOutCount);
        TCITEMW tci = { 0 };
        tci.mask = TCIF_TEXT;
        std::wstring title = L"Out \x25B6 (" + std::to_wstring(g_pktOutCount) + L")";
        tci.pszText = (LPWSTR)title.c_str();
        TabCtrl_SetItem(hTabCtrl, 1, &tci);
        delete pe;
        return 0;
    }

    case WM_ADD_PKT_IN: {
        PacketEntry* pe = (PacketEntry*)lParam;
        {
            std::lock_guard<std::mutex> lock(g_pktDataMutex);
            g_pktInData.push_back(std::move(pe->rawData));
        }
        AddPacketToListView(hPktInLV, pe, g_pktInCount);
        TCITEMW tci = { 0 };
        tci.mask = TCIF_TEXT;
        std::wstring title = L"In \x25C0 (" + std::to_wstring(g_pktInCount) + L")";
        tci.pszText = (LPWSTR)title.c_str();
        TabCtrl_SetItem(hTabCtrl, 2, &tci);
        delete pe;
        return 0;
    }

    case WM_ADD_STREAM: {
        std::wstring* pLine = (std::wstring*)lParam;
        SendMessageW(hStreamList, LB_ADDSTRING, 0, (LPARAM)pLine->c_str());
        g_streamCount++;
        // Auto-scroll
        int count = (int)SendMessageW(hStreamList, LB_GETCOUNT, 0, 0);
        SendMessageW(hStreamList, LB_SETTOPINDEX, count - 1, 0);
        // Cap at 5000 lines
        while (count > 5000) {
            SendMessageW(hStreamList, LB_DELETESTRING, 0, 0);
            count--;
        }
        // Update tab title
        TCITEMW tci = { 0 };
        tci.mask = TCIF_TEXT;
        std::wstring title = L"Live (" + std::to_wstring(g_streamCount) + L")";
        tci.pszText = (LPWSTR)title.c_str();
        TabCtrl_SetItem(hTabCtrl, 3, &tci);
        delete pLine;
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == ID_BTN_LAUNCH) {
            wchar_t amtText[10], gamePath[MAX_PATH];
            RandomizeMAC();
            GetWindowTextW(hAmountEdit, amtText, 10);
            GetWindowTextW(hGameEdit, gamePath, MAX_PATH);
            int amt = _wtoi(amtText);
            if (amt > 0) {
                EnableWindow(hBtnLaunch, FALSE);
                LaunchData* ld = new LaunchData{ gamePath, amt };
                CreateThread(NULL, 0, LaunchSequenceThread, ld, 0, NULL);
            }
        }
        else if (id == ID_BTN_KILLALL) {
            KillAllGrowtopia();
        }
        else if (id == ID_BTN_CLEAR) {
            if (g_currentTab == 0) {
                SendMessageW(hLogList, LB_RESETCONTENT, 0, 0);
            }
            else if (g_currentTab == 1) {
                ListView_DeleteAllItems(hPktOutLV);
                g_pktOutCount = 0;
                { std::lock_guard<std::mutex> lock(g_pktDataMutex); g_pktOutData.clear(); }
                SetWindowTextW(hHexOut, L"  Click a packet to view hex dump + decoded data");
            }
            else if (g_currentTab == 2) {
                ListView_DeleteAllItems(hPktInLV);
                g_pktInCount = 0;
                { std::lock_guard<std::mutex> lock(g_pktDataMutex); g_pktInData.clear(); }
                SetWindowTextW(hHexIn, L"  Click a packet to view hex dump + decoded data");
            }
            else if (g_currentTab == 3) {
                SendMessageW(hStreamList, LB_RESETCONTENT, 0, 0);
                g_streamCount = 0;
            }
        }
        break;
    }

    case WM_DESTROY:
        DeleteObject(hFontUI);
        DeleteObject(hFontBold);
        DeleteObject(hFontMono);
        DeleteObject(hbrBg);
        DeleteObject(hbrSurface);
        DeleteObject(hbrSurfaceAlt);
        DeleteObject(hbrBorder);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// ============================================================
//  Entry Point
// ============================================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    // Init Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxW(NULL, L"Winsock init failed", L"Error", MB_OK);
        return 1;
    }

    // Init Common Controls (for ListView, TabControl)
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES };
    InitCommonControlsEx(&icex);

    // Register window class
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"GTProxyLauncher";
    wc.hbrBackground = CreateSolidBrush(Theme::bg);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    RegisterClassExW(&wc);

    // Create main window (resizable)
    g_hWnd = CreateWindowExW(
        WS_EX_COMPOSITED,  // Double-buffer to reduce flicker
        L"GTProxyLauncher",
        L"GT Proxy Launcher",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        750, 800,
        NULL, NULL, hInst, NULL);

    ShowWindow(g_hWnd, nShow);
    UpdateWindow(g_hWnd);

    MSG msg = {};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WSACleanup();
    return 0;
}   