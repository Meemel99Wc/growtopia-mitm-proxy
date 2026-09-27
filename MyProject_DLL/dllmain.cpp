#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include "MinHook.h"
#include <iostream>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

// --- Globals ---
char g_ProxyIP[64] = "127.0.0.1";
u_short g_ProxyPort = 1081; // The port your Launcher is listening on

uint32_t g_LastTargetIP = 0;
uint16_t g_LastTargetPort = 0;

// Simple Logger
void LogDebug(const std::string& msg) {
    std::string finalMsg = "[GT_PROXY_DLL] " + msg + "\n";
    OutputDebugStringA(finalMsg.c_str());
}

void Log(const std::wstring& wmsg) {
    std::string msg(wmsg.begin(), wmsg.end());
    LogDebug(msg);
}

// --- Function Pointers ---
typedef int (WSAAPI* tConnect)(SOCKET s, const struct sockaddr* name, int namelen);
tConnect pOriginalConnect = NULL;

typedef int (WSAAPI* tSendTo)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
tSendTo pOriginalSendTo = NULL;

typedef int (WSAAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
tSend pOriginalSend = NULL;

typedef int (WSAAPI* tRecvFrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
tRecvFrom pOriginalRecvFrom = NULL;

typedef int (WSAAPI* LPFN_WSASENDTO)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
LPFN_WSASENDTO pOriginalWSASendTo = nullptr;

typedef int (WSAAPI* LPFN_WSARECVFROM)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
LPFN_WSARECVFROM pOriginalWSARecvFrom = nullptr;

// --- Detours ---

// FIX 1: SendMetaWhisper now uses g_ProxyPort instead of hardcoded 1081,
//        and uses pOriginalSendTo to bypass the hook entirely.
void SendMetaWhisper(uint32_t ip, uint16_t port) {
    sockaddr_in lAddr = { 0 };
    lAddr.sin_family = AF_INET;
    lAddr.sin_port = htons(g_ProxyPort);  // FIX: use the actual proxy port
    lAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    char meta[10];
    memcpy(meta, "META", 4);
    memcpy(meta + 4, &ip, 4);
    memcpy(meta + 8, &port, 2);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
        // FIX: Use pOriginalSendTo to completely bypass our hook
        // (avoids any potential recursion or hook side-effects)
        if (pOriginalSendTo) {
            pOriginalSendTo(s, meta, 10, 0, (struct sockaddr*)&lAddr, sizeof(lAddr));
        }
        else {
            sendto(s, meta, 10, 0, (struct sockaddr*)&lAddr, sizeof(lAddr));
        }
        closesocket(s);
    }
}
int WSAAPI DetourWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {

    int result = pOriginalWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

    if (result == 0 && lpFrom && lpFrom->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)lpFrom;

        if (addr->sin_addr.s_addr == inet_addr("127.0.0.1") &&
            ntohs(addr->sin_port) == g_ProxyPort) {
            if (g_LastTargetIP != 0) {
                LogDebug("WSARecvFrom SPOOF: 127.0.0.1:" + std::to_string(g_ProxyPort) +
                    " -> " + std::string(inet_ntoa(*(in_addr*)&g_LastTargetIP)) +
                    ":" + std::to_string(ntohs(g_LastTargetPort)));
                addr->sin_addr.s_addr = g_LastTargetIP;
                addr->sin_port = g_LastTargetPort;
            }
        }
        else {
            LogDebug("WSARecvFrom NO MATCH: " + std::string(inet_ntoa(addr->sin_addr)) +
                ":" + std::to_string(ntohs(addr->sin_port)));
        }
    }
    else if (result != 0) {
        LogDebug("WSARecvFrom returned: " + std::to_string(result) +
            " WSAErr: " + std::to_string(WSAGetLastError()));
    }

    return result;
}
int WSAAPI DetourRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    int result = pOriginalRecvFrom(s, buf, len, flags, from, fromlen);

    if (result > 0 && from && from->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)from;

        if (addr->sin_addr.s_addr == inet_addr("127.0.0.1") &&
            ntohs(addr->sin_port) == g_ProxyPort) {
            if (g_LastTargetIP != 0) {
                LogDebug("recvfrom SPOOF: 127.0.0.1:" + std::to_string(g_ProxyPort) +
                    " -> " + std::string(inet_ntoa(*(in_addr*)&g_LastTargetIP)) +
                    ":" + std::to_string(ntohs(g_LastTargetPort)));
                addr->sin_addr.s_addr = g_LastTargetIP;
                addr->sin_port = g_LastTargetPort;
            }
        }
    }
    return result;
}
int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (name->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)name;

        if (addr->sin_addr.s_addr != inet_addr("127.0.0.1")) {
            g_LastTargetIP = addr->sin_addr.s_addr;
            g_LastTargetPort = addr->sin_port;

            SendMetaWhisper(g_LastTargetIP, g_LastTargetPort);

            // FIX 3: Give the launcher time to process the META whisper
            // BEFORE the TCP connect arrives. This prevents the race
            // condition where the launcher accepts TCP before knowing the target.
            Sleep(50);

            // Redirect to Launcher
            addr->sin_addr.s_addr = inet_addr("127.0.0.1");
            addr->sin_port = htons(g_ProxyPort);  // FIX: use g_ProxyPort, not hardcoded
        }
    }
    return pOriginalConnect(s, name, namelen);
}

int WSAAPI DetourSend(SOCKET s, const char* buf, int len, int flags) {
    return pOriginalSend(s, buf, len, flags);
}

int WSAAPI DetourWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (lpTo && lpTo->sa_family == AF_INET) {
        struct sockaddr_in redirectedAddr;
        memcpy(&redirectedAddr, lpTo, sizeof(struct sockaddr_in));

        if (redirectedAddr.sin_addr.s_addr != inet_addr("127.0.0.1")) {
            // Send META if target changed
            if (redirectedAddr.sin_addr.s_addr != g_LastTargetIP || redirectedAddr.sin_port != g_LastTargetPort) {
                g_LastTargetIP = redirectedAddr.sin_addr.s_addr;
                g_LastTargetPort = redirectedAddr.sin_port;
                SendMetaWhisper(g_LastTargetIP, g_LastTargetPort);
                Sleep(20);
            }

            redirectedAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
            redirectedAddr.sin_port = htons(g_ProxyPort);

            return pOriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, (const struct sockaddr*)&redirectedAddr, sizeof(redirectedAddr), lpOverlapped, lpCompletionRoutine);
        }
    }
    return pOriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI DetourSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    if (to && to->sa_family == AF_INET) {
        struct sockaddr_in redirectedAddr;
        memcpy(&redirectedAddr, to, sizeof(struct sockaddr_in));

        if (redirectedAddr.sin_addr.s_addr != inet_addr("127.0.0.1")) {
            if (redirectedAddr.sin_addr.s_addr != g_LastTargetIP || redirectedAddr.sin_port != g_LastTargetPort) {
                g_LastTargetIP = redirectedAddr.sin_addr.s_addr;
                g_LastTargetPort = redirectedAddr.sin_port;

                // FIX: Use SendMetaWhisper helper instead of duplicating logic
                SendMetaWhisper(g_LastTargetIP, g_LastTargetPort);
                Sleep(20);
            }

            redirectedAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
            redirectedAddr.sin_port = htons(g_ProxyPort);

            return pOriginalSendTo(s, buf, len, flags, (const struct sockaddr*)&redirectedAddr, sizeof(redirectedAddr));
        }
    }
    return pOriginalSendTo(s, buf, len, flags, to, tolen);
}

void StartProxyHook() {
    char envBuf[128];
    if (GetEnvironmentVariableA("GT_PROXY", envBuf, sizeof(envBuf)) > 0) {
        std::string s(envBuf);
        size_t colon = s.find(':');
        if (colon != std::string::npos) {
            g_ProxyPort = (u_short)std::stoi(s.substr(colon + 1));
        }
    }

    LogDebug("Proxy Port configured: " + std::to_string(g_ProxyPort));

    if (MH_Initialize() == MH_OK) {
        MH_CreateHookApi(L"ws2_32.dll", "connect", &DetourConnect, (LPVOID*)&pOriginalConnect);
        MH_CreateHookApi(L"ws2_32.dll", "sendto", &DetourSendTo, (LPVOID*)&pOriginalSendTo);
        MH_CreateHookApi(L"ws2_32.dll", "WSASendTo", &DetourWSASendTo, (LPVOID*)&pOriginalWSASendTo);
        MH_CreateHookApi(L"ws2_32.dll", "WSARecvFrom", &DetourWSARecvFrom, (LPVOID*)&pOriginalWSARecvFrom);
        MH_CreateHookApi(L"ws2_32.dll", "send", &DetourSend, (LPVOID*)&pOriginalSend);
        MH_CreateHookApi(L"ws2_32.dll", "recvfrom", &DetourRecvFrom, (LPVOID*)&pOriginalRecvFrom);

        MH_EnableHook(MH_ALL_HOOKS);
        LogDebug("All Proxy Hooks Enabled (Connect/Send/SendTo).");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartProxyHook, NULL, 0, NULL));
    }
    return TRUE;
}