// ============================================================
//  ENetHook.h - Hook ENet internally to see plaintext packets
//  Add this to your DLL project alongside dllmain.cpp
// ============================================================

#pragma once
#include <windows.h>
#include <winsock2.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include "MinHook.h"
// ============================================================
//  ENet Structures (minimal, matching ENet internals)
// ============================================================

// Forward declarations matching ENet's types
typedef struct _ENetPacket {
    size_t   referenceCount;
    uint32_t flags;
    uint8_t* data;
    size_t   dataLength;
    void* freeCallback;
    void* userData;
} ENetPacket;

typedef struct _ENetPeer {
    void* dispatchList_sentinel; // ENetListNode
    void* dispatchList_sentinel2;
    void* host;
    uint16_t outgoingPeerID;
    uint16_t incomingPeerID;
    uint32_t connectID;
    uint8_t  outgoingSessionID;
    uint8_t  incomingSessionID;
    // ... more fields we don't need
} ENetPeer;

// ============================================================
//  Plaintext Packet Callback
// ============================================================

// The launcher listens for these on a separate UDP port
// Format: "PTXT" + direction(1) + dataLen(4) + data
#define PLAINTEXT_PORT_OFFSET 100  // e.g., proxy port 1081 -> plaintext port 1181

static u_short g_PlaintextPort = 0;

// Send plaintext capture to launcher
static void SendPlaintext(const uint8_t* data, int len, bool outbound) {
    if (g_PlaintextPort == 0 || len <= 0) return;

    // Build packet: "PTXT" + dir(1) + len(4) + data
    int totalLen = 4 + 1 + 4 + len;
    if (totalLen > 8192) totalLen = 8192; // Cap to prevent huge allocations

    std::vector<char> pkt(totalLen);
    memcpy(pkt.data(), "PTXT", 4);
    pkt[4] = outbound ? 0x01 : 0x02;
    int cappedLen = totalLen - 9;
    memcpy(pkt.data() + 5, &cappedLen, 4);
    memcpy(pkt.data() + 9, data, cappedLen);

    sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_PlaintextPort);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
        sendto(s, pkt.data(), totalLen, 0, (sockaddr*)&addr, sizeof(addr));
        closesocket(s);
    }
}

// ============================================================
//  Pattern Scanner
// ============================================================

static uint8_t* ScanPattern(uint8_t* start, size_t size, const char* pattern, const char* mask) {
    size_t patLen = strlen(mask);
    for (size_t i = 0; i <= size - patLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patLen; j++) {
            if (mask[j] == 'x' && start[i + j] != (uint8_t)pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return start + i;
    }
    return nullptr;
}

// Scan all executable sections of the main module
static uint8_t* ScanModule(HMODULE hMod, const char* pattern, const char* mask) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uint8_t* base = (uint8_t*)hMod + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            uint8_t* result = ScanPattern(base, size, pattern, mask);
            if (result) return result;
        }
    }
    return nullptr;
}

// ============================================================
//  enet_peer_send Hook (outgoing plaintext)
// ============================================================

typedef int (*tENetPeerSend)(ENetPeer* peer, uint8_t channelID, ENetPacket* packet);
static tENetPeerSend pOriginal_enet_peer_send = nullptr;

static int Hooked_enet_peer_send(ENetPeer* peer, uint8_t channelID, ENetPacket* packet) {
    if (packet && packet->data && packet->dataLength > 0) {
        // Log to debugger
        std::string msg = "[ENET_SEND] Ch=" + std::to_string(channelID)
            + " Len=" + std::to_string(packet->dataLength);

        // Quick decode GT type
        if (packet->dataLength >= 4) {
            uint32_t gtType = *(uint32_t*)packet->data;
            const char* names[] = { "UNK","HELLO","TEXT","GAME_MSG","GAME_PKT","ERROR","TRACK","LOG_REQ","LOG_RESP" };
            if (gtType < 9) msg += " GT=" + std::string(names[gtType]);

            // Decode text payloads
            if ((gtType == 2 || gtType == 3) && packet->dataLength > 4) {
                size_t txtLen = packet->dataLength - 4;
                std::string txt((char*)packet->data + 4, std::min(txtLen, (size_t)200));
                for (char& c : txt) { if (c < 32 || c > 126) c = '.'; }
                msg += " \"" + txt + "\"";
            }

            // Decode game packet type
            if (gtType == 4 && packet->dataLength >= 5) {
                uint8_t pktType = packet->data[4];
                msg += " PKT=" + std::to_string(pktType);

                if (pktType == 0 && packet->dataLength >= 36) { // STATE
                    float x = *(float*)(packet->data + 28);
                    float y = *(float*)(packet->data + 32);
                    uint32_t flags = *(uint32_t*)(packet->data + 16);
                    msg += " Pos=(" + std::to_string((int)x) + "," + std::to_string((int)y) + ")";
                    if (flags & 0x20) msg += " PUNCH";
                    if (flags & 0x4) msg += " JUMP";
                }
                else if (pktType == 3 && packet->dataLength >= 24) { // TILE_CHANGE
                    int32_t tileX = *(int32_t*)(packet->data + 20);
                    int32_t tileY = *(int32_t*)(packet->data + 24);
                    int32_t itemID = *(int32_t*)(packet->data + 52);
                    msg += " Tile=(" + std::to_string(tileX) + "," + std::to_string(tileY) + ") Item=" + std::to_string(itemID);
                }
            }
        }

        // Hex dump first 32 bytes
        msg += " HEX=[";
        int dumpLen = (int)std::min(packet->dataLength, (size_t)32);
        for (int i = 0; i < dumpLen; i++) {
            char hex[4];
            sprintf_s(hex, "%02X ", packet->data[i]);
            msg += hex;
        }
        if (packet->dataLength > 32) msg += "...";
        msg += "]";

        OutputDebugStringA(("[GT_ENET] " + msg + "\n").c_str());

        // Forward to launcher
        SendPlaintext(packet->data, (int)packet->dataLength, true);
    }

    return pOriginal_enet_peer_send(peer, channelID, packet);
}

// ============================================================
//  Packet Receive Hook (incoming plaintext)
//  We hook the game's internal dispatch function
// ============================================================

// Generic hook for any function that receives (type, data, len) or (packet*)
// We'll use a trampoline approach - hook the function that processes
// received ENet packets after ENet decodes them

typedef void (*tGamePacketHandler)(void* gameClient, int msgType, uint8_t* data, int len);
static tGamePacketHandler pOriginal_GamePacketHandler = nullptr;

static void Hooked_GamePacketHandler(void* gameClient, int msgType, uint8_t* data, int len) {
    if (data && len > 0) {
        std::string msg = "[ENET_RECV] MsgType=" + std::to_string(msgType)
            + " Len=" + std::to_string(len);

        const char* names[] = { "UNK","HELLO","TEXT","GAME_MSG","GAME_PKT","ERROR","TRACK","LOG_REQ","LOG_RESP" };
        if (msgType >= 0 && msgType < 9) msg += " GT=" + std::string(names[msgType]);

        if ((msgType == 2 || msgType == 3) && len > 0) {
            std::string txt((char*)data, std::min(len, 200));
            for (char& c : txt) { if (c < 32 || c > 126) c = '.'; }
            msg += " \"" + txt + "\"";
        }

        msg += " HEX=[";
        int dumpLen = std::min(len, 32);
        for (int i = 0; i < dumpLen; i++) {
            char hex[4];
            sprintf_s(hex, "%02X ", data[i]);
            msg += hex;
        }
        if (len > 32) msg += "...";
        msg += "]";

        OutputDebugStringA(("[GT_ENET] " + msg + "\n").c_str());

        // Forward to launcher
        // Build a fake GT packet: type(4) + data
        std::vector<uint8_t> fullPkt(4 + len);
        memcpy(fullPkt.data(), &msgType, 4);
        memcpy(fullPkt.data() + 4, data, len);
        SendPlaintext(fullPkt.data(), (int)fullPkt.size(), false);
    }

    pOriginal_GamePacketHandler(gameClient, msgType, data, len);
}

// ============================================================
//  Known Patterns for Growtopia's ENet functions
//  These may need updating per game version!
// ============================================================

struct PatternEntry {
    const char* name;
    const char* pattern;
    const char* mask;
    void* hookFunc;
    void** originalFunc;
};

// enet_peer_send signature (common across many ENet builds)
// This looks for the function prologue + early instructions
// You may need to update these for your game version

// Alternative approach: scan for string references
// enet_peer_send typically references error strings or has characteristic constants

// ============================================================
//  Initialization
// ============================================================

static bool g_ENetHooksInstalled = false;

void InitENetHooks(u_short proxyPort) {
    g_PlaintextPort = proxyPort + PLAINTEXT_PORT_OFFSET;

    HMODULE hGame = GetModuleHandleA(NULL); // Main exe
    if (!hGame) {
        OutputDebugStringA("[GT_ENET] Failed to get game module\n");
        return;
    }

    OutputDebugStringA("[GT_ENET] Scanning for ENet functions...\n");

    // Method 1: Try to find enet_peer_send by signature
    // Common x64 prologue for enet_peer_send:
    // The function typically starts with checking peer state and channel bounds

    // These patterns are VERSION-SPECIFIC. If they don't match, use Method 2.
    // Pattern for enet_peer_send (x64, MSVC compiled):
    // Look for: mov [rsp+...], rbx; push rdi; sub rsp, ...; mov ..., channelID comparison
    const char* sendPatterns[] = {
        // Pattern 1: Common MSVC x64
        "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x41\x0F\xB6\xF8",
        // Pattern 2: Alternative
        "\x40\x53\x48\x83\xEC\x00\x41\x0F\xB6\xD8\x48\x8B",
        nullptr
    };
    const char* sendMasks[] = {
        "xxxx?xxxx?xxxx",
        "xxxxx?xxxxxx",
        nullptr
    };

    uint8_t* pENetSend = nullptr;
    for (int i = 0; sendPatterns[i]; i++) {
        pENetSend = ScanModule(hGame, sendPatterns[i], sendMasks[i]);
        if (pENetSend) {
            char buf[128];
            sprintf_s(buf, "[GT_ENET] Found enet_peer_send at 0x%p (pattern %d)\n", pENetSend, i);
            OutputDebugStringA(buf);
            break;
        }
    }

    if (pENetSend) {
        if (MH_CreateHook(pENetSend, &Hooked_enet_peer_send, (LPVOID*)&pOriginal_enet_peer_send) == MH_OK) {
            MH_EnableHook(pENetSend);
            OutputDebugStringA("[GT_ENET] enet_peer_send hooked!\n");
            g_ENetHooksInstalled = true;
        }
    }
    else {
        OutputDebugStringA("[GT_ENET] enet_peer_send NOT FOUND. Trying alternative method...\n");

        // Method 2: Scan for the game's packet handler by looking for
        // characteristic constants or string references
        // 
        // In Growtopia, the packet handler often references strings like:
        // "action|", "OnSuperMain", "OnConsoleMessage"
        //
        // You can find the handler by:
        // 1. Searching for "action|" string in the exe
        // 2. Finding xrefs to that string
        // 3. The containing function is likely the packet handler
        //
        // For now, log all enet_host_service results as a fallback
    }

    // Method 3: Hook by export if ENet is a separate DLL
    HMODULE hENet = GetModuleHandleA("enet.dll");
    if (!hENet) hENet = GetModuleHandleA("enet64.dll");
    if (hENet) {
        OutputDebugStringA("[GT_ENET] Found separate ENet DLL!\n");
        void* pSend = GetProcAddress(hENet, "enet_peer_send");
        if (pSend && !pENetSend) {
            if (MH_CreateHook(pSend, &Hooked_enet_peer_send, (LPVOID*)&pOriginal_enet_peer_send) == MH_OK) {
                MH_EnableHook(pSend);
                OutputDebugStringA("[GT_ENET] enet_peer_send hooked via DLL export!\n");
                g_ENetHooksInstalled = true;
            }
        }
    }

    if (!g_ENetHooksInstalled) {
        OutputDebugStringA("[GT_ENET] === MANUAL STEPS NEEDED ===\n");
        OutputDebugStringA("[GT_ENET] 1. Open Growtopia.exe in IDA/Ghidra/x64dbg\n");
        OutputDebugStringA("[GT_ENET] 2. Search for string 'action|' or 'OnSuperMain'\n");
        OutputDebugStringA("[GT_ENET] 3. Find the xref - the containing function is the packet handler\n");
        OutputDebugStringA("[GT_ENET] 4. Note the function address offset from module base\n");
        OutputDebugStringA("[GT_ENET] 5. Update the pattern in ENetHook.h\n");
        OutputDebugStringA("[GT_ENET] ================================\n");
    }
}