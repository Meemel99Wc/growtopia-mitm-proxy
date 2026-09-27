#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <windows.h>

// ============================================================
//  ENet Protocol Structures & Constants
// ============================================================

// ENet Protocol Header (first 2 bytes of every UDP packet)
// Peer ID = upper 12 bits, flags in lower bits, then 2 bytes sent time
#pragma pack(push, 1)
struct ENetProtocolHeader {
    uint16_t peerID;       // Peer ID (with flags in low bits)
    uint16_t sentTime;     // Timestamp
};

struct ENetCommandHeader {
    uint8_t  command;      // Command type + flags
    uint8_t  channelID;
    uint16_t reliableSeqNo;
};

struct ENetConnect {
    ENetCommandHeader header;
    uint16_t outgoingPeerID;
    uint8_t  incomingSessionID;
    uint8_t  outgoingSessionID;
    uint32_t mtu;
    uint32_t windowSize;
    uint32_t channelCount;
    uint32_t incomingBandwidth;
    uint32_t outgoingBandwidth;
    uint32_t packetThrottleInterval;
    uint32_t packetThrottleAccel;
    uint32_t packetThrottleDecel;
    uint32_t connectID;
    uint32_t data;
};

struct ENetSendReliable {
    ENetCommandHeader header;
    uint16_t dataLength;
};

struct ENetSendUnreliable {
    ENetCommandHeader header;
    uint16_t unreliableSeqNo;
    uint16_t dataLength;
};

struct ENetSendFragment {
    ENetCommandHeader header;
    uint16_t startSequenceNumber;
    uint16_t dataLength;
    uint32_t fragmentCount;
    uint32_t fragmentNumber;
    uint32_t totalLength;
    uint32_t fragmentOffset;
};

struct ENetAcknowledge {
    ENetCommandHeader header;
    uint16_t receivedReliableSeqNo;
    uint16_t receivedSentTime;
};
#pragma pack(pop)

// ENet command types (lower 4 bits of command byte)
enum ENetCommand {
    ENET_CMD_NONE = 0,
    ENET_CMD_ACKNOWLEDGE = 1,
    ENET_CMD_CONNECT = 2,
    ENET_CMD_VERIFY_CONNECT = 3,
    ENET_CMD_DISCONNECT = 4,
    ENET_CMD_PING = 5,
    ENET_CMD_SEND_RELIABLE = 6,
    ENET_CMD_SEND_UNRELIABLE = 7,
    ENET_CMD_SEND_FRAGMENT = 9,
    ENET_CMD_SEND_UNSEQUENCED = 11,
    ENET_CMD_BANDWIDTH_LIMIT = 12,
    ENET_CMD_THROTTLE_CONFIGURE = 13,
    ENET_CMD_COUNT = 14,
};

// Growtopia message types (first 4 bytes of game payload)
enum GTMessageType {
    GT_MSG_UNKNOWN = 0,
    GT_MSG_SERVER_HELLO = 1,
    GT_MSG_GENERIC_TEXT = 2,
    GT_MSG_GAME_MESSAGE = 3,
    GT_MSG_GAME_PACKET = 4,
    GT_MSG_ERROR = 5,
    GT_MSG_TRACK = 6,
    GT_MSG_CLIENT_LOG_REQUEST = 7,
    GT_MSG_CLIENT_LOG_RESPONSE = 8,
};

// GT game packet types (byte at offset 0 inside GT_MSG_GAME_PACKET payload)
enum GTPacketType {
    GT_PKT_STATE = 0,
    GT_PKT_CALL_FUNCTION = 1,
    GT_PKT_UPDATE_STATUS = 2,
    GT_PKT_TILE_CHANGE_REQ = 3,
    GT_PKT_SEND_MAP_DATA = 4,
    GT_PKT_SEND_TILE_UPDATE = 5,
    GT_PKT_SEND_TILE_DATA = 6,
    GT_PKT_MODIFY_ITEM_INV = 8,
    GT_PKT_ITEM_ACTIVATE_REQ = 9,
    GT_PKT_TILE_ACTIVATE_REQ = 10,
    GT_PKT_SET_CHARACTER_STATE = 14,
    GT_PKT_PING_REPLY = 18,
    GT_PKT_PING_REQUEST = 19,
    GT_PKT_GOT_PUNCHED = 20,
    GT_PKT_APP_CHECK_RESPONSE = 22,
    GT_PKT_APP_INTEGRITY_FAIL = 23,
    GT_PKT_DISCONNECT = 24,
    GT_PKT_BATTLE_EVENT = 25,
    GT_PKT_USE_DOOR = 26,
    GT_PKT_PARENTAL_CONTROLS = 27,
    GT_PKT_GONE_FISHIN = 28,
    GT_PKT_STEAM = 29,
    GT_PKT_PET_BATTLE = 30,
    GT_PKT_NPC = 31,
    GT_PKT_SPECIAL = 32,
    GT_PKT_SEND_PARTICLE_EFFECT = 33,
    GT_PKT_ACTIVE_ARROW_TO_ITEM = 34,
    GT_PKT_SELECT_TILE_INDEX = 35,
    GT_PKT_SEND_PLAYER_TRIBUTE_DATA = 36,
};


// ============================================================
//  Packet Analyzer Class
// ============================================================
class PacketAnalyzer {
public:
    PacketAnalyzer() : m_enabled(true), m_logToFile(true), m_packetCount(0) {}

    void Init(const std::string& logPath = "packet_log.txt") {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_logToFile) {
            m_logFile.open(logPath, std::ios::out | std::ios::trunc);
            if (m_logFile.is_open()) {
                m_logFile << "=== Packet Capture Started ===" << std::endl;
                m_logFile << "Timestamp | Direction | Size | ENet Cmd | Details" << std::endl;
                m_logFile << std::string(80, '=') << std::endl;
            }
        }
    }

    void Close() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_logFile.is_open()) m_logFile.close();
    }

    // Call this from the launcher's UDP relay points
    // direction: "C->S" (client to server) or "S->C" (server to client)
    void Analyze(const char* data, int len, const std::string& direction) {
        if (!m_enabled || len < 2) return;
        std::lock_guard<std::mutex> lock(m_mutex);

        m_packetCount++;
        std::stringstream ss;

        // Timestamp
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm t;
        localtime_s(&t, &time);
        ss << std::put_time(&t, "%H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count();

        ss << " | #" << std::setw(6) << m_packetCount;
        ss << " | " << direction;
        ss << " | " << std::setw(5) << len << "B";

        // Parse ENet protocol header
        if (len < (int)sizeof(ENetProtocolHeader)) {
            ss << " | TOO SHORT";
            LogLine(ss.str());
            return;
        }

        const ENetProtocolHeader* protoHdr = (const ENetProtocolHeader*)data;
        uint16_t peerID = ntohs(protoHdr->peerID);
        uint16_t sentTime = ntohs(protoHdr->sentTime);

        // Check for compressed header (no sentTime field)
        bool hasTimestamp = true;
        int offset = sizeof(ENetProtocolHeader); // 4 bytes

        ss << " | PeerID=" << (peerID >> 4) << " Time=" << sentTime;

        // Parse commands in the packet
        int cmdIndex = 0;
        while (offset + (int)sizeof(ENetCommandHeader) <= len) {
            const ENetCommandHeader* cmdHdr = (const ENetCommandHeader*)(data + offset);
            uint8_t cmdType = cmdHdr->command & 0x0F;
            bool isAck = (cmdHdr->command & 0x80) != 0;
            uint16_t relSeq = ntohs(cmdHdr->reliableSeqNo);

            ss << "\n    CMD[" << cmdIndex << "]: " << GetCommandName(cmdType);
            ss << " Ch=" << (int)cmdHdr->channelID;
            ss << " Seq=" << relSeq;
            if (isAck) ss << " [ACK_FLAG]";

            int cmdSize = GetCommandSize(cmdType);

            // Parse payload for data commands
            switch (cmdType) {
            case ENET_CMD_ACKNOWLEDGE: {
                if (offset + (int)sizeof(ENetAcknowledge) <= len) {
                    const ENetAcknowledge* ack = (const ENetAcknowledge*)(data + offset);
                    ss << " AckSeq=" << ntohs(ack->receivedReliableSeqNo);
                }
                offset += sizeof(ENetAcknowledge);
                break;
            }
            case ENET_CMD_CONNECT: {
                if (offset + (int)sizeof(ENetConnect) <= len) {
                    const ENetConnect* conn = (const ENetConnect*)(data + offset);
                    ss << " MTU=" << ntohl(conn->mtu);
                    ss << " Channels=" << ntohl(conn->channelCount);
                    ss << " ConnID=0x" << std::hex << ntohl(conn->connectID) << std::dec;
                }
                offset += sizeof(ENetConnect);
                break;
            }
            case ENET_CMD_SEND_RELIABLE: {
                if (offset + (int)sizeof(ENetSendReliable) <= len) {
                    const ENetSendReliable* rel = (const ENetSendReliable*)(data + offset);
                    uint16_t dataLen = ntohs(rel->dataLength);
                    ss << " DataLen=" << dataLen;

                    int payloadOffset = offset + sizeof(ENetSendReliable);
                    if (payloadOffset + 4 <= len) {
                        ParseGTPayload(data + payloadOffset, std::min((int)dataLen, len - payloadOffset), ss);
                    }
                    offset += sizeof(ENetSendReliable) + dataLen;
                }
                else {
                    offset = len; // can't parse further
                }
                break;
            }
            case ENET_CMD_SEND_UNRELIABLE: {
                if (offset + (int)sizeof(ENetSendUnreliable) <= len) {
                    const ENetSendUnreliable* unrel = (const ENetSendUnreliable*)(data + offset);
                    uint16_t dataLen = ntohs(unrel->dataLength);
                    ss << " DataLen=" << dataLen;
                    ss << " UnrelSeq=" << ntohs(unrel->unreliableSeqNo);

                    int payloadOffset = offset + sizeof(ENetSendUnreliable);
                    if (payloadOffset + 4 <= len) {
                        ParseGTPayload(data + payloadOffset, std::min((int)dataLen, len - payloadOffset), ss);
                    }
                    offset += sizeof(ENetSendUnreliable) + dataLen;
                }
                else {
                    offset = len;
                }
                break;
            }
            case ENET_CMD_SEND_FRAGMENT: {
                if (offset + (int)sizeof(ENetSendFragment) <= len) {
                    const ENetSendFragment* frag = (const ENetSendFragment*)(data + offset);
                    uint16_t dataLen = ntohs(frag->dataLength);
                    ss << " DataLen=" << dataLen;
                    ss << " Frag=" << ntohl(frag->fragmentNumber) << "/" << ntohl(frag->fragmentCount);
                    ss << " Total=" << ntohl(frag->totalLength);
                    ss << " Offset=" << ntohl(frag->fragmentOffset);

                    // Only parse GT payload on first fragment
                    if (ntohl(frag->fragmentNumber) == 0) {
                        int payloadOffset = offset + sizeof(ENetSendFragment);
                        if (payloadOffset + 4 <= len) {
                            ParseGTPayload(data + payloadOffset, std::min((int)dataLen, len - payloadOffset), ss);
                        }
                    }
                    offset += sizeof(ENetSendFragment) + dataLen;
                }
                else {
                    offset = len;
                }
                break;
            }
            case ENET_CMD_DISCONNECT: {
                ss << " [DISCONNECT]";
                offset += sizeof(ENetCommandHeader) + 4; // header + data field
                break;
            }
            case ENET_CMD_PING: {
                offset += sizeof(ENetCommandHeader);
                break;
            }
            default: {
                // Unknown command, try to skip using known size or bail
                if (cmdSize > 0) {
                    offset += cmdSize;
                }
                else {
                    ss << " [UNKNOWN, stopping parse]";
                    offset = len;
                }
                break;
            }
            }
            cmdIndex++;
        }

        LogLine(ss.str());

        // Optional: hex dump for small packets or specific types
        if (len <= 128) {
            LogLine("    HEX: " + HexString(data, len));
        }
    }

    void SetEnabled(bool enabled) { m_enabled = enabled; }
    bool IsEnabled() const { return m_enabled; }

private:
    void ParseGTPayload(const char* data, int len, std::stringstream& ss) {
        if (len < 4) return;

        uint32_t msgType = *(uint32_t*)data;
        ss << " | GT_MSG=" << GetGTMessageName(msgType);

        if (msgType == GT_MSG_GENERIC_TEXT || msgType == GT_MSG_GAME_MESSAGE) {
            if (len > 4) {
                // Text payload follows the 4-byte type
                int textLen = len - 4;
                std::string text(data + 4, std::min(textLen, 200));
                // Sanitize non-printable characters
                for (char& c : text) {
                    if (c < 32 || c > 126) c = '.';
                }
                ss << " \"" << text << "\"";
                if (textLen > 200) ss << "...[" << textLen << " total]";
            }
        }
        else if (msgType == GT_MSG_GAME_PACKET && len >= 60) {
            // Game packet has a 56-byte tank packet header at offset 4
            uint8_t pktType = (uint8_t)data[4];
            ss << " PKT=" << GetGTPacketName(pktType);

            // Extract some useful fields from tank packet
            int32_t netID = *(int32_t*)(data + 8);
            float x = *(float*)(data + 28);
            float y = *(float*)(data + 32);
            int32_t intVal = *(int32_t*)(data + 52);

            if (netID != 0) ss << " NetID=" << netID;
            if (x != 0 || y != 0) ss << " Pos=(" << (int)x << "," << (int)y << ")";
            if (intVal != 0) ss << " IntVal=" << intVal;

            // Check for extended data
            uint32_t flags = *(uint32_t*)(data + 16);
            if (flags & 0x8) {
                int extDataLen = *(int*)(data + 56);
                ss << " ExtData=" << extDataLen << "B";
            }
        }
    }

    static std::string GetCommandName(uint8_t cmd) {
        switch (cmd) {
        case ENET_CMD_ACKNOWLEDGE:        return "ACK";
        case ENET_CMD_CONNECT:            return "CONNECT";
        case ENET_CMD_VERIFY_CONNECT:     return "VERIFY_CONNECT";
        case ENET_CMD_DISCONNECT:         return "DISCONNECT";
        case ENET_CMD_PING:               return "PING";
        case ENET_CMD_SEND_RELIABLE:      return "RELIABLE";
        case ENET_CMD_SEND_UNRELIABLE:    return "UNRELIABLE";
        case ENET_CMD_SEND_FRAGMENT:      return "FRAGMENT";
        case ENET_CMD_SEND_UNSEQUENCED:   return "UNSEQUENCED";
        case ENET_CMD_BANDWIDTH_LIMIT:    return "BW_LIMIT";
        case ENET_CMD_THROTTLE_CONFIGURE: return "THROTTLE_CFG";
        default:                          return "UNK_" + std::to_string(cmd);
        }
    }

    static std::string GetGTMessageName(uint32_t type) {
        switch (type) {
        case GT_MSG_SERVER_HELLO:       return "SERVER_HELLO";
        case GT_MSG_GENERIC_TEXT:        return "GENERIC_TEXT";
        case GT_MSG_GAME_MESSAGE:        return "GAME_MESSAGE";
        case GT_MSG_GAME_PACKET:         return "GAME_PACKET";
        case GT_MSG_ERROR:               return "ERROR";
        case GT_MSG_TRACK:               return "TRACK";
        case GT_MSG_CLIENT_LOG_REQUEST:  return "LOG_REQ";
        case GT_MSG_CLIENT_LOG_RESPONSE: return "LOG_RESP";
        default:                         return "UNK_" + std::to_string(type);
        }
    }

    static std::string GetGTPacketName(uint8_t type) {
        switch (type) {
        case GT_PKT_STATE:               return "STATE";
        case GT_PKT_CALL_FUNCTION:       return "CALL_FUNC";
        case GT_PKT_UPDATE_STATUS:       return "UPDATE_STATUS";
        case GT_PKT_TILE_CHANGE_REQ:     return "TILE_CHANGE";
        case GT_PKT_SEND_MAP_DATA:       return "MAP_DATA";
        case GT_PKT_SEND_TILE_UPDATE:    return "TILE_UPDATE";
        case GT_PKT_SEND_TILE_DATA:      return "TILE_DATA";
        case GT_PKT_MODIFY_ITEM_INV:     return "MODIFY_INV";
        case GT_PKT_ITEM_ACTIVATE_REQ:   return "ITEM_ACTIVATE";
        case GT_PKT_TILE_ACTIVATE_REQ:   return "TILE_ACTIVATE";
        case GT_PKT_SET_CHARACTER_STATE: return "CHAR_STATE";
        case GT_PKT_PING_REPLY:          return "PING_REPLY";
        case GT_PKT_PING_REQUEST:        return "PING_REQ";
        case GT_PKT_GOT_PUNCHED:         return "PUNCHED";
        case GT_PKT_DISCONNECT:          return "DISCONNECT";
        case GT_PKT_USE_DOOR:            return "USE_DOOR";
        case GT_PKT_GONE_FISHIN:         return "FISHING";
        case GT_PKT_SEND_PARTICLE_EFFECT: return "PARTICLE";
        default:                          return "UNK_" + std::to_string(type);
        }
    }

    static int GetCommandSize(uint8_t cmd) {
        switch (cmd) {
        case ENET_CMD_ACKNOWLEDGE:        return sizeof(ENetAcknowledge);
        case ENET_CMD_CONNECT:            return sizeof(ENetConnect);
        case ENET_CMD_VERIFY_CONNECT:     return 44; // same layout as connect
        case ENET_CMD_DISCONNECT:         return sizeof(ENetCommandHeader) + 4;
        case ENET_CMD_PING:               return sizeof(ENetCommandHeader);
        case ENET_CMD_BANDWIDTH_LIMIT:    return sizeof(ENetCommandHeader) + 8;
        case ENET_CMD_THROTTLE_CONFIGURE: return sizeof(ENetCommandHeader) + 12;
            // Variable-length commands return -1
        case ENET_CMD_SEND_RELIABLE:
        case ENET_CMD_SEND_UNRELIABLE:
        case ENET_CMD_SEND_FRAGMENT:
        case ENET_CMD_SEND_UNSEQUENCED:
            return -1;
        default: return -1;
        }
    }

    static std::string HexString(const char* data, int len) {
        std::stringstream ss;
        for (int i = 0; i < len; i++) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)(uint8_t)data[i];
            if (i < len - 1) ss << " ";
        }
        return ss.str();
    }

    void LogLine(const std::string& line) {
        if (m_logToFile && m_logFile.is_open()) {
            m_logFile << line << std::endl;
            m_logFile.flush();
        }
        // Also output to debugger
        OutputDebugStringA(("[PKT] " + line + "\n").c_str());
    }

    std::mutex m_mutex;
    std::ofstream m_logFile;
    bool m_enabled;
    bool m_logToFile;
    uint64_t m_packetCount;
};