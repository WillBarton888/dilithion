// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// CNode - Unified peer node implementation
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#include <net/node.h>
#include <util/time.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include <sstream>

CNode::CNode(int id_in, const NetProtocol::CAddress& addr_in, bool inbound)
    : id(id_in)
    , addr(addr_in)
    , fInbound(inbound)
    , nTimeConnected(GetTime())
{
    // NOTE: Block sync state (m_stalling_since, etc.) is managed by CPeer, not CNode.
    // See CPeerManager::MarkBlockAsInFlight() and related methods.
}

CNode::~CNode() {
    CloseSocket();
}

void CNode::SetSocket(int sock) {
    std::lock_guard<std::mutex> lock(m_sock_mutex);
    if (m_socket >= 0) {
        // Close existing socket
#ifdef _WIN32
        closesocket(m_socket);
#else
        close(m_socket);
#endif
    }
    m_socket = sock;
}

int CNode::GetSocket() const {
    std::lock_guard<std::mutex> lock(m_sock_mutex);
    return m_socket;
}

bool CNode::HasValidSocket() const {
    std::lock_guard<std::mutex> lock(m_sock_mutex);
#ifdef _WIN32
    return m_socket != static_cast<int>(INVALID_SOCKET) && m_socket >= 0;
#else
    return m_socket >= 0;
#endif
}

void CNode::CloseSocket() {
    std::lock_guard<std::mutex> lock(m_sock_mutex);
    if (m_socket >= 0) {
#ifdef _WIN32
        closesocket(m_socket);
#else
        close(m_socket);
#endif
        m_socket = -1;
    }
}

void CNode::AppendRecvBytes(const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(cs_vRecv);
    vRecvMsg.insert(vRecvMsg.end(), data, data + len);
}

std::vector<uint8_t>& CNode::GetRecvBuffer() {
    // Caller must hold cs_vRecv lock
    return vRecvMsg;
}

void CNode::PushProcessMsg(CProcessedMsg&& msg) {
    std::lock_guard<std::mutex> lock(cs_vProcessMsg);
    msg.nTime = GetTime();
    vProcessMsg.push_back(std::move(msg));
}

bool CNode::PopProcessMsg(CProcessedMsg& msg) {
    std::lock_guard<std::mutex> lock(cs_vProcessMsg);
    if (vProcessMsg.empty()) {
        return false;
    }
    msg = std::move(vProcessMsg.front());
    vProcessMsg.pop_front();
    return true;
}

bool CNode::HasProcessMsgs() const {
    std::lock_guard<std::mutex> lock(cs_vProcessMsg);
    return !vProcessMsg.empty();
}

void CNode::PushSendMsg(CSerializedNetMsg&& msg) {
    std::lock_guard<std::mutex> lock(cs_vSendMsg);
    vSendMsg.push_back(std::move(msg));
}

const CSerializedNetMsg* CNode::GetSendMsg() const {
    std::lock_guard<std::mutex> lock(cs_vSendMsg);
    if (vSendMsg.empty()) {
        return nullptr;
    }
    return &vSendMsg.front();
}

size_t CNode::GetSendOffset() const {
    std::lock_guard<std::mutex> lock(cs_vSendMsg);
    return nSendOffset;
}

void CNode::MarkBytesSent(size_t bytes) {
    std::lock_guard<std::mutex> lock(cs_vSendMsg);
    if (vSendMsg.empty()) return;

    nSendOffset += bytes;
    if (nSendOffset >= vSendMsg.front().data.size()) {
        // Message fully sent, remove it
        vSendMsg.pop_front();
        nSendOffset = 0;
    }
}

bool CNode::HasSendMsgs() const {
    std::lock_guard<std::mutex> lock(cs_vSendMsg);
    return !vSendMsg.empty();
}

std::string CNode::ToString() const {
    std::ostringstream ss;
    ss << "CNode{id=" << id
       << ", addr=" << addr.ip << ":" << addr.port
       << ", state=" << static_cast<int>(state.load())
       << ", inbound=" << (fInbound ? "true" : "false")
       << ", version=" << nVersion
       << "}";
    return ss.str();
}
