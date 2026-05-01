// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqabstractnotifier.h
// PR-Z-1: ZMQ notifications skeleton.
//
// PR-Z-1 scope: interface only. PR-Z-2 wires per-topic publishers into
// chainstate/mempool callbacks. PR-Z-3 lands the getzmqnotifications RPC and
// the operator runbook.

#ifndef DILITHION_ZMQ_ZMQABSTRACTNOTIFIER_H
#define DILITHION_ZMQ_ZMQABSTRACTNOTIFIER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

class CBlockIndex;
class CTransaction;
class CZMQAbstractNotifier;

using CZMQNotifierFactory = std::function<std::unique_ptr<CZMQAbstractNotifier>()>;

// Abstract base for all ZMQ notifiers. Mirrors Bitcoin Core v28.0 ABI exactly
// so that subsequent publisher classes can be ported verbatim.
class CZMQAbstractNotifier
{
public:
    static const int DEFAULT_ZMQ_SNDHWM{1000};

    CZMQAbstractNotifier() : outbound_message_high_water_mark(DEFAULT_ZMQ_SNDHWM) {}
    virtual ~CZMQAbstractNotifier();

    template <typename T>
    static std::unique_ptr<CZMQAbstractNotifier> Create()
    {
        return std::make_unique<T>();
    }

    std::string GetType() const { return type; }
    void SetType(const std::string& t) { type = t; }
    std::string GetAddress() const { return address; }
    void SetAddress(const std::string& a) { address = a; }
    int GetOutboundMessageHighWaterMark() const { return outbound_message_high_water_mark; }
    void SetOutboundMessageHighWaterMark(const int sndhwm)
    {
        if (sndhwm >= 0) {
            outbound_message_high_water_mark = sndhwm;
        }
    }

    // Initialize the underlying ZMQ socket. pcontext is a void* zmq_ctx_t.
    // Returns true on success; on failure the implementation must clean up
    // any partial state and return false.
    virtual bool Initialize(void* pcontext) = 0;

    // Tear down the socket. Idempotent: safe to call when not initialized.
    virtual void Shutdown() = 0;

    // Notification hooks. Default implementations are no-ops -- per-topic
    // publishers (PR-Z-2) override the ones they care about.

    // Notifies of ConnectTip result, i.e. new active tip only.
    virtual bool NotifyBlock(const CBlockIndex* pindex);
    // Notifies of every block connection.
    virtual bool NotifyBlockConnect(const CBlockIndex* pindex);
    // Notifies of every block disconnection.
    virtual bool NotifyBlockDisconnect(const CBlockIndex* pindex);
    // Notifies of every mempool acceptance.
    virtual bool NotifyTransactionAcceptance(const CTransaction& transaction, uint64_t mempool_sequence);
    // Notifies of every mempool removal, except inclusion in blocks.
    virtual bool NotifyTransactionRemoval(const CTransaction& transaction, uint64_t mempool_sequence);
    // Notifies of transactions added to mempool or appearing in blocks.
    virtual bool NotifyTransaction(const CTransaction& transaction);

protected:
    void* psocket{nullptr};
    std::string type;
    std::string address;
    int outbound_message_high_water_mark;  // aka SNDHWM
};

#endif  // DILITHION_ZMQ_ZMQABSTRACTNOTIFIER_H
