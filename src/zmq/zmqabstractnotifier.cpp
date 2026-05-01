// Copyright (c) 2015-2020 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqabstractnotifier.cpp
// PR-Z-1: ZMQ notifications skeleton.

#include <zmq/zmqabstractnotifier.h>

#include <cassert>

const int CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM;

CZMQAbstractNotifier::~CZMQAbstractNotifier()
{
    // psocket must have been released by Shutdown() before destruction. A
    // dangling socket here would leak a libzmq handle and produce inconsistent
    // mapPublishNotifiers state on the next Initialize().
    assert(!psocket);
}

bool CZMQAbstractNotifier::NotifyBlock(const CBlockIndex* /*pindex*/)
{
    return true;
}

bool CZMQAbstractNotifier::NotifyTransaction(const CTransaction& /*transaction*/)
{
    return true;
}

bool CZMQAbstractNotifier::NotifyBlockConnect(const CBlockIndex* /*pindex*/)
{
    return true;
}

bool CZMQAbstractNotifier::NotifyBlockDisconnect(const CBlockIndex* /*pindex*/)
{
    return true;
}

bool CZMQAbstractNotifier::NotifyTransactionAcceptance(const CTransaction& /*transaction*/, uint64_t /*mempool_sequence*/)
{
    return true;
}

bool CZMQAbstractNotifier::NotifyTransactionRemoval(const CTransaction& /*transaction*/, uint64_t /*mempool_sequence*/)
{
    return true;
}
