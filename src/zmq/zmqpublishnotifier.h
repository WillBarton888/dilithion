// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqpublishnotifier.h
// PR-Z-1: skeleton -- only the abstract publish base. Per-topic publishers
// (hashblock, hashtx, rawblock, rawtx, sequence) land in PR-Z-2.

#ifndef DILITHION_ZMQ_ZMQPUBLISHNOTIFIER_H
#define DILITHION_ZMQ_ZMQPUBLISHNOTIFIER_H

#include <zmq/zmqabstractnotifier.h>

#include <cstddef>
#include <cstdint>

class CZMQAbstractPublishNotifier : public CZMQAbstractNotifier
{
private:
    // Strict-monotonic per-publisher message sequence number. Encoded little-
    // endian as the third frame of the multipart payload. Wraps at 2^32.
    uint32_t nSequence{0U};

public:
    // Send a 3-frame multipart message:
    //   frame 0: command (topic name, e.g. "hashblock")
    //   frame 1: data    (payload, e.g. 32-byte hash)
    //   frame 2: 4-byte LE per-publisher sequence number
    // Returns false if any frame fails to send. The caller must NOT touch the
    // socket after a failed send -- libzmq leaves it in a usable state but
    // the partial multipart frame is lost.
    bool SendZmqMessage(const char* command, const void* data, size_t size);

    bool Initialize(void* pcontext) override;
    void Shutdown() override;
};

// PR-Z-2 will add the concrete publishers here:
//   class CZMQPublishHashBlockNotifier
//   class CZMQPublishHashTransactionNotifier
//   class CZMQPublishRawBlockNotifier
//   class CZMQPublishRawTransactionNotifier
//   class CZMQPublishSequenceNotifier

#endif  // DILITHION_ZMQ_ZMQPUBLISHNOTIFIER_H
