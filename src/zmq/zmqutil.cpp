// Copyright (c) 2014-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqutil.cpp
// PR-Z-1: ZMQ notifications skeleton.

#include <zmq/zmqutil.h>

#include <util/logging.h>

#include <zmq.h>

#include <cerrno>
#include <string>

namespace zmq_util {

const std::string ADDR_PREFIX_IPC = "ipc://";

void zmqError(const std::string& str)
{
    LogPrintZMQ(WARN, "[zmq] error: %s, msg: %s", str.c_str(), zmq_strerror(errno));
}

}  // namespace zmq_util
