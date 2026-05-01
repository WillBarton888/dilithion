// Copyright (c) 2014-2021 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqutil.h
// PR-Z-1: ZMQ notifications skeleton.

#ifndef DILITHION_ZMQ_ZMQUTIL_H
#define DILITHION_ZMQ_ZMQUTIL_H

#include <string>

namespace zmq_util {

// Logs a libzmq error using the current errno via zmq_strerror.
void zmqError(const std::string& str);

// Prefix for unix domain socket addresses (which are local filesystem paths).
// Mirrors libzmq convention; only used for parsing -- IPC support depends on
// libzmq being built with ZMQ_HAVE_IPC. On MSYS2 mingw64 IPC is disabled in
// our submodule build (no afunix.h via that toolchain), so operators are
// expected to use tcp:// only on Windows.
extern const std::string ADDR_PREFIX_IPC;  // "ipc://"

}  // namespace zmq_util

#endif  // DILITHION_ZMQ_ZMQUTIL_H
