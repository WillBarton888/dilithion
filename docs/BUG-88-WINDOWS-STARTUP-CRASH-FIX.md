# BUG #88: Windows Startup Crash Fix

## Problem
Local node crashes on startup on Windows, while network is working and synced. This suggests a Windows-specific issue.

## Root Cause Analysis

### Potential Windows-Specific Issues:

1. **Thread Stack Size**: Windows default stack size is 1MB (vs 8MB on Linux), which can cause stack overflow
2. **Reference Capture in Threads**: Threads capture references to local variables that may go out of scope
3. **Winsock Initialization**: Static initialization of Winsock may fail silently
4. **Exception Handling**: Windows SEH (Structured Exception Handling) differs from C++ exceptions
5. **Static Initialization Order**: Static constructors may run in unpredictable order on Windows

## Fixes Applied

### 1. Comprehensive Diagnostic Logging
Added `std::cerr` logging at every critical initialization step:
- Entry into main initialization try block
- Phase 1: Blockchain storage initialization
- Phase 2.5: P2P networking server startup
- Winsock initialization (Windows-specific)
- Each thread creation (accept, receive, maintenance)
- Phase 4: RPC server initialization

All diagnostic messages use `std::cerr` and `flush()` to ensure they appear even if the process crashes immediately after.

### 2. Exception Handling for Thread Creation
Wrapped each `std::thread` creation in try/catch blocks:
- If thread creation fails, log the error
- Set `g_node_state.running = false` to signal shutdown
- Re-throw exception to be caught by outer try/catch
- Prevents silent crashes from thread creation failures

### 3. Thread Initialization Safety
Changed thread declarations to:
```cpp
std::thread p2p_thread;  // Default-constructed (not joinable)
try {
    p2p_thread = std::thread([...]() { ... });
} catch (...) {
    // Handle failure
}
```

This ensures:
- Thread objects are always valid (default-constructed)
- `joinable()` checks are safe even if creation failed
- No undefined behavior from uninitialized thread objects

### 4. Windows-Specific Winsock Initialization Logging
Added explicit logging around `CSocketInit` to diagnose Winsock initialization failures, which are common on Windows.

## Testing
After applying fixes, test on Windows:
1. Clean startup (no existing data)
2. Startup with existing blockchain data
3. Startup after previous crash
4. Multiple rapid start/stop cycles

