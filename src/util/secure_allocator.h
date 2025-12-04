// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_SECURE_ALLOCATOR_H
#define DILITHION_UTIL_SECURE_ALLOCATOR_H

#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

/**
 * FIX-009 (CRYPT-004): Secure Memory Allocator
 *
 * Prevents sensitive data (private keys, master keys, passphrases) from being
 * swapped to disk or leaked in core dumps by using OS-level memory locking.
 *
 * Security Features:
 * - Memory locking: mlock() (Unix) / VirtualLock() (Windows)
 * - Automatic wiping: Secure memory cleanup on deallocation
 * - Swap prevention: Locked pages cannot be swapped to disk
 * - Core dump protection: Locked memory excluded from core dumps (platform-dependent)
 *
 * Platform Support:
 * - Linux: Uses mlock()/munlock() - may require CAP_IPC_LOCK or ulimit -l
 * - Windows: Uses VirtualLock()/VirtualUnlock() - requires SeLockMemoryPrivilege
 * - macOS: Uses mlock()/munlock() - limited by RLIMIT_MEMLOCK
 *
 * Thread Safety: Thread-safe (allocator operations are independent)
 *
 * Usage:
 *   std::vector<uint8_t, SecureAllocator<uint8_t>> secure_data;
 *   // Memory is automatically locked on allocation and wiped+unlocked on deallocation
 */

/**
 * Secure memory wiping - prevents compiler optimization
 *
 * This function is defined in crypter.h, but we need it here too.
 * Using inline to avoid multiple definition errors.
 */
inline void secure_memory_cleanse(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;

#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#elif defined(__GNUC__) || defined(__clang__)
    std::memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    volatile uint8_t* volatile_ptr = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        volatile_ptr[i] = 0;
    }
#endif
}

/**
 * Platform-specific memory locking wrapper
 *
 * Locks memory pages to prevent swapping to disk. This is a best-effort
 * operation - it may fail due to privilege or resource limits, but we
 * don't abort the program in that case (graceful degradation).
 *
 * @param ptr Pointer to memory to lock
 * @param len Length in bytes
 * @return true on success, false on failure (logged but not fatal)
 */
inline bool LockMemory(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) {
        return false;
    }

#ifdef _WIN32
    // Windows: VirtualLock()
    // Returns non-zero on success
    BOOL result = VirtualLock(ptr, len);
    return result != 0;
#else
    // Unix: mlock()
    // Returns 0 on success, -1 on failure
    int result = mlock(ptr, len);
    return result == 0;
#endif
}

/**
 * Platform-specific memory unlocking wrapper
 *
 * Unlocks memory pages. Should be called before freeing memory.
 * Failure is non-fatal (memory will still be freed).
 *
 * @param ptr Pointer to memory to unlock
 * @param len Length in bytes
 * @return true on success, false on failure
 */
inline bool UnlockMemory(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) {
        return false;
    }

#ifdef _WIN32
    // Windows: VirtualUnlock()
    BOOL result = VirtualUnlock(ptr, len);
    return result != 0;
#else
    // Unix: munlock()
    int result = munlock(ptr, len);
    return result == 0;
#endif
}

/**
 * SecureAllocator
 *
 * C++17-compatible allocator that locks allocated memory to prevent swapping
 * and securely wipes memory before deallocation.
 *
 * Implements std::allocator_traits requirements for use with STL containers.
 *
 * Security Properties:
 * 1. Allocated memory is locked (mlock/VirtualLock)
 * 2. Deallocated memory is wiped before unlocking and freeing
 * 3. Best-effort locking (graceful degradation if privileges insufficient)
 *
 * Thread Safety: Thread-safe (no shared state between allocations)
 */
template <typename T>
class SecureAllocator {
public:
    // C++17 allocator type definitions
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;

    // Rebind allocator to different type (required for allocator_traits)
    template <typename U>
    struct rebind {
        typedef SecureAllocator<U> other;
    };

    // Default constructor
    SecureAllocator() noexcept {}

    // Copy constructor
    SecureAllocator(const SecureAllocator&) noexcept {}

    // Rebind copy constructor
    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    // Destructor
    ~SecureAllocator() noexcept {}

    /**
     * Allocate memory and lock it
     *
     * @param n Number of elements to allocate
     * @return Pointer to allocated (and locked) memory
     * @throws std::bad_alloc if allocation fails
     */
    pointer allocate(size_type n) {
        // Check for overflow
        if (n > max_size()) {
            throw std::bad_alloc();
        }

        // Allocate memory
        size_type bytes = n * sizeof(T);
        void* ptr = ::operator new(bytes);

        if (ptr == nullptr) {
            throw std::bad_alloc();
        }

        // CID 1675311 FIX: Initialize memory before locking
        // This ensures the memory is in a known state and satisfies static analyzers
        // that flag uninitialized memory being passed to system calls (mlock/VirtualLock).
        // The actual data will overwrite this, so the overhead is minimal.
        std::memset(ptr, 0, bytes);

        // Lock memory (best-effort, don't throw on failure)
        // Locking may fail due to:
        // - Insufficient privileges (CAP_IPC_LOCK on Linux, SeLockMemoryPrivilege on Windows)
        // - Resource limits (ulimit -l on Linux, working set quota on Windows)
        // - System constraints (total locked memory limits)
        bool locked = LockMemory(ptr, bytes);

        // NOTE: We don't abort if locking fails - this provides graceful degradation.
        // The application can still function without memory locking, just with
        // reduced security (keys may be swapped to disk).
        //
        // In production, you may want to log lock failures for monitoring:
        // if (!locked) {
        //     LogPrint("secure_allocator", "Warning: Failed to lock %zu bytes at %p\n", bytes, ptr);
        // }

        (void)locked;  // Suppress unused variable warning

        return static_cast<pointer>(ptr);
    }

    /**
     * Wipe, unlock, and deallocate memory
     *
     * @param ptr Pointer to memory to deallocate
     * @param n Number of elements (for size calculation)
     */
    void deallocate(pointer ptr, size_type n) noexcept {
        if (ptr == nullptr) {
            return;
        }

        size_type bytes = n * sizeof(T);

        // Step 1: Securely wipe memory (prevents key leakage)
        secure_memory_cleanse(ptr, bytes);

        // Step 2: Unlock memory
        UnlockMemory(ptr, bytes);

        // Step 3: Free memory
        ::operator delete(ptr);
    }

    /**
     * Maximum number of elements that can be allocated
     *
     * @return Maximum size
     */
    size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    /**
     * Construct object at given location
     *
     * @param p Pointer to location
     * @param val Value to construct
     */
    void construct(pointer p, const_reference val) {
        new (p) T(val);
    }

    /**
     * Destroy object at given location
     *
     * @param p Pointer to object
     */
    void destroy(pointer p) {
        p->~T();
    }

    /**
     * Get address of reference
     *
     * @param x Reference to object
     * @return Pointer to object
     */
    pointer address(reference x) const noexcept {
        return &x;
    }

    const_pointer address(const_reference x) const noexcept {
        return &x;
    }
};

/**
 * Allocator equality (all SecureAllocators are equal)
 *
 * This allows containers to be compared and swapped even if they
 * use different allocator instances.
 */
template <typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return true;
}

template <typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return false;
}

#endif // DILITHION_UTIL_SECURE_ALLOCATOR_H
