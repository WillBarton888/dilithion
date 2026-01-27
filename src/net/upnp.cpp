// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// UPnP port mapping support using miniupnpc

#include <net/upnp.h>
#include <util/logging.h>

// Coverity static analysis: provide stubs when miniupnpc headers unavailable
#if defined(__COVERITY__) && !defined(MINIUPNPC_API_VERSION)
// Minimal stubs for Coverity to parse this file
struct UPNPDev { struct UPNPDev* pNext; };
struct UPNPUrls { char* controlURL; };
struct IGDdatas { struct { char servicetype[256]; } first; };
inline UPNPDev* upnpDiscover(int, const char*, const char*, int, int, int, int*) { return nullptr; }
inline int UPNP_GetValidIGD(UPNPDev*, UPNPUrls*, IGDdatas*, char*, int, char*, int) { return 0; }
inline int UPNP_GetExternalIPAddress(const char*, const char*, char*) { return 0; }
inline int UPNP_AddPortMapping(const char*, const char*, const char*, const char*, const char*, const char*, const char*, const char*, const char*) { return 0; }
inline int UPNP_DeletePortMapping(const char*, const char*, const char*, const char*, const char*) { return 0; }
inline void FreeUPNPUrls(UPNPUrls*) {}
inline void freeUPNPDevlist(UPNPDev*) {}
inline const char* strupnperror(int) { return ""; }
#else
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#include <cstdio>
#include <cstring>

namespace UPnP {

// Static state for UPnP session
static UPNPDev* s_devlist = nullptr;
static UPNPUrls s_urls;
static IGDdatas s_data;
static bool s_initialized = false;
static std::string s_lastError;
static uint16_t s_mappedPort = 0;

bool MapPort(uint16_t port, std::string& externalIP) {
    int error = 0;

    // Discover UPnP devices (2 second timeout)
    s_devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, &error);
    if (!s_devlist) {
        s_lastError = "No UPnP devices found on network";
        LogPrintf(NET, WARN, "[UPnP] %s (error=%d)\n", s_lastError.c_str(), error);
        return false;
    }

    // Find valid IGD (Internet Gateway Device)
    // miniupnpc API changed between versions:
    // - API < 18: 5 parameters (lanaddr only)
    // - API >= 18: 7 parameters (adds wanaddr)
    char lanaddr[64] = "";
#if defined(MINIUPNPC_API_VERSION) && MINIUPNPC_API_VERSION >= 18
    char wanaddr[64] = "";
    int status = UPNP_GetValidIGD(s_devlist, &s_urls, &s_data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
#else
    int status = UPNP_GetValidIGD(s_devlist, &s_urls, &s_data, lanaddr, sizeof(lanaddr));
#endif

    if (status == 0) {
        s_lastError = "No valid IGD found";
        LogPrintf(NET, WARN, "[UPnP] %s\n", s_lastError.c_str());
        freeUPNPDevlist(s_devlist);
        s_devlist = nullptr;
        return false;
    }

    if (status == 1) {
        LogPrintf(NET, INFO, "[UPnP] Found valid IGD: %s\n", s_urls.controlURL);
    } else if (status == 2) {
        LogPrintf(NET, INFO, "[UPnP] Found IGD (not connected): %s\n", s_urls.controlURL);
    } else if (status == 3) {
        LogPrintf(NET, INFO, "[UPnP] Found UPnP device (not IGD): %s\n", s_urls.controlURL);
    }

    LogPrintf(NET, INFO, "[UPnP] Local LAN IP: %s\n", lanaddr);

    // Get external IP address
    char externalIPAddress[40] = "";
    int ret = UPNP_GetExternalIPAddress(s_urls.controlURL, s_data.first.servicetype, externalIPAddress);
    if (ret == 0 && externalIPAddress[0] != '\0') {
        externalIP = externalIPAddress;
        LogPrintf(NET, INFO, "[UPnP] External IP: %s\n", externalIPAddress);
    } else {
        LogPrintf(NET, WARN, "[UPnP] Could not get external IP address (error=%d)\n", ret);
    }

    // Add port mapping
    char portStr[6];
    snprintf(portStr, sizeof(portStr), "%d", port);

    int result = UPNP_AddPortMapping(
        s_urls.controlURL,
        s_data.first.servicetype,
        portStr,           // External port
        portStr,           // Internal port
        lanaddr,           // Internal client
        "Dilithion Node",  // Description
        "TCP",             // Protocol
        nullptr,           // Remote host (any)
        "0"                // Lease duration (0 = permanent until removed)
    );

    if (result != 0) {
        s_lastError = strupnperror(result);
        LogPrintf(NET, WARN, "[UPnP] Failed to add port mapping: %s (error=%d)\n",
                  s_lastError.c_str(), result);

        // Try with a specific lease time if permanent mapping failed
        if (result == 725 || result == 718) {  // OnlyPermanentLeasesSupported or ConflictInMappingEntry
            result = UPNP_AddPortMapping(
                s_urls.controlURL,
                s_data.first.servicetype,
                portStr,
                portStr,
                lanaddr,
                "Dilithion Node",
                "TCP",
                nullptr,
                "3600"  // 1 hour lease
            );
            if (result == 0) {
                LogPrintf(NET, INFO, "[UPnP] Port mapping added with 1 hour lease\n");
            }
        }

        if (result != 0) {
            FreeUPNPUrls(&s_urls);
            freeUPNPDevlist(s_devlist);
            s_devlist = nullptr;
            return false;
        }
    }

    LogPrintf(NET, INFO, "[UPnP] Successfully mapped port %d (TCP)\n", port);
    s_initialized = true;
    s_mappedPort = port;
    return true;
}

void UnmapPort(uint16_t port) {
    if (!s_initialized) {
        return;
    }

    char portStr[6];
    snprintf(portStr, sizeof(portStr), "%d", port);

    int result = UPNP_DeletePortMapping(
        s_urls.controlURL,
        s_data.first.servicetype,
        portStr,
        "TCP",
        nullptr
    );

    if (result == 0) {
        LogPrintf(NET, INFO, "[UPnP] Port mapping removed for port %d\n", port);
    } else {
        LogPrintf(NET, WARN, "[UPnP] Failed to remove port mapping: %s\n", strupnperror(result));
    }

    FreeUPNPUrls(&s_urls);
    if (s_devlist) {
        freeUPNPDevlist(s_devlist);
        s_devlist = nullptr;
    }
    s_initialized = false;
    s_mappedPort = 0;
}

bool IsAvailable() {
    int error = 0;
    UPNPDev* devlist = upnpDiscover(1000, nullptr, nullptr, 0, 0, 2, &error);
    bool available = (devlist != nullptr);
    if (devlist) {
        freeUPNPDevlist(devlist);
    }
    return available;
}

std::string GetLastError() {
    return s_lastError;
}

} // namespace UPnP
