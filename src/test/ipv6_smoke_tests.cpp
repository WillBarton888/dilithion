// Copyright (c) 2025 The Dilithion Core developers
// IPv6 Dual-Stack Smoke Tests
//
// Tests: ParseEndpoint, FillSockAddr, ExtractAddress, DetectFamily,
//        CAddress::SetFromString/ToStringIP/ToString/IsIPv4/IsRoutable,
//        CNetAddr::FromString/ToStringIP, CService::FromString/ToString,
//        CreateListenSocket (dual-stack + listen + accept on loopback)

#include <net/sock.h>
#include <net/protocol.h>
#include <net/netaddress.h>
#include <net/dns.h>
#include <iostream>
#include <cstring>
#include <cassert>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#endif

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr, msg) do { \
    if (expr) { \
        g_pass++; \
        std::cout << "  PASS: " << msg << std::endl; \
    } else { \
        g_fail++; \
        std::cerr << "  FAIL: " << msg << "  (" << #expr << ")" << std::endl; \
    } \
} while(0)

// ============================================================================
// 1. ParseEndpoint tests
// ============================================================================
void test_parse_endpoint() {
    std::cout << "\n--- ParseEndpoint ---" << std::endl;

    std::string ip;
    uint16_t port;

    // IPv4
    CHECK(CSock::ParseEndpoint("1.2.3.4:8444", ip, port) && ip == "1.2.3.4" && port == 8444,
          "IPv4 basic: 1.2.3.4:8444");

    CHECK(CSock::ParseEndpoint("192.168.1.1:18444", ip, port) && ip == "192.168.1.1" && port == 18444,
          "IPv4 testnet port: 192.168.1.1:18444");

    // IPv6 bracket notation
    CHECK(CSock::ParseEndpoint("[::1]:8444", ip, port) && ip == "::1" && port == 8444,
          "IPv6 loopback: [::1]:8444");

    CHECK(CSock::ParseEndpoint("[2001:db8::1]:8444", ip, port) && ip == "2001:db8::1" && port == 8444,
          "IPv6 documentation: [2001:db8::1]:8444");

    CHECK(CSock::ParseEndpoint("[fe80::1%25eth0]:9999", ip, port) && port == 9999,
          "IPv6 with scope: [fe80::1%25eth0]:9999");

    CHECK(CSock::ParseEndpoint("[::ffff:192.168.1.1]:8444", ip, port) && port == 8444,
          "IPv4-mapped IPv6: [::ffff:192.168.1.1]:8444");

    // Hostname
    CHECK(CSock::ParseEndpoint("seed1.dilithion.org:8444", ip, port) && ip == "seed1.dilithion.org" && port == 8444,
          "Hostname: seed1.dilithion.org:8444");

    // Failures
    CHECK(!CSock::ParseEndpoint("", ip, port), "Empty string rejected");
    CHECK(!CSock::ParseEndpoint("1.2.3.4", ip, port), "No port rejected");
    CHECK(!CSock::ParseEndpoint("[::1]", ip, port), "IPv6 no port rejected");
    CHECK(!CSock::ParseEndpoint("[::1:8444", ip, port), "Missing close bracket rejected");
    CHECK(!CSock::ParseEndpoint("1.2.3.4:0", ip, port), "Port 0 rejected");
    CHECK(!CSock::ParseEndpoint("1.2.3.4:99999", ip, port), "Port >65535 rejected");
}

// ============================================================================
// 2. DetectFamily tests
// ============================================================================
void test_detect_family() {
    std::cout << "\n--- DetectFamily ---" << std::endl;

    CHECK(CSock::DetectFamily("1.2.3.4") == AF_INET, "IPv4 -> AF_INET");
    CHECK(CSock::DetectFamily("127.0.0.1") == AF_INET, "Loopback IPv4 -> AF_INET");
    CHECK(CSock::DetectFamily("::1") == AF_INET6, "IPv6 loopback -> AF_INET6");
    CHECK(CSock::DetectFamily("2001:db8::1") == AF_INET6, "IPv6 global -> AF_INET6");
    CHECK(CSock::DetectFamily("::ffff:1.2.3.4") == AF_INET6, "IPv4-mapped -> AF_INET6");
    CHECK(CSock::DetectFamily("not-an-ip") == 0, "Invalid -> 0");
}

// ============================================================================
// 3. FillSockAddr + ExtractAddress round-trip
// ============================================================================
void test_fill_and_extract() {
    std::cout << "\n--- FillSockAddr + ExtractAddress round-trip ---" << std::endl;

    struct sockaddr_storage ss;
    socklen_t ss_len;
    std::string ip_out;
    uint16_t port_out;

    // IPv4 round-trip
    CHECK(CSock::FillSockAddr("1.2.3.4", 8444, ss, ss_len), "FillSockAddr IPv4");
    CHECK(ss.ss_family == AF_INET, "  family is AF_INET");
    CHECK(CSock::ExtractAddress(ss, ip_out, port_out), "  ExtractAddress succeeds");
    CHECK(ip_out == "1.2.3.4" && port_out == 8444, "  round-trip: 1.2.3.4:8444 -> " + ip_out + ":" + std::to_string(port_out));

    // IPv6 round-trip
    CHECK(CSock::FillSockAddr("::1", 18444, ss, ss_len), "FillSockAddr IPv6 ::1");
    CHECK(ss.ss_family == AF_INET6, "  family is AF_INET6");
    CHECK(CSock::ExtractAddress(ss, ip_out, port_out), "  ExtractAddress succeeds");
    CHECK(ip_out == "::1" && port_out == 18444, "  round-trip: ::1:18444 -> " + ip_out + ":" + std::to_string(port_out));

    // IPv6 global round-trip
    CHECK(CSock::FillSockAddr("2001:db8::1", 8444, ss, ss_len), "FillSockAddr IPv6 2001:db8::1");
    CHECK(CSock::ExtractAddress(ss, ip_out, port_out), "  ExtractAddress succeeds");
    CHECK(ip_out == "2001:db8::1" && port_out == 8444, "  round-trip: 2001:db8::1:8444 -> " + ip_out + ":" + std::to_string(port_out));

    // IPv4-mapped IPv6 -> should unwrap to plain IPv4
    CHECK(CSock::FillSockAddr("::ffff:192.168.1.1", 8444, ss, ss_len), "FillSockAddr IPv4-mapped");
    CHECK(CSock::ExtractAddress(ss, ip_out, port_out), "  ExtractAddress succeeds");
    CHECK(ip_out == "192.168.1.1" && port_out == 8444,
          "  unwraps ::ffff:192.168.1.1 -> " + ip_out + ":" + std::to_string(port_out));

    // Invalid
    CHECK(!CSock::FillSockAddr("not-an-ip", 8444, ss, ss_len), "FillSockAddr rejects invalid");
}

// ============================================================================
// 4. CAddress SetFromString / ToStringIP / ToString / IsIPv4
// ============================================================================
void test_caddress() {
    std::cout << "\n--- CAddress ---" << std::endl;

    NetProtocol::CAddress addr;

    // IPv4
    CHECK(addr.SetFromString("1.2.3.4"), "SetFromString IPv4");
    CHECK(addr.IsIPv4(), "  IsIPv4() == true");
    CHECK(addr.ToStringIP() == "1.2.3.4", "  ToStringIP: " + addr.ToStringIP());

    // IPv6
    CHECK(addr.SetFromString("2001:db8::1"), "SetFromString IPv6");
    CHECK(!addr.IsIPv4(), "  IsIPv4() == false");
    std::string ipstr = addr.ToStringIP();
    CHECK(ipstr == "2001:db8::1", "  ToStringIP: " + ipstr);

    // IPv6 loopback
    CHECK(addr.SetFromString("::1"), "SetFromString ::1");
    CHECK(!addr.IsIPv4(), "  IsIPv4() == false");
    CHECK(addr.ToStringIP() == "::1", "  ToStringIP: " + addr.ToStringIP());

    // ToString with port (should bracket IPv6)
    addr.port = 8444;
    std::string full = addr.ToString();
    // Should contain [::1]:8444
    CHECK(full.find("[::1]:8444") != std::string::npos, "  ToString brackets IPv6: " + full);

    // IPv4 with port
    addr.SetFromString("1.2.3.4");
    addr.port = 8444;
    full = addr.ToString();
    CHECK(full.find("1.2.3.4:8444") != std::string::npos, "  ToString no brackets for IPv4: " + full);

    // Invalid
    CHECK(!addr.SetFromString("not-an-ip"), "SetFromString rejects invalid");
    CHECK(!addr.SetFromString(""), "SetFromString rejects empty");
}

// ============================================================================
// 5. CAddress IsRoutable (IPv6-specific checks)
// ============================================================================
void test_routability() {
    std::cout << "\n--- IsRoutable ---" << std::endl;

    NetProtocol::CAddress addr;

    // Routable IPv4
    addr.SetFromString("8.8.8.8");
    CHECK(addr.IsRoutable(), "8.8.8.8 is routable");

    // Private IPv4 — not routable
    addr.SetFromString("10.0.0.1");
    CHECK(!addr.IsRoutable(), "10.0.0.1 NOT routable");

    addr.SetFromString("192.168.1.1");
    CHECK(!addr.IsRoutable(), "192.168.1.1 NOT routable");

    addr.SetFromString("127.0.0.1");
    CHECK(!addr.IsRoutable(), "127.0.0.1 NOT routable");

    // IPv6 loopback — not routable
    addr.SetFromString("::1");
    CHECK(!addr.IsRoutable(), "::1 NOT routable");

    // IPv6 link-local — not routable
    addr.SetFromString("fe80::1");
    CHECK(!addr.IsRoutable(), "fe80::1 NOT routable");

    // IPv6 unique-local — not routable
    addr.SetFromString("fc00::1");
    CHECK(!addr.IsRoutable(), "fc00::1 NOT routable");

    addr.SetFromString("fd00::1");
    CHECK(!addr.IsRoutable(), "fd00::1 NOT routable");

    // IPv6 documentation — not routable
    addr.SetFromString("2001:db8::1");
    CHECK(!addr.IsRoutable(), "2001:db8::1 NOT routable");

    // IPv6 multicast — not routable
    addr.SetFromString("ff02::1");
    CHECK(!addr.IsRoutable(), "ff02::1 NOT routable");

    // Routable IPv6 (global unicast)
    addr.SetFromString("2607:f8b0:4004:800::200e");
    CHECK(addr.IsRoutable(), "2607:f8b0:4004:800::200e is routable (Google)");
}

// ============================================================================
// 6. CNetAddr FromString / ToStringIP
// ============================================================================
void test_cnetaddr() {
    std::cout << "\n--- CNetAddr ---" << std::endl;

    CNetAddr na;

    CHECK(CNetAddr::FromString("1.2.3.4", na), "FromString IPv4");
    CHECK(na.IsIPv4(), "  IsIPv4");
    CHECK(na.ToStringIP() == "1.2.3.4", "  ToStringIP: " + na.ToStringIP());

    CHECK(CNetAddr::FromString("::1", na), "FromString ::1");
    // ::1 is IPv6 loopback, classified as NET_UNROUTABLE (not NET_IPV6)
    // IsIPv6() returns false because it checks network type, not address family
    CHECK(!na.IsIPv6(), "  ::1 is NET_UNROUTABLE, not NET_IPV6 (loopback)");
    CHECK(!na.IsRoutable(), "  ::1 is not routable");
    CHECK(na.ToStringIP() == "::1", "  ToStringIP: " + na.ToStringIP());

    CHECK(CNetAddr::FromString("2001:db8::1", na), "FromString 2001:db8::1");
    CHECK(na.IsIPv6(), "  IsIPv6");
    CHECK(na.ToStringIP() == "2001:db8::1", "  ToStringIP: " + na.ToStringIP());

    CHECK(!CNetAddr::FromString("not-an-ip", na), "FromString rejects invalid");
}

// ============================================================================
// 7. CService FromString / ToString (bracket notation)
// ============================================================================
void test_cservice() {
    std::cout << "\n--- CService ---" << std::endl;

    CService svc;

    CHECK(CService::FromString("1.2.3.4:8444", svc), "FromString IPv4:port");
    CHECK(svc.GetPort() == 8444, "  port == 8444");
    // ToString should produce "1.2.3.4:8444"
    std::string s = svc.ToString();
    CHECK(s.find("1.2.3.4") != std::string::npos && s.find("8444") != std::string::npos,
          "  ToString: " + s);

    CHECK(CService::FromString("[::1]:8444", svc), "FromString [::1]:8444");
    CHECK(svc.GetPort() == 8444, "  port == 8444");
    s = svc.ToString();
    CHECK(s.find("::1") != std::string::npos && s.find("8444") != std::string::npos,
          "  ToString: " + s);

    CHECK(CService::FromString("[2001:db8::1]:18444", svc), "FromString [2001:db8::1]:18444");
    CHECK(svc.GetPort() == 18444, "  port == 18444");

    CHECK(!CService::FromString("[::1]", svc), "FromString [::1] no port rejected");
    CHECK(!CService::FromString("", svc), "FromString empty rejected");
}

// ============================================================================
// 8. DNS resolver IPv6 detection
// ============================================================================
void test_dns_ipv6() {
    std::cout << "\n--- DNS IPv6 detection ---" << std::endl;

    CHECK(CDNSResolver::IsIPv4("1.2.3.4"), "IsIPv4(1.2.3.4)");
    CHECK(!CDNSResolver::IsIPv4("::1"), "!IsIPv4(::1)");
    CHECK(CDNSResolver::IsIPv6("::1"), "IsIPv6(::1)");
    CHECK(CDNSResolver::IsIPv6("2001:db8::1"), "IsIPv6(2001:db8::1)");
    CHECK(CDNSResolver::IsIPv6("fe80::1"), "IsIPv6(fe80::1)");
    CHECK(!CDNSResolver::IsIPv6("1.2.3.4"), "!IsIPv6(1.2.3.4)");
    CHECK(!CDNSResolver::IsIPv6("not-an-ip"), "!IsIPv6(not-an-ip)");
}

// ============================================================================
// 9. CreateListenSocket + connect (live socket test on loopback)
// ============================================================================
void test_listen_socket() {
    std::cout << "\n--- CreateListenSocket (live socket) ---" << std::endl;

    socket_t listen_sock;
    bool is_ipv6 = false;

    // Bind to a high ephemeral port on localhost
    uint16_t test_port = 19876;
    CHECK(CSock::CreateListenSocket(test_port, "127.0.0.1", listen_sock, is_ipv6),
          "CreateListenSocket on 127.0.0.1:" + std::to_string(test_port));

    // Verify listen() works
    CHECK(listen(listen_sock, 5) == 0, "listen() succeeds");

    // Connect from a client socket
    struct sockaddr_storage ss;
    socklen_t ss_len;
    CHECK(CSock::FillSockAddr("127.0.0.1", test_port, ss, ss_len), "FillSockAddr for client");

    socket_t client = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    CHECK(CSock::IsValid(client), "Client socket created");

    int conn_result = connect(client, (struct sockaddr*)&ss, ss_len);
    CHECK(conn_result == 0, "Client connected to listen socket");

    // Accept on server side
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    socket_t accepted = accept(listen_sock, (struct sockaddr*)&peer_addr, &peer_len);
    CHECK(CSock::IsValid(accepted), "Server accepted connection");

    // Extract peer address — should be 127.0.0.1
    std::string peer_ip;
    uint16_t peer_port;
    if (CSock::IsValid(accepted)) {
        CHECK(CSock::ExtractAddress(peer_addr, peer_ip, peer_port), "ExtractAddress on accepted");
        CHECK(peer_ip == "127.0.0.1", "  peer IP is 127.0.0.1, got: " + peer_ip);
    }

    // Cleanup
    if (CSock::IsValid(accepted)) CSock::Close(accepted);
    if (CSock::IsValid(client)) CSock::Close(client);
    CSock::Close(listen_sock);
}

// ============================================================================
// 10. Dual-stack listen test (if OS supports IPv6)
// ============================================================================
void test_dual_stack() {
    std::cout << "\n--- Dual-stack listen (IPv6 if available) ---" << std::endl;

    socket_t listen_sock;
    bool is_ipv6 = false;
    uint16_t test_port = 19877;

    CHECK(CSock::CreateListenSocket(test_port, "", listen_sock, is_ipv6),
          "CreateListenSocket on all interfaces:" + std::to_string(test_port));

    if (is_ipv6) {
        std::cout << "  (IPv6 dual-stack socket created)" << std::endl;
    } else {
        std::cout << "  (IPv4-only fallback — IPv6 not available on this host)" << std::endl;
    }

    CHECK(listen(listen_sock, 5) == 0, "listen() succeeds");

    // Connect via IPv4 (should always work, even on dual-stack)
    struct sockaddr_storage ss;
    socklen_t ss_len;
    CSock::FillSockAddr("127.0.0.1", test_port, ss, ss_len);
    socket_t client = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    int conn_result = connect(client, (struct sockaddr*)&ss, ss_len);
    CHECK(conn_result == 0, "IPv4 client connects to dual-stack listener");

    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    socket_t accepted = accept(listen_sock, (struct sockaddr*)&peer_addr, &peer_len);
    CHECK(CSock::IsValid(accepted), "Server accepts IPv4 client");

    std::string peer_ip;
    uint16_t peer_port;
    if (CSock::IsValid(accepted)) {
        CSock::ExtractAddress(peer_addr, peer_ip, peer_port);
        CHECK(peer_ip == "127.0.0.1", "  IPv4-mapped unwrapped: " + peer_ip);
        CSock::Close(accepted);
    }
    CSock::Close(client);

    // If dual-stack, also try connecting via IPv6 loopback
    if (is_ipv6) {
        CSock::FillSockAddr("::1", test_port, ss, ss_len);
        client = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
        conn_result = connect(client, (struct sockaddr*)&ss, ss_len);
        CHECK(conn_result == 0, "IPv6 client connects to dual-stack listener");

        peer_len = sizeof(peer_addr);
        accepted = accept(listen_sock, (struct sockaddr*)&peer_addr, &peer_len);
        CHECK(CSock::IsValid(accepted), "Server accepts IPv6 client");

        if (CSock::IsValid(accepted)) {
            CSock::ExtractAddress(peer_addr, peer_ip, peer_port);
            CHECK(peer_ip == "::1", "  IPv6 peer is ::1: " + peer_ip);
            CSock::Close(accepted);
        }
        CSock::Close(client);
    }

    CSock::Close(listen_sock);
}

// ============================================================================
// 11. Negative / edge-case endpoint parsing
// ============================================================================
void test_parse_endpoint_edge_cases() {
    std::cout << "\n--- ParseEndpoint edge cases ---" << std::endl;

    std::string ip;
    uint16_t port;

    // Bare IPv6 without brackets (should FAIL — ambiguous with multiple colons)
    CHECK(!CSock::ParseEndpoint("::1:8444", ip, port), "Bare ::1:8444 rejected (ambiguous)");
    CHECK(!CSock::ParseEndpoint("2001:db8::1:8444", ip, port), "Bare 2001:db8::1:8444 rejected");

    // Double brackets
    CHECK(!CSock::ParseEndpoint("[[::1]]:8444", ip, port), "Double brackets rejected");

    // Trailing whitespace
    CHECK(!CSock::ParseEndpoint("[::1]:8444 ", ip, port), "Trailing space rejected");
    CHECK(!CSock::ParseEndpoint(" [::1]:8444", ip, port), "Leading space rejected");

    // Non-numeric port
    CHECK(!CSock::ParseEndpoint("[::1]:abc", ip, port), "Non-numeric port rejected");
    CHECK(!CSock::ParseEndpoint("1.2.3.4:abc", ip, port), "IPv4 non-numeric port rejected");

    // Negative port (stoi returns negative)
    CHECK(!CSock::ParseEndpoint("1.2.3.4:-1", ip, port), "Negative port rejected");

    // Empty IP
    CHECK(!CSock::ParseEndpoint(":8444", ip, port), "Empty IP rejected");

    // Empty port after colon
    CHECK(!CSock::ParseEndpoint("1.2.3.4:", ip, port), "Empty port after colon rejected");

    // IPv6 bracket missing port separator
    CHECK(!CSock::ParseEndpoint("[::1]8444", ip, port), "Missing colon after bracket rejected");

    // Valid edge: port 1 (minimum valid)
    CHECK(CSock::ParseEndpoint("1.2.3.4:1", ip, port) && port == 1, "Port 1 accepted");

    // Valid edge: port 65535 (maximum)
    CHECK(CSock::ParseEndpoint("1.2.3.4:65535", ip, port) && port == 65535, "Port 65535 accepted");

    // Valid: full IPv6 address
    CHECK(CSock::ParseEndpoint("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8444", ip, port),
          "Full (non-compressed) IPv6 accepted");
}

// ============================================================================
// 12. CAddress equivalence: ::ffff:127.0.0.1 vs 127.0.0.1
// ============================================================================
void test_ipv4_mapped_dedup() {
    std::cout << "\n--- IPv4-mapped dedup / equivalence ---" << std::endl;

    // Both should produce the same ToStringIP output (127.0.0.1)
    NetProtocol::CAddress addr_v4, addr_mapped;
    CHECK(addr_v4.SetFromString("127.0.0.1"), "SetFromString 127.0.0.1");
    CHECK(addr_mapped.SetFromString("::ffff:127.0.0.1"), "SetFromString ::ffff:127.0.0.1");

    // The mapped form should be stored as IPv4-mapped internally
    CHECK(addr_mapped.IsIPv4(), "::ffff:127.0.0.1 IsIPv4() == true (mapped)");

    // Both should produce identical ToStringIP
    CHECK(addr_v4.ToStringIP() == "127.0.0.1",
          "  v4 ToStringIP: " + addr_v4.ToStringIP());
    CHECK(addr_mapped.ToStringIP() == "127.0.0.1",
          "  mapped ToStringIP: " + addr_mapped.ToStringIP());

    // Internal bytes should be identical
    CHECK(memcmp(addr_v4.ip, addr_mapped.ip, 16) == 0,
          "  byte-level ip[] identical (dedup safe)");

    // Same for a real address
    NetProtocol::CAddress a1, a2;
    a1.SetFromString("192.168.1.1");
    a2.SetFromString("::ffff:192.168.1.1");
    CHECK(a1.ToStringIP() == a2.ToStringIP(),
          "  192.168.1.1 == ::ffff:192.168.1.1 in ToStringIP");
    CHECK(memcmp(a1.ip, a2.ip, 16) == 0,
          "  byte-level identical for 192.168.1.1");
}

// ============================================================================
// 13. Self-connection: IsOurAddress covers both IPv4 and IPv6 loopback
// ============================================================================
void test_self_connection_filter() {
    std::cout << "\n--- Self-connection filter (CAddress routability) ---" << std::endl;

    // These should all be non-routable (self-connection candidates)
    NetProtocol::CAddress addr;

    addr.SetFromString("127.0.0.1");
    CHECK(!addr.IsRoutable(), "127.0.0.1 not routable (self-conn blocked)");

    addr.SetFromString("::1");
    CHECK(!addr.IsRoutable(), "::1 not routable (self-conn blocked)");

    addr.SetFromString("0.0.0.0");
    CHECK(!addr.IsRoutable(), "0.0.0.0 not routable");

    // IPv4-mapped loopback
    addr.SetFromString("::ffff:127.0.0.1");
    CHECK(!addr.IsRoutable(), "::ffff:127.0.0.1 not routable");

    // Private ranges
    addr.SetFromString("10.0.0.1");
    CHECK(!addr.IsRoutable(), "10.0.0.1 not routable");

    addr.SetFromString("fe80::1");
    CHECK(!addr.IsRoutable(), "fe80::1 not routable (link-local)");

    // Global unicast IS routable
    addr.SetFromString("8.8.8.8");
    CHECK(addr.IsRoutable(), "8.8.8.8 IS routable");

    addr.SetFromString("2607:f8b0:4004:800::200e");
    CHECK(addr.IsRoutable(), "2607:f8b0::200e IS routable");
}

// ============================================================================
// 14. ExtractAddress: IPv4-mapped unwrapping consistency
// ============================================================================
void test_extract_unwrap_consistency() {
    std::cout << "\n--- ExtractAddress unwrap consistency ---" << std::endl;

    // Simulate what happens when an IPv4 client connects to a dual-stack socket:
    // The accept() returns ::ffff:x.x.x.x in sockaddr_in6.
    // ExtractAddress should unwrap to plain IPv4.

    struct sockaddr_in6 mapped_addr;
    memset(&mapped_addr, 0, sizeof(mapped_addr));
    mapped_addr.sin6_family = AF_INET6;
    mapped_addr.sin6_port = htons(8444);

    // Construct ::ffff:1.2.3.4
    uint8_t mapped_bytes[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff, 1,2,3,4};
    memcpy(&mapped_addr.sin6_addr, mapped_bytes, 16);

    struct sockaddr_storage ss;
    memcpy(&ss, &mapped_addr, sizeof(mapped_addr));

    std::string ip_out;
    uint16_t port_out;
    CHECK(CSock::ExtractAddress(ss, ip_out, port_out), "ExtractAddress on synthetic mapped addr");
    CHECK(ip_out == "1.2.3.4", "  unwrapped to 1.2.3.4, got: " + ip_out);
    CHECK(port_out == 8444, "  port is 8444");

    // Pure IPv6 should NOT unwrap
    struct sockaddr_in6 pure_v6;
    memset(&pure_v6, 0, sizeof(pure_v6));
    pure_v6.sin6_family = AF_INET6;
    pure_v6.sin6_port = htons(18444);
    // 2001:db8::1
    uint8_t v6_bytes[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    memcpy(&pure_v6.sin6_addr, v6_bytes, 16);

    memcpy(&ss, &pure_v6, sizeof(pure_v6));
    CHECK(CSock::ExtractAddress(ss, ip_out, port_out), "ExtractAddress on pure IPv6");
    CHECK(ip_out == "2001:db8::1", "  stays as 2001:db8::1, got: " + ip_out);
    CHECK(port_out == 18444, "  port is 18444");
}

// ============================================================================
// 15. Config validator accepts IPv6 bracket notation
// ============================================================================
void test_config_validator_ipv6() {
    std::cout << "\n--- Config validation (bracket notation) ---" << std::endl;

    // These should all pass ParseEndpoint (which config_validator now uses)
    std::string ip;
    uint16_t port;

    CHECK(CSock::ParseEndpoint("192.168.1.1:8444", ip, port), "Config: IPv4 accepted");
    CHECK(CSock::ParseEndpoint("[::1]:8444", ip, port), "Config: [::1]:8444 accepted");
    CHECK(CSock::ParseEndpoint("[2001:db8::1]:8444", ip, port), "Config: [2001:db8::1]:8444 accepted");
    CHECK(CSock::ParseEndpoint("seed1.example.com:8444", ip, port), "Config: hostname accepted");

    // These should fail
    CHECK(!CSock::ParseEndpoint("::1:8444", ip, port), "Config: bare ::1:8444 rejected");
    CHECK(!CSock::ParseEndpoint("192.168.1.1", ip, port), "Config: no port rejected");
}

// ============================================================================
// main
// ============================================================================
int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::cout << "========================================" << std::endl;
    std::cout << "  IPv6 Dual-Stack Smoke Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    test_parse_endpoint();
    test_detect_family();
    test_fill_and_extract();
    test_caddress();
    test_routability();
    test_cnetaddr();
    test_cservice();
    test_dns_ipv6();
    test_listen_socket();
    test_dual_stack();
    test_parse_endpoint_edge_cases();
    test_ipv4_mapped_dedup();
    test_self_connection_filter();
    test_extract_unwrap_consistency();
    test_config_validator_ipv6();

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Results: " << g_pass << " passed, " << g_fail << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

#ifdef _WIN32
    WSACleanup();
#endif

    return g_fail > 0 ? 1 : 0;
}
