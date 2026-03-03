// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 6 script system unit tests.
 *
 * Tests the script interpreter (EvalScript/VerifyScript), HTLC builder,
 * and atomic swap state machine persistence.
 *
 * Uses a MockSignatureChecker to test opcode flow without needing real
 * Dilithium3 keypairs, keeping the tests fast and deterministic.
 *
 * Run: ./script_tests
 */

#include <script/script.h>
#include <script/interpreter.h>
#include <script/htlc.h>
#include <script/atomic_swap.h>
#include <crypto/sha3.h>

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <string>

// ============================================================================
// Test framework (same pattern as cooldown_test.cpp)
// ============================================================================

static int passed = 0;
static int failed = 0;

#define TEST(name) \
    do { std::cout << "  " << #name << "... "; std::cout.flush(); } while(0)

#define PASS() \
    do { std::cout << "PASS\n"; ++passed; } while(0)

#define FAIL_MSG(msg) \
    do { std::cout << "FAIL (" << msg << ")\n"; ++failed; return; } while(0)

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cout << "FAIL (" << #cond << ")\n"; \
            ++failed; \
            return; \
        } \
    } while(0)

#define CHECK_MSG(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cout << "FAIL: " << msg << "\n"; \
            ++failed; \
            return; \
        } \
    } while(0)

// ============================================================================
// MockSignatureChecker
// Allows testing opcode flow without real Dilithium3 keys.
// ============================================================================

class MockChecker : public SignatureChecker {
public:
    bool  m_pass_sig;      // return value of CheckSig
    int64_t m_height;      // simulated "current block height" for CLTV
    bool  m_pass_seq;      // return value of CheckSequence

    MockChecker(bool pass_sig = true, int64_t height = 0, bool pass_seq = true)
        : m_pass_sig(pass_sig), m_height(height), m_pass_seq(pass_seq) {}

    bool CheckSig(const std::vector<uint8_t>&, const std::vector<uint8_t>&) const override {
        return m_pass_sig;
    }

    // CLTV: succeeds if our "current height" >= the script's lock value
    bool CheckLockTime(int64_t nLockTime) const override {
        return m_height >= nLockTime;
    }

    bool CheckSequence(int64_t) const override {
        return m_pass_seq;
    }
};

// ============================================================================
// Helpers
// ============================================================================

// A valid-looking fake Dilithium3 signature (3309 bytes, not all-zero or all-one)
static std::vector<uint8_t> FakeSig() {
    std::vector<uint8_t> v(3309, 0xAB);
    v[0] = 0x01;  // ensure not all-same
    return v;
}

// A valid-looking fake Dilithium3 public key (1952 bytes, not all-zero or all-one)
static std::vector<uint8_t> FakePubKey() {
    std::vector<uint8_t> v(1952, 0xCD);
    v[0] = 0x02;
    return v;
}

// HASH160 = double SHA3-256 truncated to 20 bytes.
// Matches WalletCrypto::HashPubKey in wallet.cpp.
static std::vector<uint8_t> Hash160(const std::vector<uint8_t>& data) {
    uint8_t h1[32], h2[32];
    SHA3_256(data.data(), data.size(), h1);
    SHA3_256(h1, 32, h2);
    return std::vector<uint8_t>(h2, h2 + 20);
}

// ============================================================================
// Stack opcode tests
// ============================================================================

static void test_op_0_is_false() {
    TEST(op_0_is_false);
    MockChecker c;
    CScript s; s << OP_0;
    std::vector<std::vector<uint8_t>> stack;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    // OP_0 pushes an empty vector (= false)
    CHECK(stack[0].empty());
    PASS();
}

static void test_op_1_is_true() {
    TEST(op_1_is_true);
    MockChecker c;
    CScript s; s << OP_1;
    std::vector<std::vector<uint8_t>> stack;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(!stack[0].empty());
    CHECK(stack[0][0] == 0x01);
    PASS();
}

static void test_op_dup_doubles_top() {
    TEST(op_dup_doubles_top);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0x42, 0xFF} };
    CScript s; s << OP_DUP;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 2);
    CHECK(stack[0] == stack[1]);
    auto expected_dup = std::vector<uint8_t>{0x42, 0xFF};
    CHECK(stack[0] == expected_dup);
    PASS();
}

static void test_op_drop_removes_top() {
    TEST(op_drop_removes_top);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0x01}, {0x02} };
    CScript s; s << OP_DROP;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0] == std::vector<uint8_t>{0x01});
    PASS();
}

static void test_op_swap_exchanges_top_two() {
    TEST(op_swap_exchanges_top_two);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0xAA}, {0xBB} };
    CScript s; s << OP_SWAP;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 2);
    CHECK(stack[0] == std::vector<uint8_t>{0xBB});
    CHECK(stack[1] == std::vector<uint8_t>{0xAA});
    PASS();
}

static void test_op_size_pushes_length() {
    TEST(op_size_pushes_length);
    MockChecker c;
    std::vector<uint8_t> data(7, 0xFF);
    std::vector<std::vector<uint8_t>> stack = { data };
    CScript s; s << OP_SIZE;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    // OP_SIZE pushes the length as a script number; top stays on stack
    CHECK(stack.size() == 2);
    CHECK(stack.back().size() == 1);
    CHECK(stack.back()[0] == 7);
    PASS();
}

static void test_op_dup_underflow_fails() {
    TEST(op_dup_underflow_fails);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack;  // empty
    CScript s; s << OP_DUP;
    std::string err;
    CHECK(!EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

// ============================================================================
// Equality opcode tests
// ============================================================================

static void test_op_equal_matching() {
    TEST(op_equal_matching);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0xAA, 0xBB}, {0xAA, 0xBB} };
    CScript s; s << OP_EQUAL;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(!stack[0].empty() && stack[0][0] != 0);  // true
    PASS();
}

static void test_op_equal_different() {
    TEST(op_equal_different);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0xAA}, {0xBB} };
    CScript s; s << OP_EQUAL;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0].empty() || stack[0][0] == 0);  // false
    PASS();
}

static void test_op_equalverify_matching_succeeds() {
    TEST(op_equalverify_matching_succeeds);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0x55}, {0x55} };
    CScript s; s << OP_EQUALVERIFY;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.empty());  // EQUALVERIFY consumes both elements
    PASS();
}

static void test_op_equalverify_different_fails() {
    TEST(op_equalverify_different_fails);
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { {0x55}, {0x66} };
    CScript s; s << OP_EQUALVERIFY;
    std::string err;
    CHECK(!EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

// ============================================================================
// Crypto opcode tests
// ============================================================================

static void test_op_sha3_256_known_input() {
    TEST(op_sha3_256_known_input);
    std::vector<uint8_t> input(32, 0x5A);
    uint8_t expected[32];
    SHA3_256(input.data(), input.size(), expected);

    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { input };
    CScript s; s << OP_SHA3_256;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0].size() == 32);
    CHECK(memcmp(stack[0].data(), expected, 32) == 0);
    PASS();
}

static void test_op_sha3_256_different_inputs_differ() {
    TEST(op_sha3_256_different_inputs_differ);
    // Two different inputs must produce different hashes
    std::vector<uint8_t> a(32, 0x01), b(32, 0x02);
    uint8_t ha[32], hb[32];
    SHA3_256(a.data(), a.size(), ha);
    SHA3_256(b.data(), b.size(), hb);
    CHECK(memcmp(ha, hb, 32) != 0);
    PASS();
}

static void test_op_hash160_matches_wallet_hash_pubkey() {
    TEST(op_hash160_matches_wallet_hash_pubkey);
    std::vector<uint8_t> data(64, 0x7E);
    std::vector<uint8_t> expected = Hash160(data);

    MockChecker c;
    std::vector<std::vector<uint8_t>> stack = { data };
    CScript s; s << OP_HASH160;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0].size() == 20);
    CHECK(stack[0] == expected);
    PASS();
}

// ============================================================================
// Control flow tests
// ============================================================================

static void test_if_true_branch_executes() {
    TEST(if_true_branch_executes);
    // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF  → stack = [2]
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack;
    CScript s;
    s << OP_1 << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0] == std::vector<uint8_t>{0x02});
    PASS();
}

static void test_if_false_branch_executes() {
    TEST(if_false_branch_executes);
    // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF  → stack = [3]
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack;
    CScript s;
    s << OP_0 << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0] == std::vector<uint8_t>{0x03});
    PASS();
}

static void test_nested_if() {
    TEST(nested_if);
    // OP_1 OP_IF  OP_1 OP_IF  OP_7  OP_ELSE  OP_8  OP_ENDIF  OP_ENDIF  → [7]
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack;
    CScript s;
    s << OP_1 << OP_IF
          << OP_1 << OP_IF
              << (int64_t)7
          << OP_ELSE
              << (int64_t)8
          << OP_ENDIF
      << OP_ENDIF;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0] == std::vector<uint8_t>{0x07});
    PASS();
}

static void test_op_return_fails_evaluation() {
    TEST(op_return_fails_evaluation);
    MockChecker c;
    CScript s; s << OP_RETURN;
    CHECK(s.IsUnspendable());
    std::vector<std::vector<uint8_t>> stack;
    std::string err;
    CHECK(!EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

// ============================================================================
// Locktime tests
// ============================================================================

static void test_cltv_passes_when_height_sufficient() {
    TEST(cltv_passes_when_height_sufficient);
    // Script has locktime=50, mock says current height=100 → pass
    MockChecker c(true, 100);
    std::vector<std::vector<uint8_t>> stack;
    CScript s; s << (int64_t)50 << OP_CHECKLOCKTIMEVERIFY;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    CHECK(stack.size() == 1);  // CLTV does NOT pop
    PASS();
}

static void test_cltv_fails_when_height_too_low() {
    TEST(cltv_fails_when_height_too_low);
    // Script has locktime=500, mock says current height=10 → fail
    MockChecker c(true, 10);
    std::vector<std::vector<uint8_t>> stack;
    CScript s; s << (int64_t)500 << OP_CHECKLOCKTIMEVERIFY;
    std::string err;
    CHECK(!EvalScript(stack, s, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_cltv_acts_as_nop_without_flag() {
    TEST(cltv_acts_as_nop_without_flag);
    // Without the CLTV verify flag, OP_CHECKLOCKTIMEVERIFY is treated as OP_NOP
    // (never fails, even if height would be insufficient)
    MockChecker c(true, 0);  // height=0, would fail if enforced
    std::vector<std::vector<uint8_t>> stack;
    CScript s; s << (int64_t)9999 << OP_CHECKLOCKTIMEVERIFY;
    std::string err;
    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, c, err));  // succeeds as NOP
    PASS();
}

// ============================================================================
// Security / limit tests
// ============================================================================

static void test_script_too_large_rejected() {
    TEST(script_too_large_rejected);
    // MAX_SCRIPT_SIZE = 20000; a 20001-byte script should fail immediately
    std::vector<uint8_t> big_bytes(20001, static_cast<uint8_t>(OP_NOP));
    CScript big(big_bytes.data(), big_bytes.data() + big_bytes.size());
    MockChecker c;
    std::vector<std::vector<uint8_t>> stack;
    std::string err;
    CHECK(!EvalScript(stack, big, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

// ============================================================================
// P2PKH backward-compatibility tests
// ============================================================================

static void test_p2pkh_with_correct_key_passes() {
    TEST(p2pkh_with_correct_key_passes);
    auto pk = FakePubKey();
    auto pkh = Hash160(pk);

    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;
    CHECK(scriptPubKey.IsPayToPublicKeyHash());

    CScript scriptSig;
    scriptSig << FakeSig() << pk;

    MockChecker c;  // CheckSig returns true
    std::string err;
    CHECK(VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

static void test_p2pkh_with_wrong_key_fails() {
    TEST(p2pkh_with_wrong_key_fails);
    auto pk_a = FakePubKey();
    auto pk_b = std::vector<uint8_t>(1952, 0xEE);  // different pubkey
    auto pkh = Hash160(pk_a);  // script is locked to pk_a

    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;

    CScript scriptSig;
    scriptSig << FakeSig() << pk_b;  // but we present pk_b

    MockChecker c;
    std::string err;
    // pk_b hash != pkh → EQUALVERIFY fails
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

static void test_p2pkh_sig_failure_propagates() {
    TEST(p2pkh_sig_failure_propagates);
    auto pk = FakePubKey();
    auto pkh = Hash160(pk);

    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;

    CScript scriptSig;
    scriptSig << FakeSig() << pk;

    MockChecker c(false);  // CheckSig returns false
    std::string err;
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_NONE, c, err));
    PASS();
}

// ============================================================================
// HTLC script tests
// ============================================================================

static HTLCParameters MakeTestHTLC(const std::vector<uint8_t>& preimage,
                                    const std::vector<uint8_t>& claim_pk,
                                    const std::vector<uint8_t>& refund_pk,
                                    uint32_t timeout) {
    uint8_t hash_buf[32];
    SHA3_256(preimage.data(), preimage.size(), hash_buf);
    HTLCParameters p;
    p.hash_lock          = std::vector<uint8_t>(hash_buf, hash_buf + 32);
    p.claim_pubkey_hash  = Hash160(claim_pk);
    p.refund_pubkey_hash = Hash160(refund_pk);
    p.timeout_height     = timeout;
    return p;
}

static void test_decode_htlc_roundtrip() {
    TEST(decode_htlc_roundtrip);
    std::vector<uint8_t> preimage(32, 0xDE);
    auto params = MakeTestHTLC(preimage, FakePubKey(), FakePubKey(), 1000);
    CScript script = CreateHTLCScript(params);

    CHECK(!script.empty());
    CHECK(script.IsHTLC());

    HTLCParameters decoded;
    CHECK(DecodeHTLCScript(script, decoded));
    CHECK(decoded.hash_lock         == params.hash_lock);
    CHECK(decoded.claim_pubkey_hash  == params.claim_pubkey_hash);
    CHECK(decoded.refund_pubkey_hash == params.refund_pubkey_hash);
    CHECK(decoded.timeout_height     == params.timeout_height);
    PASS();
}

static void test_htlc_claim_correct_preimage_succeeds() {
    TEST(htlc_claim_correct_preimage_succeeds);
    std::vector<uint8_t> preimage(32, 0xBE);
    auto claim_pk = FakePubKey();
    auto params   = MakeTestHTLC(preimage, claim_pk, std::vector<uint8_t>(1952, 0x33), 500);

    CScript scriptPubKey = CreateHTLCScript(params);
    CScript scriptSig    = CreateHTLCClaimScript(FakeSig(), claim_pk, preimage);

    // height=100 (before timeout — shouldn't affect claim path)
    MockChecker c(true, 100);
    std::string err;
    CHECK(VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_htlc_claim_wrong_preimage_fails() {
    TEST(htlc_claim_wrong_preimage_fails);
    std::vector<uint8_t> preimage(32, 0xBE);
    auto claim_pk = FakePubKey();
    auto params   = MakeTestHTLC(preimage, claim_pk, std::vector<uint8_t>(1952, 0x33), 500);

    CScript scriptPubKey = CreateHTLCScript(params);
    std::vector<uint8_t> wrong_preimage(32, 0xFF);  // wrong!
    CScript scriptSig    = CreateHTLCClaimScript(FakeSig(), claim_pk, wrong_preimage);

    MockChecker c(true, 100);
    std::string err;
    // SHA3-256(wrong_preimage) != hash_lock → EQUALVERIFY fails
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_htlc_claim_wrong_pubkey_fails() {
    TEST(htlc_claim_wrong_pubkey_fails);
    std::vector<uint8_t> preimage(32, 0x55);
    auto claim_pk   = FakePubKey();               // correct pubkey
    auto wrong_pk   = std::vector<uint8_t>(1952, 0xEE);  // wrong pubkey
    auto params     = MakeTestHTLC(preimage, claim_pk, std::vector<uint8_t>(1952, 0x33), 500);

    CScript scriptPubKey = CreateHTLCScript(params);
    CScript scriptSig    = CreateHTLCClaimScript(FakeSig(), wrong_pk, preimage);

    MockChecker c(true, 100);
    std::string err;
    // Hash160(wrong_pk) != claim_pubkey_hash → EQUALVERIFY fails
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_htlc_refund_after_timeout_succeeds() {
    TEST(htlc_refund_after_timeout_succeeds);
    std::vector<uint8_t> preimage(32, 0xCA);
    auto refund_pk = FakePubKey();
    auto params    = MakeTestHTLC(preimage, std::vector<uint8_t>(1952, 0x11), refund_pk, 50);

    CScript scriptPubKey = CreateHTLCScript(params);
    CScript scriptSig    = CreateHTLCRefundScript(FakeSig(), refund_pk);

    // height=100 (well past timeout=50) → CLTV passes
    MockChecker c(true, 100);
    std::string err;
    CHECK(VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_htlc_refund_before_timeout_fails() {
    TEST(htlc_refund_before_timeout_fails);
    std::vector<uint8_t> preimage(32, 0xCA);
    auto refund_pk = FakePubKey();
    auto params    = MakeTestHTLC(preimage, std::vector<uint8_t>(1952, 0x11), refund_pk, 500);

    CScript scriptPubKey = CreateHTLCScript(params);
    CScript scriptSig    = CreateHTLCRefundScript(FakeSig(), refund_pk);

    // height=10 (BEFORE timeout=500) → CLTV fails
    MockChecker c(true, 10);
    std::string err;
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_htlc_refund_wrong_pubkey_fails() {
    TEST(htlc_refund_wrong_pubkey_fails);
    std::vector<uint8_t> preimage(32, 0x77);
    auto refund_pk  = FakePubKey();
    auto wrong_pk   = std::vector<uint8_t>(1952, 0xEE);
    auto params     = MakeTestHTLC(preimage, std::vector<uint8_t>(1952, 0x11), refund_pk, 50);

    CScript scriptPubKey = CreateHTLCScript(params);
    CScript scriptSig    = CreateHTLCRefundScript(FakeSig(), wrong_pk);  // wrong key

    MockChecker c(true, 100);
    std::string err;
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

static void test_htlc_claim_cant_use_refund_script() {
    TEST(htlc_claim_cant_use_refund_script);
    // An attacker tries to use a refund scriptSig to claim (without preimage).
    // The IF branch requires preimage + sig; the ELSE branch needs CLTV to pass.
    std::vector<uint8_t> preimage(32, 0x42);
    auto claim_pk = FakePubKey();
    auto refund_pk = std::vector<uint8_t>(1952, 0x33);
    auto params = MakeTestHTLC(preimage, claim_pk, refund_pk, 500);

    CScript scriptPubKey = CreateHTLCScript(params);
    // Refund scriptSig: [sig] [pubkey] OP_FALSE  → takes ELSE branch
    // But height=10 < timeout=500  →  CLTV fails
    CScript scriptSig = CreateHTLCRefundScript(FakeSig(), refund_pk);

    MockChecker c(true, 10);  // before timeout
    std::string err;
    CHECK(!VerifyScript(scriptSig, scriptPubKey, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, c, err));
    PASS();
}

// ============================================================================
// HTLC builder helper tests
// ============================================================================

static void test_generate_preimage_random_and_32_bytes() {
    TEST(generate_preimage_random_and_32_bytes);
    auto p1 = GeneratePreimage();
    auto p2 = GeneratePreimage();
    CHECK(p1.size() == 32);
    CHECK(p2.size() == 32);
    CHECK(p1 != p2);  // negligible collision probability
    PASS();
}

static void test_hash_preimage_deterministic() {
    TEST(hash_preimage_deterministic);
    std::vector<uint8_t> preimage(32, 0xAB);
    auto h1 = HashPreimage(preimage);
    auto h2 = HashPreimage(preimage);
    CHECK(h1.size() == 32);
    CHECK(h1 == h2);  // same input → same hash
    PASS();
}

static void test_hash_preimage_different_inputs_differ() {
    TEST(hash_preimage_different_inputs_differ);
    std::vector<uint8_t> a(32, 0x01), b(32, 0x02);
    CHECK(HashPreimage(a) != HashPreimage(b));
    PASS();
}

static void test_hash_preimage_matches_sha3_256() {
    TEST(hash_preimage_matches_sha3_256);
    std::vector<uint8_t> preimage(32, 0xCC);
    uint8_t direct[32];
    SHA3_256(preimage.data(), 32, direct);
    auto via_helper = HashPreimage(preimage);
    CHECK(via_helper == std::vector<uint8_t>(direct, direct + 32));
    PASS();
}

// ============================================================================
// SwapStore persistence tests
// ============================================================================

static void test_swap_store_add_get() {
    TEST(swap_store_add_get);
    SwapStore store;
    store.SetPath("test_swaps_tmp.json");
    store.Load();  // file doesn't exist → silent success
    CHECK(store.Size() == 0);

    SwapInfo s;
    s.swap_id          = "aabbccdd11223344";
    s.role             = SwapRole::INITIATOR;
    s.state            = SwapState::HTLC_FUNDED;
    s.our_chain        = "dilv";
    s.our_amount       = 100000000;
    s.our_htlc_txid    = "deadbeef01020304";
    s.our_timeout      = 1000;
    s.their_chain      = "dil";
    s.their_amount     = 50000000;
    s.hash_lock        = std::vector<uint8_t>(32, 0x42);
    s.preimage         = std::vector<uint8_t>(32, 0x12);
    s.created_at       = 1740000000;

    store.AddSwap(s);
    CHECK(store.Size() == 1);

    SwapInfo out;
    CHECK(store.GetSwap(s.swap_id, out));
    CHECK(out.swap_id    == s.swap_id);
    CHECK(out.role       == s.role);
    CHECK(out.state      == s.state);
    CHECK(out.our_amount == s.our_amount);
    CHECK(out.hash_lock  == s.hash_lock);
    CHECK(out.preimage   == s.preimage);
    PASS();
}

static void test_swap_store_update() {
    TEST(swap_store_update);
    SwapStore store;
    store.SetPath("test_swaps_tmp.json");
    store.Load();

    // swap was already added in previous test (file persists)
    SwapInfo s;
    CHECK(store.GetSwap("aabbccdd11223344", s));
    s.state = SwapState::CLAIMED;
    CHECK(store.UpdateSwap(s.swap_id, s));

    SwapInfo reread;
    CHECK(store.GetSwap(s.swap_id, reread));
    CHECK(reread.state == SwapState::CLAIMED);
    PASS();
}

static void test_swap_store_persist_and_reload() {
    TEST(swap_store_persist_and_reload);
    // Reload from the file written by the previous two tests
    SwapStore store2;
    store2.SetPath("test_swaps_tmp.json");
    store2.Load();
    CHECK(store2.Size() == 1);

    SwapInfo reloaded;
    CHECK(store2.GetSwap("aabbccdd11223344", reloaded));
    CHECK(reloaded.our_amount == 100000000);
    CHECK(reloaded.state      == SwapState::CLAIMED);

    // Cleanup temp file
    std::remove("test_swaps_tmp.json");
    PASS();
}

static void test_swap_store_list_filter() {
    TEST(swap_store_list_filter);
    SwapStore store;
    store.SetPath("");  // in-memory only (no path)

    // Add two swaps with different states
    SwapInfo a;
    a.swap_id = "aaaa"; a.state = SwapState::HTLC_FUNDED;
    store.AddSwap(a);

    SwapInfo b;
    b.swap_id = "bbbb"; b.state = SwapState::COMPLETED;
    store.AddSwap(b);

    CHECK(store.ListSwaps(-1).size() == 2);
    CHECK(store.ListSwaps(static_cast<int>(SwapState::HTLC_FUNDED)).size() == 1);
    CHECK(store.ListSwaps(static_cast<int>(SwapState::COMPLETED)).size() == 1);
    CHECK(store.ListSwaps(static_cast<int>(SwapState::REFUNDED)).size() == 0);
    PASS();
}

static void test_swap_store_get_missing_returns_false() {
    TEST(swap_store_get_missing_returns_false);
    SwapStore store;
    SwapInfo out;
    CHECK(!store.GetSwap("nonexistent", out));
    PASS();
}

// ============================================================================
// Script type detection tests
// ============================================================================

static void test_is_p2pkh_detection() {
    TEST(is_p2pkh_detection);
    std::vector<uint8_t> pkh(20, 0xAB);
    CScript s;
    s << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;
    CHECK(s.IsPayToPublicKeyHash());
    CHECK(!s.IsHTLC());
    CHECK(!s.IsUnspendable());
    PASS();
}

static void test_is_htlc_detection() {
    TEST(is_htlc_detection);
    std::vector<uint8_t> preimage(32, 0xFF);
    auto params = MakeTestHTLC(preimage, FakePubKey(), FakePubKey(), 100);
    CScript s = CreateHTLCScript(params);
    CHECK(s.IsHTLC());
    CHECK(!s.IsPayToPublicKeyHash());
    CHECK(!s.IsUnspendable());
    PASS();
}

static void test_is_unspendable_detection() {
    TEST(is_unspendable_detection);
    CScript s; s << OP_RETURN;
    CHECK(s.IsUnspendable());
    CHECK(!s.IsPayToPublicKeyHash());
    CHECK(!s.IsHTLC());
    PASS();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Phase 6 Script System Unit Tests ===\n\n";

    std::cout << "-- Stack Opcodes --\n";
    test_op_0_is_false();
    test_op_1_is_true();
    test_op_dup_doubles_top();
    test_op_drop_removes_top();
    test_op_swap_exchanges_top_two();
    test_op_size_pushes_length();
    test_op_dup_underflow_fails();

    std::cout << "\n-- Comparison Opcodes --\n";
    test_op_equal_matching();
    test_op_equal_different();
    test_op_equalverify_matching_succeeds();
    test_op_equalverify_different_fails();

    std::cout << "\n-- Crypto Opcodes --\n";
    test_op_sha3_256_known_input();
    test_op_sha3_256_different_inputs_differ();
    test_op_hash160_matches_wallet_hash_pubkey();

    std::cout << "\n-- Control Flow --\n";
    test_if_true_branch_executes();
    test_if_false_branch_executes();
    test_nested_if();
    test_op_return_fails_evaluation();

    std::cout << "\n-- Locktime (CLTV) --\n";
    test_cltv_passes_when_height_sufficient();
    test_cltv_fails_when_height_too_low();
    test_cltv_acts_as_nop_without_flag();

    std::cout << "\n-- Security Limits --\n";
    test_script_too_large_rejected();

    std::cout << "\n-- P2PKH Backward Compatibility --\n";
    test_p2pkh_with_correct_key_passes();
    test_p2pkh_with_wrong_key_fails();
    test_p2pkh_sig_failure_propagates();

    std::cout << "\n-- HTLC Script Builder & Evaluator --\n";
    test_decode_htlc_roundtrip();
    test_htlc_claim_correct_preimage_succeeds();
    test_htlc_claim_wrong_preimage_fails();
    test_htlc_claim_wrong_pubkey_fails();
    test_htlc_refund_after_timeout_succeeds();
    test_htlc_refund_before_timeout_fails();
    test_htlc_refund_wrong_pubkey_fails();
    test_htlc_claim_cant_use_refund_script();

    std::cout << "\n-- HTLC Helpers (GeneratePreimage / HashPreimage) --\n";
    test_generate_preimage_random_and_32_bytes();
    test_hash_preimage_deterministic();
    test_hash_preimage_different_inputs_differ();
    test_hash_preimage_matches_sha3_256();

    std::cout << "\n-- SwapStore Persistence --\n";
    test_swap_store_add_get();
    test_swap_store_update();
    test_swap_store_persist_and_reload();
    test_swap_store_list_filter();
    test_swap_store_get_missing_returns_false();

    std::cout << "\n-- Script Type Detection --\n";
    test_is_p2pkh_detection();
    test_is_htlc_detection();
    test_is_unspendable_detection();

    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "SOME TESTS FAILED\n";
        return 1;
    }
    std::cout << "ALL TESTS PASSED\n";
    return 0;
}
