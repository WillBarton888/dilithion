// Copyright (c) 2025 The Dilithion Core developers
#include <boost/test/unit_test.hpp>
#include <crypto/dilithium/dilithium.h>
#include <crypto/dilithium/dilithium_paranoid.h>
#include <random.h>
#include <support/cleanse.h>

BOOST_AUTO_TEST_SUITE(dilithium_stress_tests)

BOOST_AUTO_TEST_CASE(stress_many_operations)
{
    const int iterations = 1000;
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);
    for (int i = 0; i < iterations; i++) {
        unsigned char msg[64];
        GetRandBytes(msg, 64);
        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;
        BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 64, sk), 0);
        BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 64, pk), 0);
    }
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(stress_paranoid_operations)
{
    const int iterations = 100;
    for (int i = 0; i < iterations; i++) {
        unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
        dilithium::paranoid::SecureKeyBuffer key_storage;
        if (dilithium::paranoid::keypair_paranoid(pk, key_storage.data()) != 0) continue;
        BOOST_CHECK(key_storage.verify_integrity());
        unsigned char msg[32];
        GetRandBytes(msg, 32);
        unsigned char sig[DILITHIUM_BYTES];
        size_t siglen;
        BOOST_CHECK_EQUAL(dilithium::paranoid::sign_paranoid(sig, &siglen, msg, 32, key_storage.data()), 0);
        BOOST_CHECK_EQUAL(dilithium::paranoid::verify_paranoid(sig, siglen, msg, 32, pk), 0);
        BOOST_CHECK(key_storage.verify_integrity());
    }
}

BOOST_AUTO_TEST_SUITE_END()
