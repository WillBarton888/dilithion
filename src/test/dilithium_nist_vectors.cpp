// Copyright (c) 2025 The Dilithion Core developers
#include <boost/test/unit_test.hpp>
#include <crypto/dilithium/dilithium.h>
#include <support/cleanse.h>

BOOST_AUTO_TEST_SUITE(dilithium_nist_vectors)

BOOST_AUTO_TEST_CASE(nist_parameter_sizes)
{
    BOOST_CHECK_EQUAL(DILITHIUM_PUBLICKEYBYTES, 1312);
    BOOST_CHECK_EQUAL(DILITHIUM_SECRETKEYBYTES, 2528);
    BOOST_CHECK_EQUAL(DILITHIUM_BYTES, 2420);
}

BOOST_AUTO_TEST_CASE(nist_basic_correctness)
{
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    BOOST_CHECK_EQUAL(dilithium::keypair(pk, sk), 0);
    unsigned char msg[32] = {0};
    unsigned char sig[DILITHIUM_BYTES];
    size_t siglen;
    BOOST_CHECK_EQUAL(dilithium::sign(sig, &siglen, msg, 32, sk), 0);
    BOOST_CHECK_EQUAL(dilithium::verify(sig, siglen, msg, 32, pk), 0);
    memory_cleanse(sk, DILITHIUM_SECRETKEYBYTES);
}

BOOST_AUTO_TEST_SUITE_END()
